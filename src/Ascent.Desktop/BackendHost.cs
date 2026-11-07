using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Ascent.Desktop;

public sealed class BackendStartResult
{
    public bool Started { get; init; }
    public Uri? BaseUri { get; init; }
    public string? Error { get; init; }

    /// <summary>Diagnostic text (backend stderr tail, exception message) for the failure overlay.</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// Owns exactly one instance of the existing Python backend (runtime/dev_harness.py)
/// for the lifetime of the application window. Started once, hidden, and reused for
/// every API call the WebView2 content makes — device-discovery polling happens
/// in-process inside that one backend, never as a new helper process per poll.
/// </summary>
public sealed class BackendHost : IDisposable
{
    /// <summary>
    /// Longest a qualified device mutation can legitimately occupy the backend.
    /// The RF commit waits out the vendor restart, whose observed distribution runs
    /// 10.1-11.4 s typical with real outliers at 39.7 s, 42.8 s and 107.0 s; the
    /// backend budget for that verified reconnect is 150 s
    /// (dev_harness.RECONNECT_VERIFY_TIMEOUT). Window close must outlast it, or a
    /// close during a commit hard-kills Python mid-transaction on a healthy unit.
    /// </summary>
    private static readonly TimeSpan MutationDrainBudget = TimeSpan.FromSeconds(180);

    /// <summary>How many loopback ports to try before giving up (see ReserveLoopbackPort).</summary>
    private const int PortAttempts = 3;

    private const int RecentOutputLines = 40;

    private Process? _process;
    private Uri? _baseUri;
    private int _stopping;

    /// <summary>Address parsed out of the backend banner, if it ever arrives. Written
    /// from the stdout reader thread, read from the startup probe loop.</summary>
    private volatile Uri? _announcedUri;
    private readonly BoundedLogWriter _log;
    private readonly object _recentLock = new();
    private readonly Queue<string> _recentOutput = new();

    /// <summary>Raised if the backend process exits unexpectedly after startup succeeded.</summary>
    public event EventHandler<string>? UnexpectedExit;

    public BackendHost(BoundedLogWriter log) => _log = log;

    public static string? LocateBackendScript()
    {
        var shipped = Path.Combine(AppContext.BaseDirectory, "runtime", "dev_harness.py");
        if (File.Exists(shipped)) return shipped;

        // Development override so an engineer can point the host at a source checkout
        // without rebuilding; never used unless explicitly set.
        var envDir = Environment.GetEnvironmentVariable("ASCENT_BACKEND_DIR");
        if (!string.IsNullOrWhiteSpace(envDir))
        {
            var alt = Path.Combine(envDir, "dev_harness.py");
            if (File.Exists(alt)) return alt;
        }
        return null;
    }

    /// <summary>The backend uses PEP 604 unions and match statements; 3.10 is the floor.</summary>
    private const int MinPythonMinor = 10;

    public static string? LocatePythonExecutable()
    {
        // A fully self-contained installer would ship its own interpreter here;
        // packaging that is backend/release territory, not this host's job.
        var bundled = Path.Combine(AppContext.BaseDirectory, "pyembed", "pythonw.exe");
        if (File.Exists(bundled)) return bundled;

        // Taking the FIRST interpreter on PATH is not safe. On this bench PATH
        // carries five: an ESP-IDF toolchain Python shadows every real install,
        // and msys2 ships another. A toolchain interpreter can satisfy the name
        // and still be the wrong runtime to host the backend. Probe each
        // candidate in PATH order and take the first that actually reports a
        // usable version, rather than the first that merely exists.
        foreach (var candidate in EnumerateOnPath("pythonw.exe", "python.exe"))
        {
            if (IsUsableInterpreter(candidate)) return candidate;
        }

        // Nothing verified. Fall back to the first that exists so the failure the
        // operator sees is the backend's own startup error rather than a bare
        // "no Python found" when an interpreter is plainly installed.
        foreach (var candidate in EnumerateOnPath("pythonw.exe", "python.exe")) return candidate;
        return null;
    }

    private static IEnumerable<string> EnumerateOnPath(params string[] exeNames)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var name in exeNames)
        {
            foreach (var dir in pathVar.Split(Path.PathSeparator))
            {
                string? full = null;
                try
                {
                    full = Path.Combine(dir, name);
                    if (!File.Exists(full)) full = null;
                }
                catch
                {
                    // Malformed PATH entry; skip it.
                    full = null;
                }
                if (full is not null) yield return full;
            }
        }
    }

    /// <summary>
    /// Runs the candidate with -c and reads back its major/minor. A console
    /// interpreter is used for the probe even when the launch target is
    /// pythonw.exe, because pythonw has no stdout to report on.
    /// </summary>
    internal static bool IsUsableInterpreter(string exePath)
    {
        var probe = exePath;
        if (Path.GetFileName(exePath).Equals("pythonw.exe", StringComparison.OrdinalIgnoreCase))
        {
            var console = Path.Combine(Path.GetDirectoryName(exePath) ?? string.Empty, "python.exe");
            if (File.Exists(console)) probe = console;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = probe,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("import sys;print(f'{sys.version_info[0]}.{sys.version_info[1]}')");

            using var proc = Process.Start(psi);
            if (proc is null) return false;
            var stdout = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(5000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return false;
            }
            if (proc.ExitCode != 0) return false;

            var parts = stdout.Trim().Split('.');
            if (parts.Length < 2) return false;
            if (!int.TryParse(parts[0], out var major)) return false;
            if (!int.TryParse(parts[1], out var minor)) return false;
            return major > 3 || (major == 3 && minor >= MinPythonMinor);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Picks a free loopback port by binding one and releasing it immediately, so the
    /// host knows the backend's address BEFORE the backend starts.
    ///
    /// The backend chooses an OS-assigned port and announces it on stdout. Waiting on
    /// that announcement alone is not safe: stdout is a pipe here, Python block-buffers
    /// a pipe, and the announcement is followed by serve_forever() rather than by a
    /// flush or an exit, so the line can sit in the interpreter's buffer indefinitely
    /// and the host times out on a backend that is actually serving. PYTHONUNBUFFERED
    /// (set in StartAsync) fixes the buffering, and passing an explicit port removes
    /// the dependency on stdout entirely: readiness is proven by an HTTP probe.
    ///
    /// There is a small window between releasing the port and the backend binding it.
    /// If another process wins that race the backend exits on a bind error, which is
    /// detected below and retried on a fresh port.
    /// </summary>
    private static int ReserveLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    public async Task<BackendStartResult> StartAsync(
        TimeSpan timeout, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var script = LocateBackendScript();
        if (script is null)
        {
            return new BackendStartResult
            {
                Started = false,
                Error = "Backend runtime (runtime\\dev_harness.py) was not found next to the application.",
                Detail = "Searched: " + Path.Combine(AppContext.BaseDirectory, "runtime", "dev_harness.py")
            };
        }

        var python = LocatePythonExecutable();
        if (python is null)
        {
            return new BackendStartResult
            {
                Started = false,
                Error = "No Python runtime was found to host the Ascent Control backend.",
                Detail = "Looked for pyembed\\pythonw.exe next to the application, then pythonw.exe / python.exe on PATH."
            };
        }

        BackendStartResult result = new() { Started = false, Error = "The Ascent Control backend did not start." };
        for (var attempt = 1; attempt <= PortAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            int port;
            try
            {
                port = ReserveLoopbackPort();
            }
            catch (Exception ex)
            {
                _log.WriteLine("[backend] could not reserve a loopback port: " + ex.Message);
                return new BackendStartResult
                {
                    Started = false,
                    Error = "No free local port was available for the Ascent Control backend.",
                    Detail = ex.Message
                };
            }

            bool retry;
            (result, retry) = await TryStartOnPortAsync(python, script, port, timeout, progress, ct);
            if (result.Started || !retry) return result;

            _log.WriteLine($"[backend] port {port} was taken between reservation and bind; retrying (attempt {attempt})");
        }

        return result;
    }

    private async Task<(BackendStartResult Result, bool Retry)> TryStartOnPortAsync(
        string python, string script, int port, TimeSpan timeout,
        IProgress<string>? progress, CancellationToken ct)
    {
        var expected = new Uri($"http://127.0.0.1:{port}/");

        var psi = new ProcessStartInfo
        {
            FileName = python,
            WorkingDirectory = Path.GetDirectoryName(script),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add(script);
        psi.ArgumentList.Add("--listen");
        psi.ArgumentList.Add("127.0.0.1");
        psi.ArgumentList.Add("--port");
        psi.ArgumentList.Add(port.ToString());
        psi.ArgumentList.Add("--no-browser"); // The desktop shell is the browser; never open an external one.

        // Line-buffer the child's stdout/stderr. Without this the startup banner and
        // any traceback stay inside Python's pipe buffer while serve_forever() runs,
        // which makes a healthy backend look silent and a failing one look empty.
        psi.Environment["PYTHONUNBUFFERED"] = "1";
        psi.Environment["PYTHONIOENCODING"] = "utf-8";

        // The URL is known in advance; the banner is still parsed so the log shows it
        // and so an unexpected address (a future backend that ignores --port) still wins.
        _announcedUri = null;
        ClearRecent();
        var urlPattern = new Regex(@"Ascent Control[^:]*:\s*(?<url>http://\S+)", RegexOptions.Compiled);

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            _log.WriteLine("[backend] " + e.Data);
            Remember(e.Data);
            var m = urlPattern.Match(e.Data);
            if (m.Success && Uri.TryCreate(m.Groups["url"].Value, UriKind.Absolute, out var uri))
                _announcedUri = uri;
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            _log.WriteLine("[backend-stderr] " + e.Data);
            Remember(e.Data);
        };
        process.Exited += (_, _) =>
        {
            var code = SafeExitCode(process);
            _log.WriteLine($"[backend] process exited (code {code})");
            if (Volatile.Read(ref _stopping) == 0 && _baseUri is not null)
                UnexpectedExit?.Invoke(this, RecentOutput());
        };

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            _log.WriteLine("[backend] failed to start: " + ex);
            return (new BackendStartResult
            {
                Started = false,
                Error = "Failed to start the Ascent Control backend.",
                Detail = $"{python}\n{ex.Message}"
            }, false);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _process = process;

        progress?.Report("WAITING FOR BACKEND…");

        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        var ready = await WaitForBackendAsync(process, expected, linked.Token);
        if (ready is not null)
        {
            _baseUri = ready;
            return (new BackendStartResult { Started = true, BaseUri = ready }, false);
        }

        var exited = process.HasExited;
        var tail = RecentOutput();
        var portConflict = exited && LooksLikePortConflict(tail);

        _log.WriteLine(exited
            ? "[backend] process exited before it became reachable"
            : "[backend] timed out waiting for the backend to answer");

        await StopAsync();
        Volatile.Write(ref _stopping, 0); // this attempt is over; the host may still try another port

        if (portConflict)
        {
            return (new BackendStartResult
            {
                Started = false,
                Error = "No free local port was available for the Ascent Control backend.",
                Detail = tail
            }, true);
        }

        return (new BackendStartResult
        {
            Started = false,
            Error = exited
                ? "The Ascent Control backend stopped before it began serving."
                : "The Ascent Control backend did not answer in time.",
            Detail = string.IsNullOrWhiteSpace(tail) ? $"Address: {expected}" : tail
        }, false);
    }

    /// <summary>
    /// Readiness is an answered HTTP request, not a printed line: the backend is only
    /// usable once it is actually serving, and only that proves the port belongs to us
    /// rather than to whatever else may have grabbed it. /api/app is a static JSON
    /// response, so probing it neither touches a device nor opens a serial session.
    /// </summary>
    private async Task<Uri?> WaitForBackendAsync(Process process, Uri expected, CancellationToken ct)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };

        while (!ct.IsCancellationRequested)
        {
            var target = _announcedUri ?? expected;
            try
            {
                using var response = await client.GetAsync(new Uri(target, "/api/app"), ct);
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync(ct);
                    if (body.Contains("Ascent Control", StringComparison.Ordinal))
                        return target;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return null;
            }
            catch
            {
                // Not listening yet (or not listening any more); fall through to the
                // exit check and retry.
            }

            if (process.HasExited) return null;

            try { await Task.Delay(150, ct); }
            catch (OperationCanceledException) { return null; }
        }
        return null;
    }

    private static bool LooksLikePortConflict(string text) =>
        text.Contains("10048", StringComparison.Ordinal) ||
        text.Contains("Address already in use", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("only one usage of each socket address", StringComparison.OrdinalIgnoreCase);

    private void Remember(string line)
    {
        lock (_recentLock)
        {
            _recentOutput.Enqueue(line);
            while (_recentOutput.Count > RecentOutputLines) _recentOutput.Dequeue();
        }
    }

    private void ClearRecent()
    {
        lock (_recentLock) _recentOutput.Clear();
    }

    private string RecentOutput()
    {
        lock (_recentLock)
        {
            return string.Join(Environment.NewLine, _recentOutput);
        }
    }

    private static int SafeExitCode(Process p)
    {
        try { return p.ExitCode; }
        catch { return -1; }
    }

    /// <summary>
    /// Stops the owned backend process without interrupting an operation-qualified
    /// device write. The backend shutdown endpoint waits for the mutation lock, then
    /// prevents new mutations and exits serve_forever(). A hard process-tree kill is
    /// retained only as a bounded fallback if graceful shutdown fails.
    ///
    /// Awaitable on purpose: the drain can legitimately run to MutationDrainBudget,
    /// and doing that synchronously on the UI thread froze the window for its duration.
    /// </summary>
    public async Task StopAsync(IProgress<string>? progress = null)
    {
        if (Interlocked.Exchange(ref _stopping, 1) != 0) return;

        try
        {
            if (_process is not { HasExited: false } p) return;

            progress?.Report("FINISHING DEVICE OPERATION…");

            // The shutdown endpoint blocks on the backend mutation lock, so both the
            // request and this wait have to cover the longest possible mutation.
            var graceful = await TryGracefulShutdownAsync();
            if (graceful && await WaitForExitAsync(p, MutationDrainBudget)) return;

            _log.WriteLine("[host] graceful backend shutdown failed or timed out; forcing process-tree stop");
            progress?.Report("STOPPING BACKEND…");
            p.Kill(entireProcessTree: true);
            await WaitForExitAsync(p, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _log.WriteLine("[host] backend stop error: " + ex.Message);
        }
        finally
        {
            _baseUri = null;
        }
    }

    private static async Task<bool> WaitForExitAsync(Process p, TimeSpan budget)
    {
        using var cts = new CancellationTokenSource(budget);
        try
        {
            await p.WaitForExitAsync(cts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private async Task<bool> TryGracefulShutdownAsync()
    {
        if (_baseUri is null) return false;
        try
        {
            using var client = new HttpClient { Timeout = MutationDrainBudget };
            using var content = new StringContent("{}", Encoding.UTF8, "application/json");
            var uri = new Uri(_baseUri, "/api/host/shutdown");
            using var response = await client.PostAsync(uri, content);
            _log.WriteLine($"[host] graceful shutdown response: {(int)response.StatusCode}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _log.WriteLine("[host] graceful shutdown request failed: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Synchronous last-resort stop for Dispose only. Never call this from the UI
    /// thread; MainWindow uses StopAsync so the window keeps painting while the
    /// backend drains.
    /// </summary>
    public void Dispose() => Task.Run(() => StopAsync()).GetAwaiter().GetResult();
}
