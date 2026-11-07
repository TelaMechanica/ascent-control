using System.ComponentModel;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace Ascent.Desktop;

public partial class MainWindow : Window
{
    /// <summary>
    /// Startup budget for the backend. The old 10 s was tight enough that a cold
    /// interpreter start on a loaded machine could miss it; readiness is now proven
    /// by an HTTP probe, so a longer budget costs nothing on a healthy launch.
    /// </summary>
    private static readonly TimeSpan BackendStartTimeout = TimeSpan.FromSeconds(40);

    private BackendHost? _backend;
    private BoundedLogWriter? _log;
    private bool _uiEverLoaded;
    private bool _shuttingDown;
    private bool _closeApproved;

    public MainWindow()
    {
        InitializeComponent();

        // The WebView2 native child window paints over every WPF element, so it stays
        // hidden until the approved page has actually loaded. Without this the overlay
        // (and every error message drawn in it) is invisible and startup failures
        // present as a blank white window.
        Browser.Visibility = Visibility.Hidden;

        ApplyDisplayBounds();

        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    /// <summary>
    /// Chooses restore bounds that fit the current work area. The window opens
    /// maximized (XAML), but the restore size and the minimum size must not exceed a
    /// smaller or scaled display, or the window opens partly offscreen and cannot be
    /// resized back. SystemParameters values are already DPI-independent units; the
    /// application manifest declares PerMonitorV2 so WPF and WebView2 rescale together
    /// when the window moves between monitors of different scale factors.
    /// </summary>
    private void ApplyDisplayBounds()
    {
        var work = SystemParameters.WorkArea;
        if (work.Width <= 0 || work.Height <= 0) return;

        MinWidth = Math.Min(1180, work.Width);
        MinHeight = Math.Min(720, work.Height);

        Width = Math.Max(MinWidth, Math.Min(1440, work.Width * 0.94));
        Height = Math.Max(MinHeight, Math.Min(900, work.Height * 0.94));

        Left = work.Left + Math.Max(0, (work.Width - Width) / 2);
        Top = work.Top + Math.Max(0, (work.Height - Height) / 2);
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _log = new BoundedLogWriter("host.log");
        _log.WriteLine("[host] window loaded; starting WebView2 environment");

        SetStartupStatus("PREPARING WEBVIEW2 RUNTIME…");

        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Ascent Control", "WebView2");

        try
        {
            Directory.CreateDirectory(userDataFolder);

            // Paint the WebView2 surface in the approved background colour so the
            // moment it becomes visible there is no white frame.
            Browser.DefaultBackgroundColor = System.Drawing.Color.FromArgb(0xFF, 0x08, 0x09, 0x09);

            var env = await CoreWebView2Environment.CreateAsync(userDataFolder: userDataFolder);
            await Browser.EnsureCoreWebView2Async(env);
        }
        catch (Exception ex)
        {
            _log.WriteLine("[webview2] failed to initialize: " + ex);
            ShowStartupError(
                "The Microsoft Edge WebView2 Runtime could not be initialized. " +
                "Install the WebView2 Runtime and restart Ascent Control.",
                ex.Message);
            return;
        }

        // Every navigation error (including a mid-session backend crash reload) surfaces
        // in the overlay instead of silently leaving a blank/frozen page.
        Browser.CoreWebView2.NavigationCompleted += (_, args) =>
        {
            if (args.IsSuccess)
            {
                _uiEverLoaded = true;
                ShowBrowser();
            }
            else
            {
                _log?.WriteLine($"[webview2] navigation failed: {args.WebErrorStatus}");
                ShowStartupError(
                    "The Ascent Control interface failed to load.",
                    $"WebErrorStatus: {args.WebErrorStatus}");
            }
        };

        // Host <-> page channel. The only thing it carries is video, because video is
        // the one capability the page cannot provide for itself: d3d11videosink needs a
        // real HWND and WebView2 has no way to give it one. Everything else the UI does
        // goes over HTTP to the Python backend, and should stay there.
        Browser.CoreWebView2.WebMessageReceived += (_, args) =>
        {
            string raw;
            try { raw = args.WebMessageAsJson; }
            catch (Exception ex) { _log?.WriteLine("[video] bad web message: " + ex.Message); return; }
            HandleHostMessage(raw);
        };

        Browser.CoreWebView2.ProcessFailed += (_, args) =>
        {
            _log?.WriteLine($"[webview2] process failed: {args.ProcessFailedKind} {args.Reason}");
            ShowStartupError(
                "The Ascent Control interface process stopped.",
                $"{args.ProcessFailedKind} / {args.Reason}");
        };

        _backend = new BackendHost(_log);
        _backend.UnexpectedExit += (_, message) =>
            Dispatcher.InvokeAsync(() =>
            {
                if (_shuttingDown) return;
                ShowStartupError("The Ascent Control backend stopped.", message);
            });

        SetStartupStatus("STARTING ASCENT CONTROL BACKEND…");
        var progress = new Progress<string>(SetStartupStatus);
        var result = await _backend.StartAsync(BackendStartTimeout, progress);
        if (!result.Started || result.BaseUri is null)
        {
            _log.WriteLine("[host] backend did not start: " + result.Error);
            ShowStartupError(
                result.Error ?? "The Ascent Control backend did not start.",
                result.Detail);
            return;
        }

        _log.WriteLine("[host] backend ready at " + result.BaseUri);
        // The HID pump posts axes here; it has no other way to reach the backend.
        _backendBaseUri = result.BaseUri;
        SetStartupStatus("LOADING INTERFACE…");
        Browser.CoreWebView2.Navigate(result.BaseUri.ToString());
    }

    private void SetStartupStatus(string message)
    {
        StartupOverlay.Visibility = Visibility.Visible;
        Browser.Visibility = Visibility.Hidden;
        StartupProgress.Visibility = Visibility.Visible;
        StartupProgress.IsIndeterminate = true;
        StartupText.Foreground = System.Windows.Media.Brushes.White;
        StartupText.Text = message;
        StartupDetail.Visibility = Visibility.Collapsed;
    }

    /// <summary>
    /// Failure state: the overlay stays up, the browser stays hidden, and the actual
    /// error (plus the log path that carries the backend transcript) is readable on
    /// screen. Never a white window.
    /// </summary>
    private void ShowStartupError(string message, string? detail = null)
    {
        StartupOverlay.Visibility = Visibility.Visible;
        Browser.Visibility = Visibility.Hidden;
        StartupProgress.IsIndeterminate = false;
        StartupProgress.Visibility = Visibility.Collapsed;

        StartupText.Foreground = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xF0, 0x4A, 0x52));
        StartupText.Text = message;

        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(detail)) lines.Add(detail!.Trim());
        if (_log is not null) lines.Add("Log: " + _log.LogPath);
        if (lines.Count > 0)
        {
            StartupDetail.Text = string.Join(Environment.NewLine + Environment.NewLine, lines);
            StartupDetail.Visibility = Visibility.Visible;
        }
    }

    private void ShowBrowser()
    {
        Browser.Visibility = Visibility.Visible;
        StartupOverlay.Visibility = Visibility.Collapsed;
        StartupProgress.IsIndeterminate = false;
    }

    /// <summary>
    /// Close must not block the UI thread. The backend drains any qualified device
    /// mutation before exiting, which can legitimately take the full
    /// BackendHost.MutationDrainBudget; doing that synchronously froze the window
    /// (unrepainted, "not responding") for the whole drain. The close is cancelled
    /// once, the drain is awaited with a visible state, then the window really closes.
    /// </summary>
    private async void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_closeApproved) return;

        e.Cancel = true;
        if (_shuttingDown) return;
        _shuttingDown = true;

        _log?.WriteLine("[host] window closing; stopping backend");

        // If the approved UI is up we leave it on screen behind the overlay message
        // rather than flashing back to a native-only window for the drain.
        StartupOverlay.Visibility = Visibility.Visible;
        Browser.Visibility = Visibility.Hidden;
        StartupProgress.Visibility = Visibility.Visible;
        StartupProgress.IsIndeterminate = true;
        StartupDetail.Visibility = Visibility.Collapsed;
        StartupText.Foreground = System.Windows.Media.Brushes.White;
        StartupText.Text = _uiEverLoaded
            ? "FINISHING DEVICE OPERATION…"
            : "SHUTTING DOWN…";

        try
        {
            if (_backend is not null)
            {
                await _backend.StopAsync(new Progress<string>(text =>
                {
                    StartupText.Text = text;
                }));
            }
        }
        catch (Exception ex)
        {
            _log?.WriteLine("[host] backend stop error: " + ex);
        }

        _closeApproved = true;
        Close();
    }

    // ---------------------------------------------------------------------------
    // Video
    //
    // One window for the application's lifetime, reopened rather than duplicated.
    // Failures are reported back to the page instead of being thrown, because video
    // is an optional capability: a machine without GStreamer must run everything
    // else normally and say why video is unavailable.
    // ---------------------------------------------------------------------------

    private VideoWindow? _video;
    private HidPump? _hid;
    private Uri? _backendBaseUri;

    /// <summary>
    /// Route one host message. Only two kinds exist, and both are capabilities the
    /// page genuinely cannot provide for itself: a native window for the video sink,
    /// and raw HID access. Everything else goes over HTTP to the Python backend.
    /// </summary>
    private void HandleHostMessage(string rawJson)
    {
        string type;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(rawJson);
            type = doc.RootElement.TryGetProperty("type", out var t) ? (t.GetString() ?? "") : "";
        }
        catch (Exception ex) { _log?.WriteLine("[host] unparsable message: " + ex.Message); return; }
        if (type == "video") HandleVideoMessage(rawJson);
        else if (type == "hid") HandleHidMessage(rawJson);
    }

    private void HandleHidMessage(string rawJson)
    {
        string action, path;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            action = root.TryGetProperty("action", out var a) ? (a.GetString() ?? "") : "";
            path = root.TryGetProperty("path", out var p2) ? (p2.GetString() ?? "") : "";
        }
        catch (Exception ex) { _log?.WriteLine("[hid] unparsable: " + ex.Message); return; }

        Dispatcher.Invoke(() =>
        {
            try
            {
                switch (action)
                {
                    case "list":
                        ReplyHid(true, "Enumerated.", HidPump.Enumerate());
                        return;
                    case "stop":
                        _hid?.Stop();
                        ReplyHid(true, "Stick reader stopped.", null);
                        return;
                    case "start":
                        if (string.IsNullOrWhiteSpace(path))
                        { ReplyHid(false, "A device path is required.", null); return; }
                        _hid ??= new HidPump(_log);
                        if (_backendBaseUri is not null) _hid.SetBackend(_backendBaseUri);
                        var reason = _hid.Start(path);
                        ReplyHid(reason is null,
                                 reason ?? $"Reading {_hid.Product} ({_hid.AxisCount} axes).",
                                 null);
                        return;
                    default:
                        ReplyHid(false, $"Unknown HID action '{action}'.", null);
                        return;
                }
            }
            catch (Exception ex)
            {
                _log?.WriteLine("[hid] handler failed: " + ex);
                ReplyHid(false, ex.Message, null);
            }
        });
    }

    private void ReplyHid(bool ok, string message, object? devices)
    {
        try
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                type = "hid",
                ok,
                message,
                devices,
                running = _hid?.Running ?? false,
                product = _hid?.Product,
                axisCount = _hid?.AxisCount ?? 0,
                buttonCount = _hid?.ButtonCount ?? 0,
                posted = _hid?.Posted ?? 0,
                lastAxes = _hid?.LastAxes,
                lastError = _hid?.LastError,
            });
            Browser.CoreWebView2?.PostWebMessageAsJson(payload);
        }
        catch (Exception ex) { _log?.WriteLine("[hid] reply failed: " + ex.Message); }
    }


    private void HandleVideoMessage(string rawJson)
    {
        string action, url;
        var options = new VideoPlaybackOptions();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            if (!root.TryGetProperty("type", out var type) || type.GetString() != "video") return;
            action = root.TryGetProperty("action", out var a) ? (a.GetString() ?? "") : "";
            url = root.TryGetProperty("url", out var u) ? (u.GetString() ?? "") : "";
            options = new VideoPlaybackOptions(
                root.TryGetProperty("transport", out var t) ? t.GetString() ?? "auto" : "auto",
                root.TryGetProperty("latencyMs", out var l) ? l.GetInt32() : 20);
            options.Validate();
        }
        catch (Exception ex)
        {
            _log?.WriteLine("[video] invalid playback request: " + ex.GetType().Name);
            ReplyVideo(false, "Invalid video endpoint or playback options.", null);
            return;
        }

        Dispatcher.Invoke(() =>
        {
            try
            {
                if (action == "stop")
                {
                    _video?.StopVideo();
                    ReplyVideo(true, "Video stopped.", null);
                    return;
                }
                if (action != "start")
                {
                    ReplyVideo(false, $"Unknown video action '{action}'.", null);
                    return;
                }
                if (string.IsNullOrWhiteSpace(url) ||
                    !url.StartsWith("rtsp://", StringComparison.OrdinalIgnoreCase))
                {
                    // The URL comes from the backend's own endpoint catalog, so a value
                    // that is not rtsp:// means something upstream is wrong.
                    ReplyVideo(false, "A rtsp:// URL is required.", null);
                    return;
                }

                if (_video is null || !_video.IsLoaded)
                {
                    _video = new VideoWindow(_log) { Owner = this };
                    _video.Closed += (_, _) => _video = null;
                    _video.StatusChanged += status => ReplyVideo(status.Error is null,
                        status.State == "decoded-input" ? "Decoded video frames are reaching the video sink."
                        : status.State == "frames-stale" ? "Video input stale: no new decoded frames."
                        : status.State == "waiting-for-frames" ? "Waiting for decoded video frames."
                        : status.Error ?? status.Detail ?? "Playback requested; waiting for decoded frames.", null, status);
                }
                _video.Show();
                _video.Activate();
                var reason = _video.Play(url, options);
                ReplyVideo(reason is null,
                           reason ?? "Playback requested; waiting for decoded frames.",
                           VideoWindow.DescribePipeline(VideoPlaybackOptions.DisplayEndpoint(url), options.LatencyMs, options.Transport));
            }
            catch (Exception ex)
            {
                _log?.WriteLine("[video] handler failed: " + ex);
                ReplyVideo(false, ex.Message, null);
            }
        });
    }

    private void ReplyVideo(bool ok, string message, string? pipeline, VideoPlaybackStatus? playback = null)
    {
        try
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                type = "video",
                ok,
                message,
                pipeline,
                playback,
                runtime = GstInterop.RuntimeDirectory,
                // Which runtime actually ran, and where it came from. Shown in the
                // UI because "it works on mine" is unanswerable without it: a
                // machine-global copy is a different version with a different
                // plugin set, so the source decides whether a bug reproduces.
                source = GstDiagnostics.SourceLabel(GstInterop.Source),
                version = GstInterop.Version,
                fault = GstInterop.Fault.ToString(),
                // The operator sentence and the technical one travel separately so
                // the page never has to decide which is which.
                plain = GstInterop.Fault == GstFault.None
                        ? null : GstDiagnostics.PlainMessage(GstInterop.Fault),
            });
            Browser.CoreWebView2?.PostWebMessageAsJson(payload);
        }
        catch (Exception ex)
        {
            _log?.WriteLine("[video] reply failed: " + ex.Message);
        }
    }
}
