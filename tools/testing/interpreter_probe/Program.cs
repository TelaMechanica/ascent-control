using System.Diagnostics;
using System.Text.Json;
using Ascent.Desktop;

if (args.Length == 1 && args[0] == "token-policy")
{
    var backend = new Uri("http://127.0.0.1:45678/");
    var view = new object();
    var passed = new List<bool>();
    bool Check(string? page, string? target, string method = "GET", bool script = true, object? sender = null)
        => ServiceHostRequestPolicy.ShouldAttach(backend, view, sender ?? view, page, target, method, script);
    string Origin(string path) => new Uri(backend, path).ToString();
    foreach (var path in new[] { "status", "prepare", "credential", "receiver/inspect", "receiver/verify" })
    {
        var method = path == "status" ? "GET" : "POST";
        passed.Add(Check(Origin("/"), Origin("/api/service-mode/local/" + path), method));
        passed.Add(!Check(Origin("/"), Origin("/api/service-mode/local/" + path), method, false));
    }
    foreach (var entry in new[] { ("GET", "/api/widgets/local/catalog"), ("POST", "/api/widgets/local/rescan"), ("POST", "/api/widgets/local/open-folder") })
    {
        passed.Add(Check(Origin("/"), Origin(entry.Item2), entry.Item1));
        passed.Add(!Check(Origin("/"), Origin(entry.Item2), entry.Item1, false));
        passed.Add(!Check("https://widget.invalid/", Origin(entry.Item2), entry.Item1));
        passed.Add(!Check(Origin("/"), Origin(entry.Item2), entry.Item1 == "GET" ? "POST" : "GET"));
        passed.Add(!Check(Origin("/widget/view"), Origin(entry.Item2), entry.Item1));
        passed.Add(!Check(Origin("/"), Origin(entry.Item2), entry.Item1, sender: new object()));
    }
    passed.Add(!Check(Origin("/"), Origin("/api/widgets/local/catalog/extra")));
    passed.Add(!Check(Origin("/"), Origin("/api/service-mode/local/status"), sender: new object()));
    passed.Add(!Check("https://widget.invalid/", Origin("/api/service-mode/local/status")));
    passed.Add(!Check(Origin("/widget/view"), Origin("/api/service-mode/local/status")));
    passed.Add(!Check(Origin("/"), "https://widget.invalid/api/service-mode/local/status"));
    passed.Add(!Check(Origin("/"), "http://127.0.0.1:45679/api/service-mode/local/status"));
    passed.Add(!Check(Origin("/"), Origin("/api/app")));
    passed.Add(!Check(Origin("/"), Origin("/api/service-mode/local/unknown")));
    passed.Add(!Check(Origin("/"), Origin("/api/service-mode/local/status"), "POST"));
    passed.Add(!Check("not-a-url", Origin("/api/service-mode/local/status")));
    passed.Add(!Check(Origin("/"), "http://fixture-user@127.0.0.1:45678/api/service-mode/local/status"));
    passed.Add(Check(Origin("/index.html#settings"), Origin("/api/service-mode/local/status")));
    Console.WriteLine(JsonSerializer.Serialize(new { token_policy_cases = passed.Count,
        passed = passed.All(value => value), browser_frame_isolation_proven = false }));
    return passed.All(value => value) ? 0 : 1;
}

// Owned child fixture only. No Python, app launch, credentials or device access.
if (args.Length > 0 && args[0] == "-c")
{
    switch (Environment.GetEnvironmentVariable("ASCENT_TEST_PROBE_CHILD"))
    {
        case "valid": Console.WriteLine("3.12"); return 0;
        case "old": Console.WriteLine("3.9"); return 0;
        case "invalid": Console.WriteLine("synthetic-invalid-version"); return 0;
        case "stderr":
            for (var n = 0; n < 256; n++) Console.Error.Write(new string('x', 4096));
            Console.WriteLine("3.12"); return 0;
        case "stdout":
            for (var n = 0; n < 256; n++) Console.Write(new string('x', 4096));
            return 0;
        case "hang": Thread.Sleep(Timeout.Infinite); return 0;
        default: return 3;
    }
}
if (args.Length != 1) return 2;
var mode = args[0];
Environment.SetEnvironmentVariable("ASCENT_TEST_PROBE_CHILD", mode);
var watch = Stopwatch.StartNew();
var accepted = BackendHost.IsUsableInterpreter(Environment.ProcessPath!);
var expected = mode is "valid" or "stderr";
Console.WriteLine(JsonSerializer.Serialize(new { mode, accepted, milliseconds = watch.ElapsedMilliseconds,
    passed = accepted == expected && watch.Elapsed < TimeSpan.FromSeconds(7), hardware_access = false }));
return accepted == expected && watch.Elapsed < TimeSpan.FromSeconds(7) ? 0 : 1;
