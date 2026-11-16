using System.Diagnostics;
using System.Text.Json;
using Ascent.Desktop;

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
