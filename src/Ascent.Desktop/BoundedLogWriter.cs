using System.IO;

namespace Ascent.Desktop;

/// <summary>
/// A small append-only log capped at MaxBytes, rotating to a single ".previous.log"
/// backup rather than growing without bound. Used for both the host/backend
/// transcript and the crash log required under %LOCALAPPDATA%\Ascent Control\.
/// Logging failures are swallowed on purpose: logging must never crash the app.
/// </summary>
public sealed class BoundedLogWriter
{
    private const long MaxBytes = 5 * 1024 * 1024;
    private readonly object _lock = new();
    private readonly string _path;

    public BoundedLogWriter(string fileName)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Ascent Control", "logs");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, fileName);
    }

    public string LogPath => _path;

    public void WriteLine(string line)
    {
        lock (_lock)
        {
            try
            {
                var fi = new FileInfo(_path);
                if (fi.Exists && fi.Length > MaxBytes)
                {
                    var rotated = _path + ".previous.log";
                    File.Copy(_path, rotated, overwrite: true);
                    File.WriteAllText(_path, string.Empty);
                }
                File.AppendAllText(_path, $"{DateTime.UtcNow:O} {line}{Environment.NewLine}");
            }
            catch
            {
                // Never let logging take the app down.
            }
        }
    }
}
