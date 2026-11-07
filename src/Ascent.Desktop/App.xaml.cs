using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace Ascent.Desktop;

public partial class App : Application
{
    private BoundedLogWriter? _crashLog;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // A crash must leave a useful bounded log under %LOCALAPPDATA%\Ascent Control\,
        // per the desktop-host acceptance requirements, regardless of which layer failed.
        _crashLog = new BoundedLogWriter("crash.log");

        DispatcherUnhandledException += (_, args) =>
        {
            _crashLog?.WriteLine("[unhandled-ui] " + args.Exception);

            // Without this the window is torn down and the user is left looking at
            // nothing. Show the real exception and the log path, then exit
            // deterministically instead of falling into the default crash dialog.
            args.Handled = true;
            ShowFatal(args.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            _crashLog?.WriteLine("[unhandled] " + args.ExceptionObject);
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            _crashLog?.WriteLine("[unobserved-task] " + args.Exception);
            args.SetObserved();
        };
    }

    private void ShowFatal(Exception ex)
    {
        try
        {
            MessageBox.Show(
                $"Ascent Control stopped unexpectedly.\n\n{ex.GetType().Name}: {ex.Message}\n\n" +
                $"Log: {_crashLog?.LogPath}",
                "Ascent Control", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch
        {
            // A failure to report a failure must not loop.
        }
        finally
        {
            Shutdown(1);
        }
    }
}
