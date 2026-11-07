using System.Windows;

namespace Ascent.Desktop;

/// <summary>
/// Hosts the RTSP video surface. One per application; reopened rather than
/// duplicated if the page asks for video again.
/// </summary>
public partial class VideoWindow : Window
{
    private readonly GstVideoController _controller = new();
    private VideoSurface? _surface;
    private readonly BoundedLogWriter? _log;
    private long _generation;
    private string? _lastState, _lastCaps, _lastError, _lastDetail;
    internal event Action<VideoPlaybackStatus>? StatusChanged;

    public VideoWindow(BoundedLogWriter? log = null)
    {
        InitializeComponent();
        _log = log;
        Closed += (_, _) => { Interlocked.Increment(ref _generation); _controller.Dispose(); };
        _controller.Changed += status =>
        {
            var generation = Interlocked.Read(ref _generation);
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (generation != Interlocked.Read(ref _generation)) return;
                if (_lastState != status.State || _lastCaps != status.DecodedCaps
                    || _lastError != status.Error || _lastDetail != status.Detail)
                {
                    _log?.WriteLine($"[video] state={status.State} sink_buffers={status.SinkBuffers} caps={status.DecodedCaps ?? "unknown"} error={VideoPlaybackOptions.LogDetail(status.Error)} detail={VideoPlaybackOptions.LogDetail(status.Detail)}");
                    _lastState = status.State; _lastCaps = status.DecodedCaps;
                    _lastError = status.Error; _lastDetail = status.Detail;
                }
                Status.Text = status.State switch
                {
                    "decoded-input" => "",
                    "waiting-for-frames" => "WAITING FOR DECODED VIDEO FRAMES…",
                    "frames-stale" => "VIDEO INPUT STALE — no new decoded frames",
                    "starting" => "STARTING VIDEO…",
                    "warning" => "VIDEO WARNING — " + status.Detail,
                    "source-timeout" => "RTCP TIMEOUT REPORTED — playback remains open",
                    _ => status.Error ?? "Waiting for video"
                };
                if (status.StopRequired)
                {
                    Interlocked.Increment(ref _generation);
                    _controller.Stop();
                }
                StatusChanged?.Invoke(status);
            }));
        };
    }

    /// <summary>The pipeline this window would run, for the UI to display.</summary>
    public static string DescribePipeline(string rtspUri, int latencyMs = 20, string transport = "auto") =>
        GstVideoController.BuildDescription(rtspUri, latencyMs, transport: transport);

    /// <summary>Start the stream. Returns null on success or a reason to show.</summary>
    internal string? Play(string rtspUri, VideoPlaybackOptions? options = null)
    {
        Interlocked.Increment(ref _generation);
        Status.Text = "STARTING VIDEO…";
        if (_surface is null)
        {
            try
            {
                _surface = new VideoSurface();
                Root.Children.Add(_surface);
            }
            catch (Exception ex)
            {
                _log?.WriteLine("[video] surface creation failed: " + ex);
                _surface = null;
                return ShowFailure("The native video surface could not be created.", ex.Message);
            }
        }

        // BuildWindowCore runs when the HwndHost is first arranged, so the handle may
        // not exist yet on the very first call. Force a layout pass rather than
        // guessing at a delay.
        _surface.UpdateLayout();
        var handle = _surface.SurfaceHandle;
        if (handle == IntPtr.Zero)
        {
            UpdateLayout();
            handle = _surface.SurfaceHandle;
        }

        var reason = _controller.Start(rtspUri, handle, options);
        if (reason is not null)
        {
            _log?.WriteLine("[video] start failed: " + reason);
            return ShowFailure("Video could not start.", reason);
        }
        _log?.WriteLine("[video] playback requested " + VideoPlaybackOptions.DisplayEndpoint(rtspUri)
            + $" transport={options?.Transport ?? "auto"} buffer_ms={options?.LatencyMs ?? 20}");
        return null;
    }

    public void StopVideo()
    {
        Interlocked.Increment(ref _generation);
        _controller.Stop();
        Status.Text = "VIDEO STOPPED.";
    }

    /// <summary>Anything the bus reported since the last check, or null.</summary>
    public string? PollError() => _controller.LastError;

    private string ShowFailure(string headline, string detail)
    {
        Status.Text = headline + "\n\n" + detail;
        if (_surface is not null)
        {
            Root.Children.Remove(_surface);
            _surface.Dispose();
            _surface = null;
        }
        return detail;
    }
}
