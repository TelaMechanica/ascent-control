using System.Globalization;
using System.Runtime.InteropServices;

namespace Ascent.Desktop;

/// <summary>One host playback pipeline. Local decoded buffers are not RF/video-effect proof.</summary>
internal sealed class GstVideoController : IDisposable
{
    private readonly object _gate = new();
    private Run? _run;
    private sealed class Run
    {
        internal IntPtr Pipeline, Pad;
        internal UIntPtr ProbeId;
        internal GstInterop.PadProbe? Probe;
        internal readonly CancellationTokenSource Cancel = new();
        internal Thread? Watch;
        internal long Buffers;
        internal string? Caps;
        internal VideoPlaybackStatus? LastPublished;
    }
    internal event Action<VideoPlaybackStatus>? Changed;
    internal string? LastError { get; private set; }
    internal bool IsPlaying { get { lock (_gate) return _run is not null; } }

    internal static string BuildDescription(string rtspUri, int latencyMs = 20,
        int bufferMode = 3, string sink = "d3d11videosink", string transport = "auto")
    {
        new VideoPlaybackOptions(transport, latencyMs).Validate();
        var uri = VideoPlaybackOptions.ValidateUri(rtspUri);
        if (sink is not ("d3d11videosink" or "fakesink"))
            throw new ArgumentException("Unsupported video sink.");
        if (bufferMode is < 0 or > 4) throw new ArgumentException("Invalid buffer mode.");
        var protocol = transport == "auto" ? "" : $"protocols={transport} ";
        return string.Create(CultureInfo.InvariantCulture,
            $"rtspsrc name=source location=\"{uri}\" latency={latencyMs} buffer-mode={bufferMode} {protocol}" +
            $"! parsebin ! decodebin3 ! queue name=video-queue ! videoconvert " +
            $"! {sink} name=video-sink sync=false");
    }

    internal string? Start(string rtspUri, IntPtr windowHandle, VideoPlaybackOptions? options = null)
    {
        if (windowHandle == IntPtr.Zero) return "The video surface is not ready yet.";
        options ??= new();
        string description;
        try { description = BuildDescription(rtspUri, options.LatencyMs, transport: options.Transport); }
        catch (ArgumentException e) { return e.Message; }
        var init = GstInterop.Initialise();
        if (init is not null) return init;
        return StartPipeline(description, windowHandle);
    }

    // Same lifecycle used by native host fixtures with a finite local fakesrc/fakesink.
    // It never changes receiver configuration or assumes buffers were displayed.
    internal string? StartPipeline(string description, IntPtr windowHandle)
    {
        Stop();
        var pipeline = GstInterop.gst_parse_launch(description, out var error);
        if (error != IntPtr.Zero)
        {
            var reason = GstInterop.MessageOf(error) ?? "Could not parse the video pipeline.";
            GstInterop.g_error_free(error);
            if (pipeline != IntPtr.Zero) GstInterop.gst_object_unref(pipeline);
            return reason;
        }
        if (pipeline == IntPtr.Zero) return "Could not build the video pipeline.";
        var sink = GstInterop.gst_bin_get_by_name(pipeline, "video-sink");
        if (sink == IntPtr.Zero)
        {
            GstInterop.gst_object_unref(pipeline);
            return "The pipeline has no video sink.";
        }
        if (windowHandle != IntPtr.Zero)
            GstInterop.gst_video_overlay_set_window_handle(sink, windowHandle);
        var run = new Run { Pipeline = pipeline,
            Pad = GstInterop.gst_element_get_static_pad(sink, "sink") };
        GstInterop.gst_object_unref(sink);
        if (run.Pad == IntPtr.Zero)
        {
            GstInterop.gst_object_unref(pipeline);
            return "The video sink has no observable input pad.";
        }
        run.Probe = (_, _, _) =>
        {
            // Never throw through a native callback; no UI work on streaming thread.
            try { Interlocked.Increment(ref run.Buffers); } catch { }
            return 1; // GST_PAD_PROBE_OK
        };
        run.ProbeId = GstInterop.gst_pad_add_probe(run.Pad, GstInterop.PAD_PROBE_BUFFER,
            run.Probe, IntPtr.Zero, IntPtr.Zero);
        lock (_gate) { _run = run; LastError = null; }
        Publish(run, new("starting", 0));
        var stateResult = GstInterop.gst_element_set_state(pipeline, GstInterop.STATE_PLAYING);
        if (stateResult == 0) // GST_STATE_CHANGE_FAILURE
        {
            Stop();
            LastError = "The video pipeline refused to enter playback.";
            return LastError;
        }
        run.Watch = new Thread(() => WatchBus(run)) { IsBackground = true, Name = "gst-bus" };
        run.Watch.Start();
        return null;
    }

    private void Publish(Run run, VideoPlaybackStatus status)
    {
        Action<VideoPlaybackStatus>? changed;
        lock (_gate)
        {
            if (_run != run || run.Cancel.IsCancellationRequested) return;
            var previous = run.LastPublished;
            // Notify transitions rather than re-rendering the Live form for every
            // buffer. Counts describe the observation at that transition.
            if (previous is not null && previous.State == status.State &&
                previous.DecodedCaps == status.DecodedCaps && previous.Error == status.Error &&
                previous.Detail == status.Detail) return;
            run.LastPublished = status;
            if (status.Error is not null) LastError = status.Error;
            else if (status.State == "decoded-input") LastError = null;
            changed = Changed;
        }
        // Subscribers may dispatch to another thread or read controller state.
        // Never hold the native lifecycle gate across external consumer code.
        try { changed?.Invoke(status); } catch { /* consumer cannot break native lifecycle */ }
    }

    private void WatchBus(Run run)
    {
        var bus = GstInterop.gst_element_get_bus(run.Pipeline);
        if (bus == IntPtr.Zero) { Publish(run, new("failed", 0, Error: "The video bus is unavailable.")); return; }
        long last = 0;
        var lastBuffer = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            while (!run.Cancel.IsCancellationRequested)
            {
                var msg = GstInterop.gst_bus_timed_pop_filtered(bus, 200_000_000UL,
                    GstInterop.MESSAGE_ERROR | GstInterop.MESSAGE_EOS | GstInterop.MESSAGE_WARNING |
                    GstInterop.MESSAGE_ELEMENT | GstInterop.MESSAGE_STATE_CHANGED | GstInterop.MESSAGE_ASYNC_DONE);
                var count = Interlocked.Read(ref run.Buffers);
                if (count > last)
                {
                    last = count; lastBuffer.Restart();
                    // A source handoff can renegotiate while this pipeline stays
                    // alive. The first frame's caps must not mask later formats.
                    run.Caps = ReadCaps(run.Pad) ?? run.Caps;
                    Publish(run, new("decoded-input", count, run.Caps));
                }
                else if (lastBuffer.ElapsedMilliseconds > 3000)
                    Publish(run, new(count == 0 ? "waiting-for-frames" : "frames-stale", count, run.Caps));
                if (msg == IntPtr.Zero) continue;
                try
                {
                    var type = GstInterop.MessageType(msg);
                    if (type == GstInterop.MESSAGE_EOS)
                    { Publish(run, new("ended", count, run.Caps, "The video stream ended.")); break; }
                    if (type is GstInterop.MESSAGE_ERROR or GstInterop.MESSAGE_WARNING)
                    {
                        IntPtr err, debug;
                        if (type == GstInterop.MESSAGE_ERROR) GstInterop.gst_message_parse_error(msg, out err, out debug);
                        else GstInterop.gst_message_parse_warning(msg, out err, out debug);
                        try
                        {
                            var text = GstInterop.MessageOf(err) ?? "Video pipeline error.";
                            // Keep native element/reason context, with endpoint secrets
                            // removed before it enters the status/publication path.
                            var detail = VideoPlaybackOptions.LogDetail(Marshal.PtrToStringUTF8(debug));
                            if (type == GstInterop.MESSAGE_WARNING)
                                detail = VideoPlaybackOptions.LogDetail(text + " " + detail);
                            Publish(run, new(type == GstInterop.MESSAGE_ERROR ? "failed" : "warning",
                                count, run.Caps, type == GstInterop.MESSAGE_ERROR ? text : null, detail));
                        }
                        finally { if (err != IntPtr.Zero) GstInterop.g_error_free(err); if (debug != IntPtr.Zero) GstInterop.g_free(debug); }
                        if (type == GstInterop.MESSAGE_ERROR) break;
                    }
                    else if (type == GstInterop.MESSAGE_ELEMENT)
                    {
                        var structure = GstInterop.gst_message_get_structure(msg);
                        if (structure != IntPtr.Zero)
                        {
                            var text = GstInterop.gst_structure_to_string(structure);
                            try
                            {
                                var detail = Marshal.PtrToStringUTF8(text);
                                if (detail?.StartsWith("GstRTSPSrcTimeout", StringComparison.Ordinal) == true)
                                    Publish(run, new("source-timeout", count, run.Caps,
                                        "RTCP source timeout reported.", detail));
                            }
                            finally { if (text != IntPtr.Zero) GstInterop.g_free(text); }
                        }
                    }
                }
                finally { GstInterop.gst_message_unref(msg); }
            }
        }
        catch (Exception ex) { Publish(run, new("failed", last, Error: "Video observation failed: " + ex.GetType().Name)); }
        finally { GstInterop.gst_object_unref(bus); }
    }

    private static string? ReadCaps(IntPtr pad)
    {
        var caps = GstInterop.gst_pad_get_current_caps(pad);
        if (caps == IntPtr.Zero) return null;
        try
        {
            var text = GstInterop.gst_caps_to_string(caps);
            try { return Marshal.PtrToStringUTF8(text); }
            finally { if (text != IntPtr.Zero) GstInterop.g_free(text); }
        }
        finally { GstInterop.gst_caps_unref(caps); }
    }

    internal void Stop()
    {
        Run? run;
        lock (_gate) { run = _run; _run = null; }
        if (run is null) return;
        run.Cancel.Cancel();
        // Bus wait is bounded200ms; finish it before releasing its native pipeline.
        run.Watch?.Join();
        GstInterop.gst_element_set_state(run.Pipeline, GstInterop.STATE_NULL);
        if (run.ProbeId != UIntPtr.Zero) GstInterop.gst_pad_remove_probe(run.Pad, run.ProbeId);
        GstInterop.gst_object_unref(run.Pad);
        GstInterop.gst_object_unref(run.Pipeline);
        GC.KeepAlive(run.Probe);
        run.Cancel.Dispose();
    }
    public void Dispose() => Stop();
}
