namespace Ascent.Desktop;

/// <summary>
/// Turns a video failure into something an operator can act on, and keeps the
/// technical form separately for support.
///
/// WHY THESE ARE SEPARATE SENTENCES. Before this, every initialisation failure
/// produced one message -- "GStreamer was not found. Looked for
/// gstreamer-1.0-0.dll under ..." followed by three machine-global paths. That
/// sentence is correct for exactly one cause and actively misleading for the
/// rest: it names a product the operator never installed and never should have to,
/// and it invites them to go and install it, which is the wrong remedy now that
/// the runtime ships inside the application.
///
/// The remedies genuinely differ:
///   * components missing      -> the installation is incomplete: repair it.
///   * load failure            -> the files are there but unusable: repair it.
///   * a plugin missing        -> same, but names which, behind Details.
///   * cache unwritable        -> a permissions problem, not a broken install.
///   * no hardware decoder     -> nothing is broken; this machine has no GPU
///                                video decoding. Repairing will not help, so
///                                saying "reinstall" would waste the operator's
///                                time and still not fix it.
/// </summary>
internal static class GstDiagnostics
{
    /// <summary>The sentence the normal UI shows. No paths, no plugin names, no product names.</summary>
    internal static string PlainMessage(GstFault fault) => fault switch
    {
        GstFault.RuntimeMissing =>
            "Video components are incomplete. Repair or reinstall Ascent Control.",
        GstFault.LoadFailed =>
            "Video components are present but could not be loaded. Repair or reinstall Ascent Control.",
        GstFault.PluginMissing =>
            "Video components are incomplete. Repair or reinstall Ascent Control.",
        GstFault.RegistryUnwritable =>
            "Video could not prepare its working files. Check that your user profile is writable.",
        _ => "Video could not start.",
    };

    /// <summary>Bundled / External fallback / Unavailable, for the runtime row.</summary>
    internal static string SourceLabel(GstSource source) => source switch
    {
        GstSource.Bundled => "Bundled",
        GstSource.ExternalFallback => "External fallback",
        _ => "Unavailable",
    };

    /// <summary>
    /// Classify a RUNTIME failure -- one that arrives on the bus after the pipeline
    /// is already playing -- from the message GStreamer produced.
    ///
    /// This is pattern matching on another project's error text, which is fragile,
    /// so it is used only to pick a friendlier sentence and never to decide
    /// behaviour. An unrecognised message falls through to the text itself rather
    /// than being swallowed.
    /// </summary>
    internal static string RuntimePlainMessage(string? gstMessage)
    {
        var m = (gstMessage ?? string.Empty).ToLowerInvariant();
        if (m.Length == 0) return "The video stream stopped.";

        if (m.Contains("could not open resource") || m.Contains("connect") ||
            m.Contains("not found") || m.Contains("unauthorized") || m.Contains("refused"))
            return "Could not reach the video stream on the receiver. Check that it is connected and powered.";
        if (m.Contains("not negotiated") || m.Contains("negotiation"))
            return "The receiver and this computer could not agree on a video format.";
        if (m.Contains("decode") || m.Contains("decoder") || m.Contains("no decoder"))
            return "This computer could not decode the video. Its graphics adapter may not support the format the receiver is sending.";
        if (m.Contains("output window") || m.Contains("sink") || m.Contains("d3d11") || m.Contains("device"))
            return "The video could not be displayed. The graphics adapter refused the video window.";
        return "The video stream stopped.";
    }
}
