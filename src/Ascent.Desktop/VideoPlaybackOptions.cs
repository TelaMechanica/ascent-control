namespace Ascent.Desktop;

/// <summary>Host playback choices only; never receiver encoder or RF settings.</summary>
internal sealed record VideoPlaybackOptions(string Transport = "auto", int LatencyMs = 20)
{
    internal void Validate()
    {
        if (Transport is not ("auto" or "udp" or "tcp"))
            throw new ArgumentException("Video transport must be auto, udp or tcp.");
        if (LatencyMs < 0 || LatencyMs > 2000)
            throw new ArgumentException("Video buffering must be 0..2000 ms.");
    }

    internal static string ValidateUri(string text)
    {
        if (text.Any(char.IsControl) || !Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || uri.Scheme != "rtsp" || string.IsNullOrWhiteSpace(uri.Host))
            throw new ArgumentException("A valid rtsp:// endpoint is required.");
        // AbsoluteUri escapes quotes and whitespace before gst_parse_launch sees it.
        return uri.AbsoluteUri;
    }

    internal static string DisplayEndpoint(string text)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return "Invalid endpoint";
        return new UriBuilder(uri) { UserName = "", Password = "", Query = "", Fragment = "" }.Uri.AbsoluteUri;
    }

    internal static string LogDetail(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "-";
        // Native error text can repeat the validated URI, including credentials
        // and query tokens. Keep the diagnostic but omit the complete URI.
        var safe = System.Text.RegularExpressions.Regex.Replace(text,
            @"(?i)\b(?:rtsp|rtsps|http|https)://[^\s""<>]+", "[endpoint]");
        safe = new string(safe.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        return safe.Length > 512 ? safe[..512] : safe;
    }
}

internal sealed record VideoPlaybackStatus(string State, long SinkBuffers,
    string? DecodedCaps = null, string? Error = null, string? Detail = null)
{
    // RTCP timeout is an element notification, not a fatal GstMessage ERROR.
    // Keep the existing session able to receive frames after an RF handoff.
    internal bool StopRequired => State is "failed" or "ended";
}
