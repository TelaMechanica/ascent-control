using System.Net.Http;
using System.Linq;
using System.Text;

namespace Ascent.Desktop;

/// <summary>
/// Reads a joystick continuously and posts the axes to the backend.
///
/// The split is deliberate. HID produces an event only when a stick moves; CRSF
/// wants a steady rate whether or not one did. So the host reads at input rate and
/// the backend transmits on its own clock -- which is also the only arrangement in
/// which "the sticks stopped arriving" is detectable at all. The backend stops
/// transmitting when that happens; see runtime/caddx_hid.py.
///
/// This class therefore posts and nothing more. It never builds a CRSF frame and
/// never opens a socket to the aircraft: one CRSF implementation, in Python, already
/// tested.
/// </summary>
internal sealed class HidPump : IDisposable
{
    private readonly BoundedLogWriter? _log;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private readonly HidJoystick _stick = new();
    private Thread? _thread;
    private volatile bool _stop;
    private Uri? _baseUri;
    private string? _epoch;
    private long _sequence;
    private long _epochOrder;

    internal string? Product => _stick.Product;
    internal int ButtonCount => _stick.ButtonCount;
    internal int AxisCount => _stick.Axes.Count;
    internal bool Running => _thread is { IsAlive: true };
    internal string? LastError { get; private set; }
    internal long Posted { get; private set; }
    internal ushort[]? LastAxes { get; private set; }

    internal HidPump(BoundedLogWriter? log) => _log = log;

    internal void SetBackend(Uri baseUri) => _baseUri = baseUri;

    internal static bool IsPublicDevice(string? product)
    {
        var text = product ?? "";
        foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(
            text, @"[a-z]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            var token = match.Value.ToLowerInvariant();
            if (token.EndsWith("x", StringComparison.Ordinal) && match.Index + match.Length < text.Length
                && char.IsAsciiDigit(text[match.Index + match.Length])) token = token[..^1];
            var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(token)));
            if (fingerprint is "2FD02CB5903E6608BCB7499A38B9204D0CAE711687E7A8F4866F96494AFA735D" or "0BB09D80600EEC3EB9D7793A6F859BEDDE2A2D83899B70BD78E961ED674B32F4") return false;
        }
        return true;
    }

    internal static List<HidJoystick.DeviceInfo> Enumerate() => HidJoystick.Enumerate().Where(d => IsPublicDevice(d.Product)).ToList();

    /// <summary>Open a stick and start pumping. Returns null on success, or a reason.</summary>
    internal string? Start(string devicePath)
    {
        Stop();
        if (_baseUri is null) return "The backend is not running yet.";
        var observed = HidJoystick.Enumerate().FirstOrDefault(d => d.Path == devicePath);
        if (observed is null) return "The selected controller is no longer available. Find sticks again.";
        if (!IsPublicDevice(observed.Product)) return "This controller is available in AC+.";
        var reason = _stick.Open(devicePath);
        if (reason is not null) { _log?.WriteLine($"[hid] refused {devicePath}: {reason}"); return reason; }
        if (!IsPublicDevice(_stick.Product)) { _stick.Close(); return "This controller is available in AC+."; }
        // NO EIGHT-AXIS MINIMUM. A seven-axis gamepad was refused here on the bench
        // and the refusal was invisible, so pressing USE looked like a dead button.
        //
        // The rule was not protecting anything. Frames are not built positionally
        // from axes; the backend resolves them through a channel map whose entries
        // may be an axis, a button or a fixed value, so a seven-axis stick with
        // buttons fills sixteen channels. The real protections live in the backend
        // and are untouched: a channel mapped to an axis the device does not report
        // is refused by name, and the stream will not run while any channel is
        // unassigned.
        if (_stick.Axes.Count == 0)
            return $"{Product} reports no axes, so there is nothing to read.";
        _epoch=Guid.NewGuid().ToString("N");_epochOrder=System.Diagnostics.Stopwatch.GetTimestamp();_sequence=0;
        try { PostSource("connect"); }
        catch(Exception ex) { _stick.Close();LastError=ex.Message;return "HID identity registration failed: "+ex.Message; }
        _stop = false;
        LastError = null;
        Posted = 0;
        _thread = new Thread(Pump) { IsBackground = true, Name = "hid-pump" };
        _thread.Start();
        _log?.WriteLine($"[hid] pumping {Product} ({_stick.Axes.Count} axes)");
        return null;
    }

    private void PostSource(string action)
    {
        if(_epoch is null || _baseUri is null)return;
        var body=System.Text.Json.JsonSerializer.Serialize(new { action,epoch=_epoch,epoch_order=_epochOrder,device=_stick.SourceDevice,descriptor=_stick.Descriptor });
        using var content=new StringContent(body,Encoding.UTF8,"application/json");
        using var reply=_http.PostAsync(new Uri(_baseUri,"/api/cgc/hid/source"),content).GetAwaiter().GetResult();
        reply.EnsureSuccessStatusCode();
    }

    private void Pump()
    {
        var url = new Uri(_baseUri!, "/api/cgc/hid/axes");
        while (!_stop)
        {
            ushort[]? axes;
            try { axes = _stick.ReadAxes(); }
            catch (Exception ex) { LastError = ex.Message; break; }
            if (axes is null) { LastError = "The device stopped reporting."; break; }
            LastAxes = axes;
            try
            {
                // BUTTONS TRAVEL WITH THE AXES. They were never sent before: the
                // backend accepted a `buttons` array, the channel map supported a
                // button source, and the UI offered Button 0-7 -- but nothing ever
                // produced one, so every button mapping failed with
                // MAP_BUTTON_MISSING. On a transmitter-style controller that is the
                // difference between usable and not: such a device has few axes and
                // many switches, and channel 5 is commonly ARM.
                var btns = _stick.LastButtons;
                var body=System.Text.Json.JsonSerializer.Serialize(new { source="hid",epoch=_epoch,sequence=++_sequence,
                          axes,buttons=btns,raw_axes=_stick.LastRawAxes });
                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                using var res = _http.PostAsync(url, content).GetAwaiter().GetResult();
                if (res.IsSuccessStatusCode) Posted++;
                else LastError = $"backend returned {(int)res.StatusCode}";
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                // A transient backend hiccup should not kill the reader; a persistent
                // one shows up as the axes going stale, which stops transmission.
                Thread.Sleep(100);
            }
        }
        try { PostSource("disconnect"); } catch(Exception ex) { LastError=ex.Message; }
        _log?.WriteLine("[hid] pump ended: " + (LastError ?? "stopped"));
    }

    internal void Stop()
    {
        _stop = true;
        // ReadFile blocks, so the thread may be parked in the driver until the next
        // report. Closing the handle is what releases it.
        _stick.Close();
        if (_thread is { IsAlive: true }) _thread.Join(TimeSpan.FromSeconds(1));
        // Never reuse a reader while its previous thread can still post old samples.
        if(_thread is { IsAlive:true }) throw new InvalidOperationException("Previous HID reader is still stopping.");
        try { PostSource("disconnect"); } catch(Exception ex) { LastError=ex.Message; }
        _thread = null;LastAxes=null;
    }

    public void Dispose() { Stop(); _http.Dispose(); }
}
