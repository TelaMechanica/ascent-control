using System.Runtime.InteropServices;
using System.IO;
using System.Linq;

namespace Ascent.Desktop;

/// <summary>
/// Minimal P/Invoke surface for GStreamer, used to render the device's RTSP stream.
///
/// CGC v0.3.5 does this through gstreamer-sharp (its 3rdLibs carries
/// gstreamer-sharp.dll, gio-sharp.dll and glib-sharp.dll) over the same native
/// runtime. We bind the C API directly instead, for two reasons: the managed
/// binding is a NuGet package this build cannot fetch, and vendoring a DLL out of
/// Caddx's installer is a redistribution decision that is not ours to make quietly.
///
/// The cost of binding directly is that the pipeline is built with
/// gst_parse_launch rather than element by element, so we do not get the vendor's
/// per-pad probe callbacks. The data path is identical; what is lost is their
/// source/decoder timeout detection, which is re-implemented more simply here as a
/// bus watch. That difference is stated in docs/CGC_LIVE_MODE.md rather than hidden.
///
/// Nothing here is loaded until video is actually requested, so a machine without
/// GStreamer runs the rest of the application normally and reports the absence.
/// </summary>
internal static class GstInterop
{
    private const string GstLib = "gstreamer-1.0-0.dll";
    private const string GstVideoLib = "gstvideo-1.0-0.dll";

    // GstState
    internal const int STATE_NULL = 1;
    internal const int STATE_READY = 2;
    internal const int STATE_PAUSED = 3;
    internal const int STATE_PLAYING = 4;

    // GstMessageType bits we watch.
    internal const uint MESSAGE_ERROR = 1 << 1;
    internal const uint MESSAGE_EOS = 1 << 0;

    internal const uint MESSAGE_WARNING = 1 << 2;
    internal const uint MESSAGE_STATE_CHANGED = 1 << 6;
    internal const uint MESSAGE_ELEMENT = 1 << 15;
    internal const uint MESSAGE_ASYNC_DONE = 1 << 21;
    internal const uint PAD_PROBE_BUFFER = 1 << 4;

    // Public GStreamer1.x headers: GstMessage starts with GstMiniObject then type.
    // Sequential native alignment, not a magic byte offset. Native fixture checks
    // gst_message_new_eos against this ABI on the shipped Windows runtime.
    [StructLayout(LayoutKind.Sequential)]
    internal struct MiniObjectPrefix
    {
        public UIntPtr Type;
        public int RefCount, LockState;
        public uint Flags;
        public IntPtr Copy, Dispose, Free;
        public uint PrivateUint;
        public IntPtr PrivatePointer;
    }
    internal static uint MessageType(IntPtr message) =>
        unchecked((uint)Marshal.ReadInt32(message, Marshal.SizeOf<MiniObjectPrefix>()));

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int PadProbe(IntPtr pad, IntPtr info, IntPtr user);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern UIntPtr gst_pad_add_probe(IntPtr pad, uint mask, PadProbe callback, IntPtr user, IntPtr destroy);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_pad_remove_probe(IntPtr pad, UIntPtr id);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr gst_element_get_static_pad(IntPtr element, string name);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_pad_get_current_caps(IntPtr pad);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_caps_to_string(IntPtr caps);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_caps_unref(IntPtr caps);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_message_parse_warning(IntPtr message, out IntPtr error, out IntPtr debug);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_message_get_structure(IntPtr message);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_structure_to_string(IntPtr structure);
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_message_new_eos(IntPtr source);
    [DllImport("glib-2.0-0.dll", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void g_free(IntPtr value);
    [DllImport("glib-2.0-0.dll", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void g_error_free(IntPtr error);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_init(IntPtr argc, IntPtr argv);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr gst_parse_launch(string pipelineDescription, out IntPtr error);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int gst_element_set_state(IntPtr element, int state);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_object_unref(IntPtr obj);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr gst_bin_get_by_name(IntPtr bin, string name);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_element_get_bus(IntPtr element);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_bus_timed_pop_filtered(IntPtr bus, ulong timeout, uint types);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_message_unref(IntPtr msg);

    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_message_parse_error(IntPtr msg, out IntPtr err, out IntPtr debug);

    [DllImport(GstVideoLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void gst_video_overlay_set_window_handle(IntPtr overlay, IntPtr handle);

    /// <summary>"GStreamer 1.28.7" and so on. Reported in the UI so a support
    /// report can say which runtime actually ran, not which one was installed.</summary>
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr gst_version_string();

    /// <summary>Non-null when an element can be built. Used to tell a MISSING
    /// PLUGIN apart from a runtime that would not load at all -- two different
    /// faults with two different remedies, previously one message.</summary>
    [DllImport(GstLib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr gst_element_factory_find(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string? path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);

    /// <summary>Resolve this library's OWN dependencies starting from the directory
    /// it lives in, rather than from the process search path.</summary>
    private const uint LoadWithAlteredSearchPath = 0x00000008;

    /// <summary>GError layout: domain (uint32), code (int32), message (char*).</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct GError
    {
        public uint Domain;
        public int Code;
        public IntPtr Message;
    }

    internal static string? MessageOf(IntPtr gerror)
    {
        if (gerror == IntPtr.Zero) return null;
        var e = Marshal.PtrToStructure<GError>(gerror);
        return e.Message == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(e.Message);
    }

    private static bool _initialised;
    private static string? _runtimeDirectory;
    private static GstSource _source = GstSource.Unavailable;
    private static string? _version;

    internal static string? RuntimeDirectory => _runtimeDirectory;

    /// <summary>Bundled / External fallback / Unavailable, for display.</summary>
    internal static GstSource Source => _source;

    /// <summary>The runtime's own version string, once it has loaded.</summary>
    internal static string? Version => _version;

    /// <summary>What failed, specifically. None once initialisation has succeeded.</summary>
    internal static GstFault Fault { get; private set; } = GstFault.None;

    /// <summary>
    /// Every element the application's own pipeline needs, including the ones
    /// rtspsrc and decodebin3 build at runtime rather than at parse time.
    ///
    /// Checked individually so a missing plugin names ITSELF. A pipeline that
    /// fails to parse reports only the first element it could not find, and a
    /// decoder chosen dynamically does not appear in the pipeline string at all,
    /// so neither would have told an operator which file was absent.
    /// </summary>
    internal static readonly string[] RequiredElements =
    {
        "queue", "typefind", "parsebin", "decodebin3", "videoconvert",
        "rtspsrc", "rtpjitterbuffer", "udpsrc",
        "rtph264depay", "rtph265depay", "h264parse", "h265parse",
        "d3d11videosink",
    };

    /// <summary>
    /// Decoders. Kept apart from RequiredElements because their absence is a
    /// DIFFERENT failure: these are hardware decoders provided by the GPU driver
    /// through D3D11, so on a machine with no video-capable GPU -- a VM, a remote
    /// session, a very old adapter -- they can be legitimately missing while the
    /// install is perfectly intact. Reporting that as a broken installation would
    /// send the operator to reinstall something that is not broken.
    /// </summary>
    internal static readonly string[] DecoderElements = { "d3d11h264dec", "d3d11h265dec" };

    internal static bool HasElement(string name)
    {
        try
        {
            var f = gst_element_factory_find(name);
            if (f == IntPtr.Zero) return false;
            gst_object_unref(f);
            return true;
        }
        catch { return false; }
    }

    internal static string[] MissingElements(IEnumerable<string> names)
        => names.Where(n => !HasElement(n)).ToArray();

    /// <summary>
    /// Point GStreamer at the bundled plugins and a writable cache, for THIS
    /// PROCESS AND ITS CHILDREN ONLY.
    ///
    /// Environment.SetEnvironmentVariable without an EnvironmentVariableTarget
    /// writes the process block. It does not touch the registry, the machine PATH
    /// or the user PATH, and it disappears when the process exits. That is a
    /// requirement rather than an implementation detail: an installer that edits
    /// the machine PATH to make its own video work is a change the operator did
    /// not ask for and cannot easily find later.
    ///
    /// GST_PLUGIN_SYSTEM_PATH_1_0 is set EVEN WHEN EMPTY on the bundled path.
    /// Leaving it unset lets GStreamer fall back to the directory compiled into
    /// the build, which on a machine that also has a global install is that
    /// install's plugin directory -- so a stray global plugin could load into our
    /// process and change behaviour we thought was pinned.
    /// </summary>
    private static GstFault PrepareEnvironment(GstRuntimeLocator.Found found)
    {
        if (found.PluginDirectory is not null)
        {
            Environment.SetEnvironmentVariable("GST_PLUGIN_SYSTEM_PATH_1_0", found.PluginDirectory);
            Environment.SetEnvironmentVariable("GST_PLUGIN_PATH_1_0", found.PluginDirectory);
            // The unsuffixed names are consulted by older code paths; clear them so
            // an inherited value cannot widen the search.
            Environment.SetEnvironmentVariable("GST_PLUGIN_SYSTEM_PATH", found.PluginDirectory);
            Environment.SetEnvironmentVariable("GST_PLUGIN_PATH", found.PluginDirectory);
        }

        var registry = GstRuntimeLocator.RegistryFile;
        try
        {
            var dir = Path.GetDirectoryName(registry);
            if (dir is not null) Directory.CreateDirectory(dir);
            Environment.SetEnvironmentVariable("GST_REGISTRY_1_0", registry);
            Environment.SetEnvironmentVariable("GST_REGISTRY", registry);
            // SCAN PLUGINS IN-PROCESS. Without this, gst_init forks
            // gst-plugin-scanner.exe to scan the registry whenever it is cold
            // (first run after install) or the plugin set changed -- and that
            // scanner is a console program that flashes visible black windows on
            // launch. Reported from the bench as "powershell windows popping up,
            // ~4 on launch"; it arrived with the bundled GStreamer, not the Python
            // probes (which already hide their consoles). Forking buys crash
            // isolation during the scan that a fixed, self-contained, pinned
            // plugin set does not need. In-process scan = zero windows.
            Environment.SetEnvironmentVariable("GST_REGISTRY_FORK", "no");
        }
        catch
        {
            return GstFault.RegistryUnwritable;
        }
        return GstFault.None;
    }

    /// <summary>
    /// Make the runtime loadable and call gst_init once. Returns null on success or
    /// a human-readable reason on failure -- never throws, because video being
    /// unavailable must not take down the application. Fault carries the machine
    /// -readable cause for the UI to branch on.
    /// </summary>
    internal static string? Initialise()
    {
        if (_initialised) return null;

        var found = GstRuntimeLocator.Locate();
        if (found.Source == GstSource.Unavailable || found.BinDirectory is null)
        {
            Fault = GstFault.RuntimeMissing;
            _source = GstSource.Unavailable;
            return "The bundled video components are missing from this installation.";
        }

        var envFault = PrepareEnvironment(found);
        if (envFault != GstFault.None)
        {
            Fault = envFault;
            return "The video plugin cache could not be created under " +
                   GstRuntimeLocator.RegistryFile + ".";
        }

        // The transitive dependencies (glib, gobject, gstvideo) live beside the core
        // DLL, so the directory itself has to be searchable rather than just the file.
        if (!SetDllDirectory(found.BinDirectory))
        {
            Fault = GstFault.LoadFailed;
            return $"Could not add {found.BinDirectory} to the library search path.";
        }

        // SetDllDirectory is not sufficient on its own, and the payload self-test
        // fails without this: a by-name P/Invoke resolved the core DLL but not its
        // dependencies (ERROR_MOD_NOT_FOUND). Pre-loading the core by ABSOLUTE path
        // with LOAD_WITH_ALTERED_SEARCH_PATH makes the loader resolve glib, gobject
        // and the rest from the bundle's own directory. Every later by-name P/Invoke
        // then binds to this already-loaded module.
        //
        // It also fixes a second, quieter fault: with a machine-global GStreamer on
        // PATH the loader could pair OUR core DLL with THEIR glib, which fails as
        // ERROR_PROC_NOT_FOUND (127) when the versions differ. Resolving from our own
        // directory first makes the bundle self-contained rather than merely present.
        var core = Path.Combine(found.BinDirectory, GstLib);
        if (LoadLibraryExW(core, IntPtr.Zero, LoadWithAlteredSearchPath) == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            Fault = GstFault.LoadFailed;
            return $"The video components at {found.BinDirectory} could not be loaded " +
                   $"(Windows error {err}).";
        }

        try
        {
            gst_init(IntPtr.Zero, IntPtr.Zero);
        }
        catch (DllNotFoundException ex)
        {
            Fault = GstFault.LoadFailed;
            return $"The video components at {found.BinDirectory} could not be loaded: {ex.Message}";
        }
        catch (BadImageFormatException)
        {
            Fault = GstFault.LoadFailed;
            return $"The video components at {found.BinDirectory} are not 64-bit, which this application requires.";
        }

        var missing = MissingElements(RequiredElements);
        if (missing.Length > 0)
        {
            Fault = GstFault.PluginMissing;
            _source = found.Source;
            _runtimeDirectory = found.BinDirectory;
            return "The video components are incomplete: " + string.Join(", ", missing) + ".";
        }

        try
        {
            var v = gst_version_string();
            _version = v == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(v);
        }
        catch { _version = null; }

        _runtimeDirectory = found.BinDirectory;
        _source = found.Source;
        Fault = GstFault.None;
        _initialised = true;
        return null;
    }

}
