using System.IO;
using System.Runtime.InteropServices;

namespace Ascent.Desktop;

/// <summary>Where the GStreamer runtime came from, for display and for support.</summary>
internal enum GstSource
{
    /// <summary>Shipped inside the Ascent Control installation. The normal case.</summary>
    Bundled,
    /// <summary>A machine-global install, used only because no bundled copy exists.</summary>
    ExternalFallback,
    /// <summary>Nothing usable was found.</summary>
    Unavailable,
}

/// <summary>
/// What went wrong, specifically enough to tell an operator something useful.
///
/// These are deliberately SEPARATE causes with separate remedies. Before this they
/// were one sentence -- "GStreamer was not found", with a list of searched paths --
/// which is the right message for exactly one of them and misleading for the rest.
/// </summary>
internal enum GstFault
{
    None,
    /// <summary>No runtime at all: the install is incomplete.</summary>
    RuntimeMissing,
    /// <summary>Found the files but the OS refused to load them.</summary>
    LoadFailed,
    /// <summary>Loaded, but an element the pipeline needs has no plugin.</summary>
    PluginMissing,
    /// <summary>The plugin cache could not be written, so discovery cannot persist.</summary>
    RegistryUnwritable,
}

/// <summary>
/// Finds the GStreamer runtime, preferring the copy shipped with Ascent Control.
///
/// WHY THIS EXISTS, in one paragraph, because the reason is a shipped defect rather
/// than a design preference. The first release searched only machine-global
/// locations -- the GSTREAMER_1_0_ROOT_MSVC_X86_64 environment variable,
/// C:\gstreamer and C:\Program Files\gstreamer. On every development machine one of
/// those was populated, so video worked everywhere it was tried. On a clean Windows
/// install none of them exist, the MSI installs no GStreamer of its own, and video
/// could not start at all. The dependency was real, undeclared, and invisible to
/// everyone who already had it.
///
/// BUNDLED IS PREFERRED EVEN WHEN A GLOBAL INSTALL EXISTS. Not for purity: a global
/// copy is a different version with a different plugin set, so whichever one wins
/// decides whether a bug reproduces. Preferring our own makes behaviour the same on
/// every machine, which is the only way a support report means anything.
///
/// THE EXTERNAL FALLBACK IS RETAINED DELIBERATELY and is reported as such, so a
/// developer running from a source checkout -- where no bundled copy is staged --
/// still gets video, and so that a machine whose bundled files were damaged degrades
/// to something rather than nothing. It is never silent: the UI names the source.
/// </summary>
internal static class GstRuntimeLocator
{
    private const string CoreDll = "gstreamer-1.0-0.dll";

    /// <summary>Laid out exactly as upstream does, so the staging script copies rather than rearranges.</summary>
    internal const string BundleDirName = "gstreamer";
    internal const string BundleBinRel = BundleDirName + @"\bin";
    internal const string BundlePluginRel = BundleDirName + @"\lib\gstreamer-1.0";

    internal static string BundleRoot =>
        Path.Combine(AppContext.BaseDirectory, BundleDirName);
    internal static string BundledBinDirectory =>
        Path.Combine(AppContext.BaseDirectory, BundleDirName, "bin");
    internal static string BundledPluginDirectory =>
        Path.Combine(AppContext.BaseDirectory, BundleDirName, "lib", "gstreamer-1.0");

    /// <summary>
    /// The plugin cache. It must NOT live under Program Files: that directory is
    /// read-only for a standard user, and a cache that cannot be written is rebuilt
    /// on every launch -- which turns a one-off scan into a per-start delay and, on
    /// a locked-down machine, into a confusing partial plugin list.
    /// </summary>
    internal static string RegistryFile
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(local, "Ascent Control", "gstreamer", "registry.bin");
        }
    }

    /// <summary>
    /// Machine-global locations, searched ONLY when no bundled copy is present.
    /// The MinGW build is deliberately not searched: mixing runtimes produces
    /// failures that look like missing plugins.
    /// </summary>
    internal static IEnumerable<string> ExternalCandidates()
    {
        var env = Environment.GetEnvironmentVariable("GSTREAMER_1_0_ROOT_MSVC_X86_64");
        if (!string.IsNullOrWhiteSpace(env))
            yield return Path.Combine(env, "bin");
        yield return @"C:\gstreamer\1.0\msvc_x86_64\bin";
        yield return @"C:\Program Files\gstreamer\1.0\msvc_x86_64\bin";
    }

    internal readonly record struct Found(GstSource Source, string? BinDirectory, string? PluginDirectory);

    /// <summary>Bundled first, always. Returns Unavailable rather than throwing.</summary>
    internal static Found Locate()
    {
        var bundledBin = BundledBinDirectory;
        if (SafeExists(Path.Combine(bundledBin, CoreDll)))
            return new Found(GstSource.Bundled, bundledBin, BundledPluginDirectory);

        foreach (var dir in ExternalCandidates())
        {
            if (!SafeExists(Path.Combine(dir, CoreDll))) continue;
            // Upstream layout: <root>\bin and <root>\lib\gstreamer-1.0 are siblings.
            var root = Path.GetDirectoryName(dir.TrimEnd(Path.DirectorySeparatorChar));
            var plugins = root is null ? null
                : Path.Combine(root, "lib", "gstreamer-1.0");
            return new Found(GstSource.ExternalFallback, dir, plugins);
        }
        return new Found(GstSource.Unavailable, null, null);
    }

    private static bool SafeExists(string path)
    {
        try { return File.Exists(path); }
        catch { return false; }   // a malformed path from the environment
    }
}
