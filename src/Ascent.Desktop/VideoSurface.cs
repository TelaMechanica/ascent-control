using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Ascent.Desktop;

/// <summary>
/// A bare Win32 child window for GStreamer's video sink to draw into.
///
/// d3d11videosink renders through GstVideoOverlay, which needs a real HWND -- it
/// cannot draw into a WPF visual. So this is an HwndHost wrapping a plain child
/// window and nothing else; no painting of our own, because the sink owns every
/// pixel inside it.
///
/// **Why video is a separate top-level window rather than a panel in the main one.**
/// Microsoft.Web.WebView2.Wpf.WebView2 is itself an HwndHost, and MainWindow.xaml
/// already records the consequence: its native child window composes ABOVE all WPF
/// content regardless of z-order. Two HwndHosts in one window therefore cannot be
/// layered, only tiled -- and tiling would mean shrinking the approved web UI and
/// teaching it that it no longer owns the window. A separate owned window avoids
/// the airspace problem completely and keeps the locked UI untouched.
/// </summary>
internal sealed class VideoSurface : HwndHost
{
    private const int WS_CHILD = 0x40000000;
    private const int WS_VISIBLE = 0x10000000;
    private const int WS_CLIPCHILDREN = 0x02000000;
    private const int WS_CLIPSIBLINGS = 0x04000000;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(
        int exStyle, string className, string? windowName, int style,
        int x, int y, int width, int height,
        IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hwnd);

    /// <summary>The handle handed to gst_video_overlay_set_window_handle.</summary>
    internal IntPtr SurfaceHandle { get; private set; }

    protected override HandleRef BuildWindowCore(HandleRef hwndParent)
    {
        SurfaceHandle = CreateWindowExW(
            0, "static", null,
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0, 0, (int)Math.Max(1, ActualWidth), (int)Math.Max(1, ActualHeight),
            hwndParent.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (SurfaceHandle == IntPtr.Zero)
            throw new InvalidOperationException(
                "Could not create the native video surface: " +
                Marshal.GetLastWin32Error());
        return new HandleRef(this, SurfaceHandle);
    }

    protected override void DestroyWindowCore(HandleRef hwnd)
    {
        if (hwnd.Handle != IntPtr.Zero) DestroyWindow(hwnd.Handle);
        SurfaceHandle = IntPtr.Zero;
    }
}
