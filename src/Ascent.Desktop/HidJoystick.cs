using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace Ascent.Desktop;

/// <summary>
/// Reads a HID joystick using Windows' own HID parser.
///
/// CGC v0.3.5 gets its descriptor handling from HidSharp. That is a NuGet package
/// this build cannot fetch offline, and the work it does -- walk the report
/// descriptor, find the value items, pull a logical value out of a report -- is
/// exactly what <c>HidP_GetValueCaps</c> and <c>HidP_GetData</c> already do in
/// <c>hid.dll</c>. So the parser is the operating system's, the same way the video
/// path uses the installed GStreamer rather than a bundled binding.
///
/// Axis selection follows <c>DescriptorDrivenParser</c> exactly: Generic Desktop
/// page (0x01), usages 0x30..0x40, in descriptor order. Values are normalized to
/// 0..2048 by the vendor's own formula, because that is the contract the rest of the
/// chain expects -- their parser reports every axis as 0..2048 regardless of what
/// the device declares.
/// </summary>
internal sealed class HidJoystick : IDisposable
{
    private const int GENERIC_DESKTOP_PAGE = 0x01;
    private const int USAGE_MIN = 0x30;
    private const int USAGE_MAX = 0x40;
    internal const int NORMALIZED_MAX = 2048;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint DIGCF_PRESENT = 0x02, DIGCF_DEVICEINTERFACE = 0x10;
    private const int HIDP_STATUS_SUCCESS = 0x00110000;

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDD_ATTRIBUTES
    { public int Size; public ushort VendorID, ProductID, VersionNumber; }

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDP_CAPS
    {
        public ushort Usage, UsagePage;
        public ushort InputReportByteLength, OutputReportByteLength, FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)] public ushort[] Reserved;
        public ushort NumberLinkCollectionNodes;
        public ushort NumberInputButtonCaps, NumberInputValueCaps, NumberInputDataIndices;
        public ushort NumberOutputButtonCaps, NumberOutputValueCaps, NumberOutputDataIndices;
        public ushort NumberFeatureButtonCaps, NumberFeatureValueCaps, NumberFeatureDataIndices;
    }

    // HIDP_VALUE_CAPS is 72 bytes. Only the fields we consume are named; the rest is
    // padding held by explicit offsets so the layout cannot drift.
    [StructLayout(LayoutKind.Explicit, Size = 72)]
    private struct HIDP_VALUE_CAPS
    {
        [FieldOffset(0)] public ushort UsagePage;
        [FieldOffset(2)] public byte ReportID;
        [FieldOffset(12)] public byte IsRange;
        [FieldOffset(6)] public ushort LinkCollection;
        [FieldOffset(18)] public ushort BitSize;
        [FieldOffset(20)] public ushort ReportCount;
        [FieldOffset(68)] public ushort DataIndex;
        [FieldOffset(70)] public ushort DataIndexMax;
        [FieldOffset(40)] public int LogicalMin;
        [FieldOffset(44)] public int LogicalMax;
        // Range.UsageMin and NotRange.Usage share this offset; IsRange says which.
        [FieldOffset(56)] public ushort Usage;
        [FieldOffset(58)] public ushort UsageMax;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    { public int cbSize; public Guid InterfaceClassGuid; public int Flags; public IntPtr Reserved; }

    [DllImport("hid.dll")] private static extern void HidD_GetHidGuid(out Guid guid);
    [DllImport("hid.dll")] private static extern bool HidD_GetAttributes(SafeFileHandle h, ref HIDD_ATTRIBUTES a);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)]
    private static extern bool HidD_GetProductString(SafeFileHandle h, byte[] buffer, int len);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)]
    private static extern bool HidD_GetManufacturerString(SafeFileHandle h, byte[] buffer, int len);
    [DllImport("hid.dll")] private static extern bool HidD_GetPreparsedData(SafeFileHandle h, out IntPtr data);
    [DllImport("hid.dll")] private static extern bool HidD_FreePreparsedData(IntPtr data);
    [DllImport("hid.dll")] private static extern int HidP_GetCaps(IntPtr preparsed, out HIDP_CAPS caps);
    [DllImport("hid.dll")] private static extern int HidP_GetValueCaps(int reportType, [Out] HIDP_VALUE_CAPS[] caps, ref ushort length, IntPtr preparsed);
    [DllImport("hid.dll")] private static extern int HidP_GetButtonCaps(int reportType, [Out] HIDP_BUTTON_CAPS[] caps, ref ushort length, IntPtr preparsed);
    [DllImport("hid.dll")] private static extern int HidP_MaxUsageListLength(int reportType, ushort usagePage, IntPtr preparsed);
    [DllImport("hid.dll")] private static extern int HidP_GetUsages(int reportType, ushort usagePage, ushort linkCollection, [Out] ushort[] usageList, ref int usageLength, IntPtr preparsed, byte[] report, int reportLength);

    /// <summary>
    /// HIDP_BUTTON_CAPS, explicit layout so the two fields we read are auditable
    /// against the SDK header rather than inferred from field order.
    ///
    /// x64 layout: UsagePage@0, ReportID@2, IsAlias@3, BitField@4, LinkCollection@6,
    /// LinkUsage@8, LinkUsagePage@10, IsRange@12, IsStringRange@13,
    /// IsDesignatorRange@14, IsAbsolute@15, ReportCount@16, Reserved[9]@20..55,
    /// then the Range/NotRange union at 56. Total 72 bytes.
    ///
    /// Only UsageMin and UsageMax are read, and only when IsRange is set -- a
    /// non-range button cap describes a single button at Usage@56.
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 72)]
    private struct HIDP_BUTTON_CAPS
    {
        [FieldOffset(0)]  public ushort UsagePage;
        [FieldOffset(2)] public byte ReportID;
        [FieldOffset(6)] public ushort LinkCollection;
        [FieldOffset(12)] public byte IsRange;
        [FieldOffset(56)] public ushort UsageMin;   // Range.UsageMin, or NotRange.Usage
        [FieldOffset(58)] public ushort UsageMax;   // Range.UsageMax
        [FieldOffset(68)] public ushort DataIndex;
        [FieldOffset(70)] public ushort DataIndexMax;
    }

    private const ushort BUTTON_PAGE = 0x09;

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SetupDiGetClassDevsW(ref Guid guid, IntPtr enumerator, IntPtr hwnd, uint flags);
    [DllImport("setupapi.dll")]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr devInfo, ref Guid guid, uint index, ref SP_DEVICE_INTERFACE_DATA data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr set, ref SP_DEVICE_INTERFACE_DATA data, IntPtr detail, int detailSize, out int required, IntPtr devInfo);
    [DllImport("setupapi.dll")] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle h, byte[] buffer, int toRead, out int read, IntPtr overlapped);

    internal sealed record AxisSpec(ushort Usage, int LogicalMin, int LogicalMax, string Name,
                                   byte ReportId = 0, ushort LinkCollection = 0, ushort BitSize = 0, ushort DataIndex = 0);

    internal static IEnumerable<AxisSpec> ExpandAxis(AxisSpec first, ushort last)
    {
        if (last < first.Usage || last > USAGE_MAX) throw new InvalidDataException("Ambiguous HID axis range.");
        for (int usage=first.Usage; usage<=last; usage++)
            yield return first with { Usage=(ushort)usage, Name=UsageName((ushort)usage), DataIndex=checked((ushort)(first.DataIndex+usage-first.Usage)) };
    }

    internal static long SignedValue(uint raw, AxisSpec spec)
    {
        if (spec.LogicalMin>=0) return raw;
        int bits=spec.BitSize;
        if(bits<=0 || bits>=32) return unchecked((int)raw);
        uint mask=(1u<<bits)-1;
        raw &= mask;
        return (raw & (1u<<(bits-1)))!=0 ? (long)raw-(1L<<bits) : raw;
    }


    internal sealed record DeviceInfo(string Path, string Product, ushort VendorId,
                                      ushort ProductId, int AxisCount);

    /// <summary>DescriptorDrivenParser.UsageToName.</summary>
    internal static string UsageName(ushort usage) => usage switch
    {
        0x30 => "X", 0x31 => "Y", 0x32 => "Z", 0x33 => "Rx", 0x34 => "Ry", 0x35 => "Rz",
        0x36 => "Slider", 0x37 => "Dial", 0x38 => "Wheel", 0x39 => "Hat Switch",
        _ => $"0x{usage:X2}",
    };

    /// <summary>HidAxisNormalizer.NormalizeTo2048, integer, round-to-nearest.</summary>
    internal static ushort Normalize(long value, int logicalMin, int logicalMax)
    {
        if (logicalMax <= logicalMin) return 0;
        long clamped = Math.Max(logicalMin, Math.Min(logicalMax, value));
        long span = (long)logicalMax - logicalMin;
        return (ushort)(((clamped - logicalMin) * NORMALIZED_MAX + span / 2) / span);
    }

    /// <summary>Every present HID device that exposes at least one Generic Desktop axis.</summary>
    internal static List<DeviceInfo> Enumerate()
    {
        var found = new List<DeviceInfo>();
        HidD_GetHidGuid(out var guid);
        var set = SetupDiGetClassDevsW(ref guid, IntPtr.Zero, IntPtr.Zero,
                                       DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == IntPtr.Zero || set == new IntPtr(-1)) return found;
        try
        {
            for (uint i = 0; ; i++)
            {
                var iface = new SP_DEVICE_INTERFACE_DATA { cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref guid, i, ref iface)) break;
                SetupDiGetDeviceInterfaceDetailW(set, ref iface, IntPtr.Zero, 0, out var need, IntPtr.Zero);
                if (need <= 0) continue;
                var buf = Marshal.AllocHGlobal(need);
                try
                {
                    // SP_DEVICE_INTERFACE_DETAIL_DATA_W: cbSize is 8 on x64 (4-byte
                    // size + 2-byte wchar aligned to 8), then the path follows at +4.
                    Marshal.WriteInt32(buf, 8);
                    if (!SetupDiGetDeviceInterfaceDetailW(set, ref iface, buf, need, out _, IntPtr.Zero))
                        continue;
                    var path = Marshal.PtrToStringUni(buf + 4);
                    if (string.IsNullOrEmpty(path)) continue;
                    var info = Describe(path);
                    if (info is not null && info.AxisCount > 0) found.Add(info);
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return found;
    }

    private static DeviceInfo? Describe(string path)
    {
        // Shared read/write: a stick is very often already open by another process,
        // and refusing to share would make every device look absent.
        using var h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;
        if (!HidD_GetPreparsedData(h, out var pre)) return null;
        try
        {
            var axes = ReadAxisSpecs(pre);
            var attrs = new HIDD_ATTRIBUTES { Size = Marshal.SizeOf<HIDD_ATTRIBUTES>() };
            HidD_GetAttributes(h, ref attrs);
            var name = new byte[254];
            var product = HidD_GetProductString(h, name, name.Length)
                ? System.Text.Encoding.Unicode.GetString(name).TrimEnd('\0')
                : $"HID {attrs.VendorID:X4}:{attrs.ProductID:X4}";
            return new DeviceInfo(path, product, attrs.VendorID, attrs.ProductID, axes.Count(a=>a.Usage!=0x39));
        }
        finally { HidD_FreePreparsedData(pre); }
    }

    internal static bool IsControllerCollection(ushort page,ushort usage) => page==1 && (usage==4 || usage==5);

    internal static bool ReportMatches(IReadOnlyList<AxisSpec> axes,byte[] report) =>
        report.Length>0 && axes.All(a=>a.ReportId==report[0]);

    private static List<AxisSpec> ReadAxisSpecs(IntPtr preparsed)
    {
        var axes = new List<AxisSpec>();
        if (HidP_GetCaps(preparsed, out var caps) != HIDP_STATUS_SUCCESS || !IsControllerCollection(caps.UsagePage,caps.Usage)) return axes;
        ushort count = caps.NumberInputValueCaps;
        if (count == 0) return axes;
        var valueCaps = new HIDP_VALUE_CAPS[count];
        if (HidP_GetValueCaps(0 /* HidP_Input */, valueCaps, ref count, preparsed) != HIDP_STATUS_SUCCESS)
            return axes;
        for (int i = 0; i < count; i++)
        {
            var vc = valueCaps[i];
            // Expand bounded usage ranges without changing capability enumeration order.
            if (vc.UsagePage != GENERIC_DESKTOP_PAGE) continue;
            if (vc.Usage < USAGE_MIN || vc.Usage > USAGE_MAX) continue;
            try {
                if(vc.ReportCount!=1 || (vc.IsRange!=0 && vc.DataIndexMax-vc.DataIndex!=vc.UsageMax-vc.Usage)) return new();
                axes.AddRange(ExpandAxis(new AxisSpec(vc.Usage, vc.LogicalMin, vc.LogicalMax, UsageName(vc.Usage),
                              vc.ReportID, vc.LinkCollection, vc.BitSize, vc.DataIndex), vc.IsRange!=0 ? vc.UsageMax : vc.Usage));
            } catch(InvalidDataException) { return new(); }
        }
        if(axes.Select(a=>(a.ReportId,a.DataIndex)).Distinct().Count()!=axes.Count) return new();
        return axes;
    }

    // HIDP_DATA: USHORT index/reserved, ULONG raw union, exactly 8 bytes.
    [StructLayout(LayoutKind.Explicit, Size=8)]
    internal struct HidData {
        [FieldOffset(0)] public ushort DataIndex;
        [FieldOffset(4)] public uint RawValue;
    }
    [DllImport("hid.dll")] private static extern int HidP_MaxDataListLength(int reportType, IntPtr preparsed);
    [DllImport("hid.dll")] private static extern int HidP_GetData(int reportType, [Out] HidData[] data, ref uint count, IntPtr preparsed, byte[] report, int length);

    // Shared by the actual report consumer and host-only tests. No usage lookup:
    // two Slider fields are independently decoded by their descriptor data indices.
    internal static (ushort[] values,long[] raw)? DecodeFields(IReadOnlyList<AxisSpec> axes,IEnumerable<HidData> data) {
        var fields=new Dictionary<ushort,uint>();
        foreach(var item in data) if(!fields.TryAdd(item.DataIndex,item.RawValue)) return null;
        var values=new ushort[axes.Count];var raw=new long[axes.Count];
        for(int i=0;i<axes.Count;i++) {
            var a=axes[i];
            if(a.LogicalMax<=a.LogicalMin || !fields.TryGetValue(a.DataIndex,out var value)) return null;
            raw[i]=SignedValue(value,a);values[i]=Normalize(raw[i],a.LogicalMin,a.LogicalMax);
        }
        return (values,raw);
    }

    private readonly object _readLock = new();
    private SafeFileHandle? _handle;
    private IntPtr _preparsed;
    private int _reportLength;
    private int _maxData;
    private List<AxisSpec> _axes = new();

    internal IReadOnlyList<AxisSpec> Axes => _axes;
    internal string? Product { get; private set; }
    internal object? SourceDevice { get; private set; }
    internal object? Descriptor { get; private set; }
    internal long[] LastRawAxes { get; private set; } = Array.Empty<long>();
    private readonly List<(ushort usage, byte reportId, ushort link, ushort dataIndex)> _buttonSpecs = new();

    private int _buttonCount;
    private int _maxPressed;
    private ushort _buttonUsageMin = 1;

    /// <summary>
    /// How many buttons this device declares. Zero when it has none.
    ///
    /// This exists because the channel map can drive a CRSF channel from a BUTTON,
    /// which matters far more than it looks: a transmitter-style controller has few
    /// axes and many switches, and channel 5 is commonly ARM -- a switch, not a
    /// stick. Without buttons such a device can only fill its remaining channels
    /// with fixed constants, which cannot arm anything.
    /// </summary>
    internal int ButtonCount => _buttonCount;

    /// <summary>Button states from the most recent report, index 0 = first button.</summary>
    internal bool[] LastButtons { get; private set; } = Array.Empty<bool>();

    /// <summary>
    /// Discover the button range. Buttons are usage page 0x09 and are numbered from
    /// their usage, which is 1-based on every device the HID specification
    /// describes; the lowest declared usage is kept so index 0 means "the first
    /// button this device has" rather than "usage 1" on a device that starts higher.
    /// </summary>
    private void DiscoverButtons(IntPtr preparsed, HIDP_CAPS caps)
    {
        _buttonCount = 0; _maxPressed = 0; _buttonUsageMin = 1; _buttonSpecs.Clear();
        var n = caps.NumberInputButtonCaps;
        if (n == 0) return;
        var bcaps = new HIDP_BUTTON_CAPS[n];
        var count = n;
        if (HidP_GetButtonCaps(0 /* HidP_Input */, bcaps, ref count, preparsed) != HIDP_STATUS_SUCCESS)
            return;
        ushort lo = ushort.MaxValue, hi = 0;
        for (int i = 0; i < count; i++)
        {
            var bc = bcaps[i];
            if (bc.UsagePage != BUTTON_PAGE) continue;
            var min = bc.UsageMin;
            // A non-range cap describes ONE button, whose usage sits where UsageMin
            // would be. Reading UsageMax there would be reading the next field.
            var max = bc.IsRange != 0 ? bc.UsageMax : bc.UsageMin;
            if (min == 0 || max<min || max-min>1024) continue;
            for(int usage=min;usage<=max;usage++) _buttonSpecs.Add(((ushort)usage,bc.ReportID,bc.LinkCollection,checked((ushort)(bc.DataIndex+usage-min))));
            if (min < lo) lo = min;
            if (max > hi) hi = max;
        }
        if (hi == 0 || lo == ushort.MaxValue) return;
        _buttonUsageMin = lo;
        _buttonCount = hi - lo + 1;
        var maxList = HidP_MaxUsageListLength(0, BUTTON_PAGE, preparsed);
        _maxPressed = maxList > 0 ? maxList : _buttonCount;
    }

    /// <summary>Open a device for reading. Returns null on success or a reason.</summary>
    internal string? Open(string path)
    {
        Close();
        var h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return $"Could not open the device ({Marshal.GetLastWin32Error()}).";
        if (!HidD_GetPreparsedData(h, out var pre)) { h.Dispose(); return "The device has no HID report descriptor."; }
        if (HidP_GetCaps(pre, out var caps) != HIDP_STATUS_SUCCESS)
        { HidD_FreePreparsedData(pre); h.Dispose(); return "The HID capabilities could not be read."; }
        if(!IsControllerCollection(caps.UsagePage,caps.Usage))
        { HidD_FreePreparsedData(pre); h.Dispose(); return "Select a Joystick or Game Pad collection."; }
        var fields = ReadAxisSpecs(pre);
        var axes = fields.Where(a=>a.Usage!=0x39).ToList();
        if (axes.Count == 0 || axes.Any(a=>a.LogicalMax<=a.LogicalMin))
        { HidD_FreePreparsedData(pre); h.Dispose(); return "The device exposes no unambiguous Generic Desktop axis layout or has unresolved logical bounds."; }
        _handle = h; _preparsed = pre; _axes = axes;
        _reportLength = caps.InputReportByteLength;
        _maxData=HidP_MaxDataListLength(0,pre);
        if(_maxData<=0 || _maxData>65536) { Close(); return "Invalid HID data capacity."; }
        DiscoverButtons(pre, caps);
        if (fields.Select(a=>a.ReportId).Concat(_buttonSpecs.Select(b=>b.reportId)).Distinct().Count()>1
            || _buttonSpecs.Select(b=>b.link).Distinct().Count()>1 || _buttonSpecs.Select(b=>b.usage).Distinct().Count()!=_buttonSpecs.Count
            || (_buttonSpecs.Count>0 && _buttonSpecs.Count!=_buttonCount))
        { Close(); return "This HID report layout needs separate qualification (multiple reports, multiple button collections or sparse usages)."; }
        var attrs=new HIDD_ATTRIBUTES { Size=Marshal.SizeOf<HIDD_ATTRIBUTES>() };
        HidD_GetAttributes(h,ref attrs);
        SourceDevice=new { device_id=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path))),
                           product="", vendor_id=(int)attrs.VendorID, product_id=(int)attrs.ProductID };
        Descriptor=new { hats=fields.Where(a=>a.Usage==0x39).Select(a=>new { usage_page=1,usage=(int)a.Usage,report_id=(int)a.ReportId,link_collection=(int)a.LinkCollection,
                                     data_index=(int)a.DataIndex,bit_size=(int)a.BitSize,logical_min=a.LogicalMin,logical_max=a.LogicalMax }).ToArray(), report_length=_reportLength, collection_usage_page=(int)caps.UsagePage, collection_usage=(int)caps.Usage,
            axes=axes.Select(a=>new { usage_page=1,usage=(int)a.Usage,report_id=(int)a.ReportId,link_collection=(int)a.LinkCollection,
                                     data_index=(int)a.DataIndex,bit_size=(int)a.BitSize,logical_min=a.LogicalMin,logical_max=a.LogicalMax }).ToArray(),
            buttons=_buttonSpecs.OrderBy(b=>b.usage).Select(b=>new { usage_page=9,usage=(int)b.usage,report_id=(int)b.reportId,link_collection=(int)b.link,
                                                data_index=(int)b.dataIndex,bit_size=1,logical_min=0,logical_max=1 }).ToArray() };
        var name = new byte[254];
        Product = HidD_GetProductString(h, name, name.Length)
            ? System.Text.Encoding.Unicode.GetString(name).TrimEnd('\0') : "HID device";
        Array.Clear(name); // Manufacturer has its own null-terminated string; discard prior product bytes.
        SourceDevice=new { device_id=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path))),
                           product=Product, manufacturer=HidD_GetManufacturerString(h,name,name.Length) ? System.Text.Encoding.Unicode.GetString(name).TrimEnd('\0') : "", vendor_id=(int)attrs.VendorID, product_id=(int)attrs.ProductID };
        return null;
    }

    /// <summary>Block for one report and return the axes normalized to 0..2048.</summary>
    internal ushort[]? ReadAxes()
    {
        var h = _handle;
        if (h is null || h.IsInvalid || _reportLength <= 0) return null;
        var report = new byte[_reportLength];
        if (!ReadFile(h, report, report.Length, out var read, IntPtr.Zero) || read != report.Length) return null;
        lock(_readLock) {
        if(_preparsed==IntPtr.Zero || _handle!=h) return null;
        if(!ReportMatches(_axes,report)) return null;
        var data=new HidData[_maxData];
        uint count=(uint)data.Length;
        if(HidP_GetData(0,data,ref count,_preparsed,report,read)!=HIDP_STATUS_SUCCESS || count>data.Length) return null;
        var decoded=DecodeFields(_axes,data.Take((int)count));
        if(decoded is null) return null;
        var (values,rawValues)=decoded.Value;
        LastRawAxes=rawValues;
        if(!ReadButtons(report, read)) return null;
        return values;
        }
    }

    /// <summary>
    /// Fill LastButtons from the same report the axes came from.
    ///
    /// HidP_GetUsages returns the usages that are PRESSED, not a per-button state,
    /// so the array is cleared first and then set -- a released button simply does
    /// not appear. Reading from the same report keeps axes and buttons coherent:
    /// sampling them from different reports could arm on a stale frame.
    /// </summary>
    private bool ReadButtons(byte[] report, int read)
    {
        if (_buttonCount <= 0 || _maxPressed <= 0)
        { LastButtons = Array.Empty<bool>(); return true; }
        var state = new bool[_buttonCount];
        var list = new ushort[_maxPressed];
        var len = _maxPressed;
        if (HidP_GetUsages(0, BUTTON_PAGE, _buttonSpecs[0].link, list, ref len, _preparsed, report, read)
            == HIDP_STATUS_SUCCESS)
        {
            for (int i = 0; i < len; i++)
            {
                var idx = list[i] - _buttonUsageMin;
                if (idx >= 0 && idx < state.Length) state[idx] = true;
            }
        }
        else return false;
        LastButtons = state;
        return true;
    }

    internal void Close()
    {
        lock(_readLock) {
        if (_preparsed != IntPtr.Zero) { HidD_FreePreparsedData(_preparsed); _preparsed = IntPtr.Zero; }
        _handle?.Dispose(); _handle = null;
        _axes = new(); Product = null; _reportLength = 0;
        SourceDevice=null;Descriptor=null;LastRawAxes=Array.Empty<long>();_buttonSpecs.Clear();
        _buttonCount = 0; _maxPressed = 0; LastButtons = Array.Empty<bool>();
        }
    }

    public void Dispose() => Close();
}
