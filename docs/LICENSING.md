# Public AC licensing

Original public ASCENT Control software is GPL-3.0-only. Copyright remains with
TelaMechanica. Commercial use and redistribution are permitted under the GPL;
the previous personal/private-use restrictions do not apply to this new grant.
Existing third-party copyrights and applicable notices must remain intact.

When conveying covered binaries, provide their corresponding source under GPLv3
using a compliant method. The matching tagged source, build scripts, configuration
and required source inputs must remain available; a link to an unrelated newer
branch is not a substitute. Private modifications need not be published merely
because they are used privately.

## Firmware combination permission

The image builders insert original patch/adapter code into vendor firmware.
FIRMWARE-LINKING-PERMISSION.txt provides a narrow GPL section 7 permission for that
combination. Original AC code and changes to it remain under GPLv3, including
applicable source obligations. This permission does not authorize redistribution
of the vendor firmware or grant its copyright, patent or trademark rights.
It is not an exception for arbitrary proprietary applications.

## Component boundaries

| Component | Treatment |
|---|---|
| Original public desktop/backend/UI/build code | GPL-3.0-only |
| Original code inserted into vendor firmware | GPL-3.0-only with the stated additional permission |
| Native mtd-utils filesystem helper / GNU ARM tools | Separate executables under retained upstream GNU licenses; no relicensing to GPLv3 |
| GStreamer | Retained LGPL terms, component notices and replacement instructions |
| Python, .NET and WebView2 | Their retained runtime/SDK terms |
| Vendor camera applications, tuning data, configuration resources and artwork | Vendor/third-party rights retained; not covered by the original-project grant |
| AC+ | Separate private project; no release or licensing grant made here |

The filesystem helper and GNU ARM tools are launched as independent processes;
the desktop does not link their GPL-2.0-only code into its own executable.
The firmware permission is deliberately limited to original material that
TelaMechanica can license. The scope inventory does not assert ownership of
third-party portions inside a listed file.
