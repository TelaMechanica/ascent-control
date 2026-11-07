# ASCENT Control third party notices

Original ASCENT Control code is attributed to its sole contributor, TelaMechanica,
and is covered only as specified by LICENSE and PROJECT_LICENSE_SCOPE.json.
The following material retains separate terms and attribution.

| Component | Pinned version | Use and applicable terms |
| --- | --- | --- |
| CPython Windows embeddable runtime | 3.12.7 | Python and bundled dependency terms are retained in pyembed/LICENSE.txt. |
| GStreamer Windows runtime | 1.26.11 | Dynamically loaded media libraries and ten explicitly enumerated plugins. LGPL text, component inventory and replacement instructions accompany the staged runtime. |
| Microsoft WebView2 SDK | 1.0.4191.47 | SDK license accompanies the staged desktop host. Installed browser runtime is a separate Microsoft component. |
| .NET Windows desktop runtime | Supplied by the pinned .NET 8 build | Runtime license and third-party notices accompany the self-contained desktop output. |
| ASCENT native filesystem helper | mtd-utils 2.2.0 derivative | GPL-2.0. Exact helper source, adapter/build recipe and retained notices are in third_party/native-ubifs-source and in the native-tools corresponding-source archive. |
| GNU Arm Embedded binutils | 10-2020-q4-major distribution | Separately executed ARM tools retain GNU licenses and vendor notices. Corresponding source is a separately inventoried release input. |
| Unicorn | 2.1.4 | Emulator and bindings retain their upstream component licenses. Exact source and license texts must accompany redistribution. |
| Capstone | 5.0.9 | Disassembler and bindings retain upstream notices and terms. |
| pyelftools | 0.33 | Retains its upstream license and bundled construct notices. |
| Camera support data | Manifest-pinned vendor inputs | Caddx-origin camera applications, reference application and tuning/bridge assets retain their owners' rights. They are excluded from the original-project license. Image provenance and all 19 payload hashes/sizes are recorded by the support manifest. |
| Vendor configuration resources and device artwork | Source-inventoried | Vendor-derived JSON/resources and product renders retain their owners' rights; they are excluded from the original-project license. |
| RC controller artwork | Source-inventoried | The supplied pack records generated PNG assets and simplified vector traces, with original-byte provenance. Product names and marks retain their owners' rights. |

The public installer includes the requested Z8, Z40 and Hub camera support pack.
It also includes the legacy HD Pro sources and donor-bound patch assets. HD Pro
hardware capture and tuning remain unqualified; its AC build target is available
for tester image creation. These assets do not grant receiver access or include AC+ provisioning.

This file is an inventory, not a replacement for the component license texts or
an assertion of rights in vendor material. Release validation must check the
actual staged and extracted files, license texts and corresponding-source inputs.
