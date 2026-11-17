# Read-only local folder catalog preview

The operator-selected workflow is a local Widgets folder scanned at application
startup, with Open Widgets folder and Rescan actions. This increment supplies
bounded discovery and a command-line preview. It does not add startup/UI wiring,
registration, activation, installed-state tracking or receiver installation.

From the source root, point the tool at an existing local folder:

```sh
python tools/widget_sdk.py catalog ./Widgets
```

Only top-level `.zip` files using the existing declarative SDK 0.1 contract are
inspected. Directories are not traversed and unknown extensions are ignored.
The folder is not created if missing. This does not define a native Picker/
Netrunner installer format or admit arbitrary package code. Mapster remains deferred.

## Discovery results

A validated entry contains its package identity/version, content SHA-256 and the
inspector's `publisher_verified:false` and `executable:false`. View text is not
returned. Validation is not publisher authentication or permission to execute.
The catalog never reads credentials, acquires ServiceLease or invokes receiver
operations. It does not extract ZIPs, install software, modify configuration or
register packages just because they were discovered.

| Result | Meaning |
|---|---|
| VALIDATED_PREVIEW | Existing declarative preview passes inspection |
| PACKAGE_REJECTED | Unsupported or malformed package; parser text is not reflected |
| PACKAGE_TOO_LARGE | Archive exceeds the preview bound |
| UNSAFE_ENTRY / UNSAFE_NAME | Link, special file, hardlink, reparse point or nonportable name |
| FILE_UNAVAILABLE / FILE_CHANGED | No stable readable snapshot; retry through an explicit rescan |
| SOURCE_NAME_CONFLICT | Case-colliding filenames; no file is selected |
| DUPLICATE_COPY | Same identity/version and bytes appear more than once |
| VERSION_CONFLICT | Same identity/version has different bytes; no copy is preferred |
| INSPECTION_FAILED | Unexpected inspection error; no validated metadata published |

Distinct versions remain separate observations. There is no automatic highest-
version choice and no Update available claim without installed-state evidence.
The CLI emits structured JSON; it exits nonzero for folder/limit failures or any
row needing review. Empty readable folders are distinct from unavailable/missing
ones. Output can contain local package filenames; apply the normal privacy review
before posting it.

`complete` means the bounded folder enumeration finished, not that every package
is valid. Per-file rejections remain visible. Folder changes and global limits
discard the partial catalog. Folder paths and exception messages are not echoed.
Registration/activation remain false and installation_checked remains false.

## Bounds and file identity

At most 256 directory entries, 64 candidate packages and 16 MiB total package bytes
are considered. Failed snapshots retain their worst-case read reservation, so
file races cannot evade the total byte budget. The existing inspector also enforces 2 MiB per archive, 4 MiB
expanded content and 64 archive entries. Catalog version output is ASCII and
bounded to 64 characters; invalid names are represented by an opaque entry key.

Inspection uses immutable byte snapshots rather than reopening a filename.
Malformed ZIP seek/offset failures are normalized to PackageInvalid; explicit
SDK contract rejections retain their existing reasons.
Linux opens directory components and files through descriptor-relative no-follow
operations. Windows uses fixed system file APIs with reparse refusal, normalized
handle-path checks, native 128-bit file identity/change time and read/delete sharing
restrictions. Unsupported metadata fails closed. Local Windows NTFS and Linux
fixtures are host evidence, not qualification of arbitrary filesystems or hardware.
Any future install action must independently revalidate the selected package bytes,
current target and permissions; a discovery result is not an installation lease.

The Windows design uses Microsoft's [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[handle path](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew),
[handle metadata](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
and [FILE_BASIC_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info)
contracts. Creation timestamps are not substituted for native change times.

## Next integration boundary

A source-only `CatalogCoordinator` now supplies background scan coordination for
a fixed host-supplied folder. It retains one worker and coalesces pending requests
into a latest-generation rerun, discarding obsolete successes and failures. Status
reads return independent snapshots; rescanning immediately invalidates the prior
observation. Slow scans become SCAN_DELAYED after five seconds without claiming
that filesystem I/O was cancelled. Closing invalidates observations and prevents
new work; an already blocked daemon worker may finish later and cannot publish.
Scanner failures and worker-start failures return fixed codes, not exception text
or root paths. Serialized observations are limited to 256 KiB.

The development desktop now explicitly ships the four read-only SDK/catalog
modules. Trusted backend startup captures `config_root()/Widgets` once and starts
a background scan only when the per-launch native host session exists. The
configurable save directory cannot relocate it. Startup does not create a missing
folder; shutdown closes the coordinator without joining blocked filesystem I/O.

`GET /api/widgets/local/catalog` returns the current observation and
`POST /api/widgets/local/rescan` accepts an empty JSON object and schedules a new
generation. Both require the native host session and existing local-origin
checks. Query parameters, nonempty bodies and wrong methods are refused. Requests
cannot start an uninitialized catalog or supply a folder. The native hook adds
these two exact method/path pairs, for seven total; it exposes no secret to page
JavaScript. Historical review claims that the SDK inspector is unshipped and that
the hook has five pairs describe earlier checkpoints. Browser/frame isolation
remains unproven and package content must never enter the trusted WebView.

The app still needs an explicit fixed-folder opening action and a text-only
Widget Manager view. No package view is rendered by this integration.
Package filenames remain untrusted local data; snapshot copies are not sanitized
support attachments.
No raw caller-supplied path should become a privileged HTTP folder scan. Package
registration and native deployment need their own reviewed contracts, target and
operation guards, data preservation and explicit activation semantics. Neither
catalog discovery nor source publication enables a third-party executor.
