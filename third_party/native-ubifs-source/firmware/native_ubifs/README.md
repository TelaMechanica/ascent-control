# Native UBIFS inventory helper

This separate GPLv2 program adapts mtd-utils 2.2.0 to build UBIFS filesystems from an explicit inode inventory and ordinary content blobs. It does not need WSL, MSYS2 or Cygwin at runtime. It contains no camera firmware images or vendor camera application code. The helper's license is separate from the surrounding application's license.

`UPSTREAM.json` pins the upstream URL, tag, commit and release-archive hash. Original source and notices remain under `upstream/`. `LICENSE.GPL-2.0.txt` applies to this adapter; retain the upstream and supporting-library notices. A distribution of the helper must carry its applicable license and corresponding source obligations. Do not place this helper under a restricted application license.

## Command interface

```text
ascent-mkfs.ubifs.exe --ascent-capabilities
ascent-mkfs.ubifs.exe --version
ascent-mkfs.ubifs.exe --ascent-inventory inventory.json -r payload -o output.ubifs \
  -m 2048 -e 126976 -c 128 -x zlib -k r5 -f 8 -l 2 -p 1 -j 1048576
```

The geometry above is only an example. The caller must derive all geometry from the exact donor and validate the resulting image. Supported geometry arguments are `-r`, `-o`, `-m`, `-e`, `-c`, `-x`, `-k`, `-f`, `-l`, `-p`, `-j`, plus optional `-F`. Values must be explicit and switches must not repeat. Only zlib and r5 are admitted by this adapter. The output must be outside the payload directory, retaining the upstream containment check.

The capability response has schema `ascent.ubifs.helper.v1`, inventory schema `ascent.ubifs.inventory.v1`, `metadata: true`, and `host: windows` or `linux`. A capability response alone does not qualify a binary; applications must bind the helper to their validated source and executable hashes.

The inventory is UTF-8 JSON:

```json
{
  "schema": "ascent.ubifs.inventory.v1",
  "entries": [
    {
      "path": "/",
      "type": "directory",
      "mode": 16877,
      "uid": 0,
      "gid": 0,
      "nlink": 2,
      "flags": 16,
      "size": 160,
      "atime": [1700000000, 0],
      "mtime": [1700000000, 0]
    }
  ]
}
```

Each row provides `path`, `type`, full numeric POSIX `mode`, `uid`, `gid`, `nlink`, UBIFS `flags`, `size`, and `[seconds, nanoseconds]` values for `atime` and `mtime`. A `file` additionally supplies `content_file`, a flat basename of eight decimal digits plus `.bin`. A `symlink` supplies `target` and its UTF-8 byte length as `size`. Symlinks are encoded directly into UBIFS, not created on the host. Directory names are taken from logical device paths, not blob names.

Limits are deliberate: at most 4096 entries and 16 MiB of JSON; a declared file size must not exceed 256 MiB; only directories, single-link regular files and symlinks are accepted. Paths must be absolute, unambiguous POSIX paths with existing directory parents and no duplicate path. Owners and groups preserve their full 32-bit unsigned values. Atime and mtime preserve nonnegative 64-bit seconds and nanoseconds. Ctime is initialized to mtime because the existing semantic contract explicitly excludes ctime. Extended attributes, encryption, special files and hardlinks require a separately qualified implementation; they are not normalized away. Only UBIFS flags 0–31 are supported.

Directories must already have exact logical size `160 + sum(ALIGN(57 + UTF8_child_name_bytes, 8))` and link count `2 + direct_subdirectory_count`. An overlay caller must recompute these fields after adding entries; a no-op caller must preserve the donor values. The helper rejects inconsistencies instead of allowing the host filesystem to fill them in.

The Windows adapter converts UTF-8 arguments and file paths to wide Windows APIs. The current resolved-path compatibility check rejects paths whose UTF-8 expansion exceeds its upstream `PATH_MAX` buffer, rather than risking overflow. Short Unicode paths and Unicode device filenames have been tested; arbitrary long Windows paths are not qualified.

## Build from source

Linux with GCC, zlib and libuuid development headers:

```sh
python3 firmware/native_ubifs/build.py /path/to/fresh/output
```

Windows with Python, an existing MSYS2 UCRT64 GCC installation and its zlib static library:

```powershell
.\firmware\native_ubifs\Build-Windows.ps1 -BuildRoot C:\Build\ascent-ubifs \
  -Python C:\Python312\python.exe
```

Use a fresh isolated build directory and `-NoArtifactCopy` when building outside the application checkout. The build script does not install or update toolchains. Native Python prepares the adapted source; GCC builds a console PE executable with static zlib, relative source arguments, neutral file/macro prefix maps, stripped debug information and a zero PE timestamp. Assertions remain enabled. Runtime imports are Windows system libraries and Universal CRT API sets, without an MSYS/Cygwin runtime. `build.py --prepare-only` is also available when generating a source tree separately.

The source generator copies upstream unchanged into the build directory, disables UBI device-output handling, replaces filesystem traversal with inventory traversal and overrides inode metadata inside the upstream inode writer. Windows source preparation uses explicit 64-bit stat types and compatibility headers. Index, LPT, node layout, journal, checksums and compression stay in upstream mtd-utils. All modified source and generator scripts are part of the corresponding-source package.

## Validation

`test_helper.py` exercises a valid fixture plus malformed schemas, duplicate fields/paths, missing metadata, invalid inode types/modes, hardlinks, escaping blob paths, absent parents, timestamp bounds, unsupported flags and inconsistent directory metadata. It accepts helper, synthetic fixture directory and a fresh results directory as arguments.

The separate synthetic fixture also verifies Unicode host/device names, nonzero nanoseconds, post-2038 timestamps, UID/GID values beyond 16 bits, setuid/setgid bits, explicit flags, binary content and a symlink without host symlink creation. Independent UBIFS inventory is the comparison oracle. Real donor no-op rebuilding and the surrounding application's complete per-target gates remain required before a generated firmware image is accepted.
