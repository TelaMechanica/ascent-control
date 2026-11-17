"""Bounded local SDK-package discovery. Never installs, registers or executes."""
import errno
import hashlib
from pathlib import Path
import re

from .widget_catalog_io import ChangedEntry, UnsafeEntry, open_folder, _plain
from .widget_sdk import MAX_ARCHIVE_BYTES, PackageInvalid, inspect_package_bytes

MAX_DIRECTORY_ENTRIES = 256
MAX_PACKAGES = 64
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def _result(status, entries=(), scanned=0, ignored=0):
    return {'schema': 'ascent.widget_catalog.v0', 'status': status,
            'complete': status == 'OK', 'entries': list(entries),
            'scanned_entries': scanned, 'ignored_entries': ignored,
            'read_only': True, 'registration_performed': False,
            'activation_performed': False, 'installation_checked': False}


def _safe_name(name):
    return (0 < len(name) <= 255 and not name.startswith('.') and
            not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF or c in '<>:"/\\|?*' for c in name) and
            name.split('.')[0].upper() not in {'CON', 'PRN', 'AUX', 'NUL',
                *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))})


def _row(name, status):
    return {'entry_key': hashlib.sha256(name.encode('utf-8', errors='surrogatepass')).hexdigest(),
            'source_name': name if _safe_name(name) else None, 'status': status}


def _inspect(data):
    result = inspect_package_bytes(data)
    # Discovery output is bounded even when an older provisional inspector
    # accepts unusually long version strings. No free-form view text is returned.
    if (not re.fullmatch(r'[a-z][a-z0-9-]{2,63}', result['id']) or
            not isinstance(result['version'], str) or len(result['version']) > 64 or
            not re.fullmatch(r'0\.[0-9]+\.[0-9]+', result['version']) or
            result['executable'] is not False or result['publisher_verified'] is not False):
        raise PackageInvalid('Catalog metadata outside preview contract')
    return result


def scan_folder(path):
    """Inspect top-level .zip files; return observations without installed-state claims.

    A folder/limit failure discards the partial catalog. Individual package
    failures remain visible. No arbitrary package modules or views are imported.
    """
    scanned = ignored = total = 0
    try:
        with open_folder(Path(path)) as folder:
            candidates = []
            with folder.entries() as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_DIRECTORY_ENTRIES:
                        return _result('ENTRY_LIMIT', scanned=scanned, ignored=ignored)
                    if not entry.name.lower().endswith('.zip'):
                        ignored += 1
                        continue
                    candidates.append(entry.name)
                    if len(candidates) > MAX_PACKAGES:
                        return _result('PACKAGE_LIMIT', scanned=scanned, ignored=ignored)
            candidates.sort(key=lambda value: (value.casefold(), value))
            folded = {}
            for name in candidates:
                folded.setdefault(name.casefold(), []).append(name)
            rows = []
            for name in candidates:
                row = _row(name, 'PACKAGE_REJECTED')
                rows.append(row)
                if not _safe_name(name):
                    row['status'] = 'UNSAFE_NAME'
                    continue
                if len(folded[name.casefold()]) != 1:
                    row['status'] = 'SOURCE_NAME_CONFLICT'
                    continue
                try:
                    before = folder.stat(name)
                    _plain(before)
                    if before.st_size > MAX_ARCHIVE_BYTES:
                        row['status'] = 'PACKAGE_TOO_LARGE'
                        continue
                    if total + before.st_size > MAX_TOTAL_BYTES:
                        return _result('BYTE_LIMIT', scanned=scanned, ignored=ignored)
                    # Reserve the maximum read before opening. A failed/stale
                    # snapshot may already have read bytes, so it cannot refund
                    # the budget. Successful reads refund only the unused part.
                    reservation = min(MAX_ARCHIVE_BYTES + 1, MAX_TOTAL_BYTES - total)
                    if reservation <= 0:
                        return _result('BYTE_LIMIT', scanned=scanned, ignored=ignored)
                    total += reservation
                    data = folder.read(name, before, reservation - 1)
                    total -= reservation - len(data)
                    if total > MAX_TOTAL_BYTES:
                        return _result('BYTE_LIMIT', scanned=scanned, ignored=ignored)
                    if len(data) > MAX_ARCHIVE_BYTES:
                        row['status'] = 'PACKAGE_TOO_LARGE'
                        continue
                    package = _inspect(data)
                    row.update(status='VALIDATED_PREVIEW', package=package,
                               sha256=hashlib.sha256(data).hexdigest())
                except ChangedEntry:
                    row['status'] = 'FILE_CHANGED'
                except UnsafeEntry:
                    row['status'] = 'UNSAFE_ENTRY'
                except OSError:
                    row['status'] = 'FILE_UNAVAILABLE'
                except PackageInvalid:
                    row['status'] = 'PACKAGE_REJECTED'
                except Exception:
                    # Do not turn an unexpected inspection failure into a valid
                    # entry or echo untrusted parser errors into catalog output.
                    row['status'] = 'INSPECTION_FAILED'
            versions = {}
            for row in rows:
                if row['status'] == 'VALIDATED_PREVIEW':
                    package = row['package']
                    versions.setdefault((package['id'], package['version']), []).append(row)
            for group in versions.values():
                if len(group) > 1:
                    status = 'DUPLICATE_COPY' if len({row['sha256'] for row in group}) == 1 else 'VERSION_CONFLICT'
                    for row in group:
                        row['status'] = status
            folder.check()
            return _result('OK', rows, scanned, ignored)
    except ChangedEntry:
        return _result('FOLDER_CHANGED', scanned=scanned, ignored=ignored)
    except UnsafeEntry:
        return _result('FOLDER_UNSAFE', scanned=scanned, ignored=ignored)
    except FileNotFoundError:
        return _result('FOLDER_MISSING', scanned=scanned, ignored=ignored)
    except OSError as exc:
        status = 'FOLDER_UNSAFE' if exc.errno in (errno.ELOOP, errno.ENOTDIR) else 'FOLDER_UNAVAILABLE'
        return _result(status, scanned=scanned, ignored=ignored)
