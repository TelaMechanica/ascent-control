"""Provisional 0.x package inspection. Validation never installs or executes.

Digests detect corruption; they do not authenticate publishers. Runtime isolation,
user grants and publisher verification remain separate production requirements.
"""
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
from tempfile import TemporaryDirectory
import zipfile
import zlib

SDK_VERSION = '0.1.0-dev'
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_EXPANDED_BYTES = 4 * 1024 * 1024
MAX_PINNED_EXPANDED_BYTES = 5 * 1024 * 1024
MAX_FILES = 64
ALLOWED_CAPABILITIES = frozenset({'host.version.read'})


class PackageInvalid(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageInvalid('Duplicate JSON field')
        result[key] = value
    return result



def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_object)
    except PackageInvalid:
        raise
    except (ValueError, RecursionError):
        # Includes the interpreter's integer-conversion and nesting limits.
        # Preserve package rejection without exposing a raw parser traceback.
        raise PackageInvalid('Malformed package JSON') from None


def _path(value):
    if not isinstance(value, str) or not value or not value.isascii() or len(value) > 160:
        raise PackageInvalid('Invalid package path')
    parts = value.split('/')
    if any(p in ('', '.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]+', p) or p.endswith(('.', ' ')) for p in parts):
        raise PackageInvalid('Unsafe package path')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{p}{n}' for p in ('COM', 'LPT') for n in range(1, 10)}
    if any(p.split('.')[0].upper() in reserved for p in parts):
        raise PackageInvalid('Reserved package path')
    return PurePosixPath(value).as_posix()


def inspect_package(path):
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageInvalid('Archive exceeds limit')
    return _inspect_archive(path)


def inspect_package_bytes(data):
    """Inspect an immutable, already bounded snapshot; never reopen a pathname."""
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
        raise PackageInvalid('Archive exceeds limit or is not immutable bytes')
    with io.BytesIO(data) as stream:
        return _inspect_archive(stream)


def _archive_names(archive, *, max_expanded_bytes=MAX_EXPANDED_BYTES):
    entries = archive.infolist()
    if not 1 <= len(entries) <= MAX_FILES or sum(e.file_size for e in entries) > max_expanded_bytes:
        raise PackageInvalid('Expanded package exceeds limit')
    names = []
    for entry in entries:
        name = _path(entry.filename)
        mode = entry.external_attr >> 16
        if entry.is_dir() or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or entry.flag_bits & 1:
            raise PackageInvalid('Only ordinary unencrypted files are allowed')
        names.append(name)
    if len({n.casefold() for n in names}) != len(names):
        raise PackageInvalid('Duplicate or case-colliding path')
    return names


def verify_release_payload(data, *, archive_digest, file_digests, max_expanded_bytes=MAX_EXPANDED_BYTES):
    """Verify an opaque release archive selected by a trusted host inventory.

    Both digest inputs come from application-owned release metadata. This path
    never derives trust from a package manifest, opens devices, or runs payloads.
    """
    if type(max_expanded_bytes) is not int or not 0 < max_expanded_bytes <= MAX_PINNED_EXPANDED_BYTES:
        raise PackageInvalid('Invalid pinned release size limit')
    if (not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES
            or hashlib.sha256(data).hexdigest() != archive_digest):
        raise PackageInvalid('Release archive digest differs')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = _archive_names(archive, max_expanded_bytes=max_expanded_bytes)
            if set(names) != set(file_digests):
                raise PackageInvalid('Release payload inventory differs')
            payload = {name: archive.read(name) for name in names}
            if any(hashlib.sha256(blob).hexdigest() != file_digests[name]
                   for name, blob in payload.items()):
                raise PackageInvalid('Release payload digest differs')
            return payload
    except PackageInvalid:
        raise
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError,
            OverflowError, RuntimeError, NotImplementedError) as exc:
        raise PackageInvalid('Malformed release archive') from exc


@contextmanager
def stage_release_payload(path, *, archive_digest, file_digests, max_expanded_bytes=MAX_EXPANDED_BYTES):
    """Stage a flat, pinned widget payload for a trusted host installer."""
    from .widget_catalog_io import open_folder

    if not file_digests or any('/' in _path(name) for name in file_digests):
        raise PackageInvalid('Release files must have plain names')
    path = Path(path)
    with open_folder(path.parent) as folder:
        data = folder.read(path.name, folder.stat(path.name), MAX_ARCHIVE_BYTES)
    payload = verify_release_payload(data, archive_digest=archive_digest, file_digests=file_digests,
                                     max_expanded_bytes=max_expanded_bytes)
    with TemporaryDirectory(prefix='ascent-widget-release-') as directory:
        root = Path(directory)
        for name, blob in payload.items():
            (root / name).write_bytes(blob)
        yield root


def _inspect_archive(source):
    try:
        with zipfile.ZipFile(source) as archive:
            names = _archive_names(archive)
            if len(names) < 2:
                raise PackageInvalid('Expanded package exceeds limit')
            if 'widget.json' not in names:
                raise PackageInvalid('Manifest missing')
            manifest = _json(archive.read('widget.json'))
            fields = {'schema', 'id', 'version', 'sdk', 'display_name', 'capabilities', 'files', 'view'}
            if not isinstance(manifest, dict) or set(manifest) != fields:
                raise PackageInvalid('Manifest fields differ from SDK contract')
            if manifest['schema'] != 'ascent.widget.v0' or manifest['sdk'] != '0.1':
                raise PackageInvalid('Unsupported SDK/schema')
            if not isinstance(manifest['id'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{2,63}', manifest['id']):
                raise PackageInvalid('Invalid widget identity')
            if not isinstance(manifest['version'], str) or not re.fullmatch(r'0\.\d+\.\d+', manifest['version']):
                raise PackageInvalid('Expected provisional 0.x version')
            if not isinstance(manifest['display_name'], str) or not 1 <= len(manifest['display_name']) <= 80:
                raise PackageInvalid('Invalid display name')
            caps = manifest['capabilities']
            if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps) or len(set(caps)) != len(caps) or not set(caps) <= ALLOWED_CAPABILITIES:
                raise PackageInvalid('Unsupported capabilities')
            pins = manifest['files']
            if not isinstance(pins, dict) or set(pins) != set(names) - {'widget.json'}:
                raise PackageInvalid('Payload inventory differs')
            for name, digest in pins.items():
                _path(name)
                if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise PackageInvalid('Invalid digest')
                if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                    raise PackageInvalid('Payload digest differs')
            view = manifest['view']
            if not isinstance(view, str) or view not in pins or not view.endswith('.json'):
                raise PackageInvalid('Declarative view missing')
            definition = _json(archive.read(view))
            if not isinstance(definition, dict) or set(definition) != {'type', 'text'} or definition['type'] != 'text' or not isinstance(definition['text'], str) or len(definition['text']) > 200:
                raise PackageInvalid('Unsupported declarative view')
            if set(pins) != {view}:
                raise PackageInvalid('This prototype accepts only a declarative view')
            return {'id': manifest['id'], 'version': manifest['version'], 'sdk': SDK_VERSION,
                    'validated': True, 'publisher_verified': False, 'executable': False}
    except PackageInvalid:
        raise
    except (zipfile.BadZipFile, zlib.error, EOFError, KeyError, UnicodeError, ValueError,
            OSError, OverflowError, RuntimeError, NotImplementedError) as exc:
        raise PackageInvalid('Malformed package') from exc
