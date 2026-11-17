"""Review exact source/export contents for personal data; never redact or upload.

Findings contain hashes and categories, never matched values or file names. Keep
local denylists private. A clean scan is evidence, not exhaustive PII recognition.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import socket
import stat
import subprocess
import zipfile
import zlib

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10000
MAX_ARCHIVE_DEPTH = 3
PATTERNS = {
    'personal-path': re.compile(r'(?:/(?:home|Users)/|/mnt/[a-z]/Users/|[a-z]:[\\/]+Users[\\/]+)[a-z0-9_.-]+', re.I),
    'computer-label': re.compile(r'\b(?:DESKTOP|LAPTOP|ANDROID)-[a-z0-9]{4,}\b', re.I),
    'device-address': re.compile(r'(?<![a-f0-9])(?:[a-f0-9]{2}[:-]){5}[a-f0-9]{2}(?![a-f0-9])', re.I),
    'bbid-shaped-value': re.compile(r'(?<![a-f0-9])(?:[a-f0-9]{2}:){3}[a-f0-9]{2}(?![a-f0-9])', re.I),
    # Bare eight-hex values are ambiguous (colors/CRC/bit masks). Match named
    # identity fields; unlabelled values still require the private denylist pass.
    'bare-bbid-field': re.compile(r"\b(?:bbid|bb_id|bb_mac_addr(?:_\d+)?)['\"]?\s*[:=]\s*['\"]?(?:0x)?[a-f0-9]{8}(?![a-f0-9])", re.I),
    'long-device-id': re.compile(r'(?<![a-f0-9])[a-f0-9]{20}(?![a-f0-9])', re.I),
    'private-key-marker': re.compile(r'-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----'),
    'access-token': re.compile(r'\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})\b', re.I),
}

PATTERNS = {name: re.compile(pattern.pattern, (pattern.flags & ~re.UNICODE) | re.ASCII)
            for name, pattern in PATTERNS.items()}


def categories(data, tokens):
    found = set()
    # Both byte alignments matter when UTF-16 strings are embedded in binaries.
    for start in range(0, max(1, len(data)), 1024 * 1024):
        chunk = data[max(0, start-32768):start+1024*1024]
        for encoding in ('utf-8', 'utf-16-le', 'utf-16-be'):
            for offset in ((0,) if encoding == 'utf-8' else (0, 1)):
                value = chunk[offset:].decode(encoding, errors='replace')
                folded = value.casefold()
                if any(token.casefold() in folded for token in tokens):
                    found.add('known-personal-identifier')
                # Generic shapes contain printable ASCII. Collapse other spans
                # before matching so binary/UTF-16 noise cannot dominate runtime.
                ascii_text = '\n'.join(re.findall(r'[ -~]{3,}', value))
                for name, pattern in PATTERNS.items():
                    if pattern.search(ascii_text): found.add(name)
    return sorted(found)


class Review:
    def __init__(self, tokens=()):
        if any(not isinstance(t, str) or not 3 <= len(t) <= 4096 for t in tokens):
            raise ValueError('Denylist must contain strings of three to 4096 characters')
        self.tokens = tuple(set(tokens))
        self.items = []

    def _record(self, label, data, reasons):
        self.items.append({'item_id': hashlib.sha256(label.encode()).hexdigest(),
                           'sha256': hashlib.sha256(data).hexdigest(),
                           'bytes': len(data), 'findings': sorted(set(reasons))})

    def inspect(self, label, data, depth=0):
        reasons = categories(data, self.tokens) + categories(label.encode(), self.tokens)
        self._record(label, data, reasons)
        # Inspect compressed contents too; no extraction or package execution.
        if not zipfile.is_zipfile(io.BytesIO(data)):
            signatures = (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08',
                          b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!')
            if data.startswith(signatures) or data[257:262] == b'ustar':
                self.items[-1]['findings'].append('container-format-unreviewed')
            return
        if depth >= MAX_ARCHIVE_DEPTH:
            self.items[-1]['findings'].append('archive-depth-unreviewed')
            return
        parent = self.items[-1]
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if (len(entries) > MAX_ARCHIVE_ENTRIES or
                        sum(e.file_size for e in entries) > MAX_ARCHIVE_BYTES):
                    parent['findings'].append('archive-limits-unreviewed')
                    return
                names = set()
                for index, entry in enumerate(entries):
                    mode = entry.external_attr >> 16
                    if entry.flag_bits & 1 or stat.S_ISLNK(mode):
                        parent['findings'].append('archive-entry-unreviewed')
                        continue
                    if entry.filename.casefold() in names:
                        parent['findings'].append('archive-duplicate-entry')
                    names.add(entry.filename.casefold())
                    name = entry.filename.replace('\\', '/')
                    if name.startswith('/') or '..' in name.split('/') or ':' in name:
                        parent['findings'].append('archive-unsafe-path')
                    if entry.is_dir():
                        self._record(label+'!'+str(index), b'', categories(name.encode(), self.tokens))
                        continue
                    self.inspect(label+'!'+str(index)+'!'+name, archive.read(entry), depth+1)
        except (OSError, ValueError, RuntimeError, EOFError, NotImplementedError, zipfile.BadZipFile, zlib.error):
            parent['findings'].append('archive-read-unreviewed')

    def file(self, root, name):
        path = root/name
        # Do not follow any symlink component outside the selected export.
        current = root
        for part in Path(name).parts:
            current = current/part
            if current.is_symlink():
                self._record(name, b'', ['non-ordinary-file-unreviewed'])
                return
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            self._record(name, b'', ['non-ordinary-file-unreviewed'])
        elif info.st_size > MAX_FILE_BYTES:
            self._record(name, b'', ['file-limits-unreviewed'])
        else:
            with path.open('rb') as stream: data = stream.read(MAX_FILE_BYTES+1)
            if len(data) > MAX_FILE_BYTES:
                self._record(name, b'', ['file-limits-unreviewed'])
            else:
                self.inspect(name, data)

    def report(self):
        return {'schema': 'ascent.privacy-review.v1', 'items': self.items,
                'known_tokens': len(self.tokens),
                'finding_items': sum(bool(item['findings']) for item in self.items),
                'clean': all(not item['findings'] for item in self.items),
                'limits': 'Pattern/known-token screening; manual privacy review remains required. No files changed or uploaded.'}


def review_tree(root, *, tokens=(), git_source=False, metadata_since=None, history_since=None):
    root = Path(root).resolve()
    if not root.is_dir(): raise ValueError('Review root must be a directory')
    review = Review(tokens)
    if git_source:
        raw = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root, stderr=subprocess.DEVNULL)
        names = sorted(set(n.decode('utf-8') for n in raw.split(b'\0') if n))
    else:
        names = sorted(str(p.relative_to(root)) for p in root.rglob('*')
                       if '.git' not in p.relative_to(root).parts and (p.is_file() or p.is_symlink()))
    for name in names:
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Invalid inventory path')
        review.file(root, name)
    if not names: raise ValueError('Empty review inventory')
    if metadata_since is not None and history_since is not None:
        raise ValueError('Choose one history scope')
    revision = history_since if history_since is not None else metadata_since
    if revision is not None:
        if not git_source: raise ValueError('Metadata review requires Git source mode')
        base = subprocess.check_output(['git', 'rev-parse', '--verify', '--end-of-options',
                                        revision+'^{commit}'], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        commits = subprocess.check_output(['git', 'rev-list', base+'..HEAD'], cwd=root, stderr=subprocess.DEVNULL).decode().splitlines()
        for commit in commits:
            data = subprocess.check_output(['git', 'show', '-s', '--format=%B%n%an%n%ae%n%cn%n%ce', commit], cwd=root, stderr=subprocess.DEVNULL)
            review.inspect('commit-metadata:'+commit, data)
        if history_since is not None:
            # Review unique new historical blobs too, including deleted files.
            objects = subprocess.check_output(['git', 'rev-list', '--objects', base+'..HEAD'],
                                              cwd=root, stderr=subprocess.DEVNULL).decode().splitlines()
            labels = dict(line.split(' ', 1) if ' ' in line else (line, '') for line in objects)
            if labels:
                info = subprocess.check_output(['git', 'cat-file', '--batch-check'],
                    input=('\n'.join(labels)+'\n').encode(), cwd=root, stderr=subprocess.DEVNULL)
                for line in info.decode().splitlines():
                    oid, kind, size = line.split()
                    if kind != 'blob': continue
                    label = 'history-blob:'+oid+':'+labels[oid]
                    if int(size) > MAX_FILE_BYTES:
                        review._record(label, b'', ['file-limits-unreviewed'])
                        continue
                    data = subprocess.check_output(['git', 'cat-file', 'blob', oid],
                                                   cwd=root, stderr=subprocess.DEVNULL)
                    review.inspect(label, data)
    return review.report()



def apply_review(report, document):
    """Exact-content dispositions retain findings; stale/broad rules cannot pass."""
    if (not isinstance(document, dict) or set(document) != {'schema', 'items'} or
            document['schema'] != 'ascent.privacy-dispositions.v1' or
            not isinstance(document['items'], list)):
        raise ValueError('Invalid review dispositions')
    reasons = {'synthetic-test-fixture', 'format-validation-code', 'public-product-prose',
               'binary-coincidence', 'pinned-vendor-dependency'}
    indexed = {item['item_id']: item for item in report['items']}
    seen = set()
    for rule in document['items']:
        if (not isinstance(rule, dict) or set(rule) != {'item_id', 'sha256', 'findings', 'reason'} or
                not isinstance(rule['item_id'], str) or rule['item_id'] in seen or
                not isinstance(rule['reason'], str) or rule['reason'] not in reasons or
                not isinstance(rule['findings'], list) or not rule['findings'] or
                any(not isinstance(value, str) for value in rule['findings'])):
            raise ValueError('Invalid review disposition')
        seen.add(rule['item_id'])
        item = indexed.get(rule['item_id'])
        if (item is None or item['sha256'] != rule['sha256'] or
                sorted(item['findings']) != sorted(rule['findings'])):
            raise ValueError('Stale review disposition')
        # Unreadable/limited/unsupported content is never a reviewed false positive.
        if any(value not in PATTERNS for value in item['findings']):
            raise ValueError('Incomplete scan cannot be accepted')
        item['review_reason'] = rule['reason']
    report['reviewed_finding_items'] = len(seen)
    report['review_passed'] = all(not item['findings'] or 'review_reason' in item for item in report['items'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--git-source', action='store_true', help='Only Git tracked/unignored source; use export mode for attachments')
    parser.add_argument('--reviewed-findings', type=Path, help='Exact-hash dispositions; findings remain visible')
    parser.add_argument('--history-since', help='Review metadata and all new historical blobs, including deleted files, since this Git revision')
    parser.add_argument('--metadata-since', help='Review new commit messages and author/committer identities since this Git revision')
    parser.add_argument('--denylist', type=Path, help='Private JSON array; values are never echoed')
    args = parser.parse_args(argv)
    try:
        tokens = json.loads(args.denylist.read_bytes()) if args.denylist else []
        if not isinstance(tokens, list): raise ValueError('Invalid denylist')
        local = [Path.home().name, socket.gethostname()]
        tokens += [t for t in local if len(t) >= 3 and t.casefold() not in {'root', 'runner', 'runneradmin', 'user', 'builder', 'ci'}]
        result = review_tree(args.root, tokens=tokens, git_source=args.git_source, metadata_since=args.metadata_since, history_since=args.history_since)
        if args.reviewed_findings:
            result = apply_review(result, json.loads(args.reviewed_findings.read_bytes()))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'clean': False, 'error': 'PRIVACY_REVIEW_INCOMPLETE'}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('review_passed', result['clean']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
