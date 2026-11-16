"""Synthetic publication-scrub checks. No operator identifiers in fixtures."""
import importlib.util
import io
import json
from pathlib import Path
import zipfile
import pytest

spec = importlib.util.spec_from_file_location('privacy_review', Path(__file__).resolve().parents[1]/'tools/privacy_review.py')
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)
TOKEN = 'synthetic-' + 'person-identity'


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as writer:
        for name, data in files: writer.writestr(name, data)
    return output.getvalue()


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-16-le', 'utf-16-be'])
@pytest.mark.parametrize('prefix', [b'', b'\x01'])
def test_binary_encoded_identity_detected_without_echo(encoding, prefix):
    review = privacy.Review([TOKEN])
    review.inspect('binary', prefix+TOKEN.encode(encoding)+b'\0')
    report = review.report()
    assert report['clean'] is False
    assert 'known-personal-identifier' in report['items'][0]['findings']
    assert TOKEN not in json.dumps(report)


def test_filename_identifier_detected_without_echo():
    review = privacy.Review([TOKEN]);review.inspect(TOKEN+'.txt', b'innocent')
    assert review.report()['clean'] is False
    assert TOKEN not in json.dumps(review.report())


def test_nested_compressed_identity_detected():
    review = privacy.Review([TOKEN])
    review.inspect('outer.zip', archive([('nested.zip', archive([('readme', TOKEN.encode())]))]))
    assert review.report()['clean'] is False
    assert len(review.items) == 3


def test_file_and_archive_names_have_no_plaintext_in_report():
    review = privacy.Review([TOKEN])
    review.inspect(TOKEN+'.zip', archive([(TOKEN, b'content')]))
    assert TOKEN not in json.dumps(review.report())
    assert all(len(item['item_id']) == 64 for item in review.items)


@pytest.mark.parametrize('parts,category', [
    (['/', 'home', '/', 'fixture-person', '/work'], 'personal-path'),
    (['C:', '\\', 'Users', '\\', 'fixture-person'], 'personal-path'),
    (['DESK', 'TOP-', 'TEST1234'], 'computer-label'),
    (['ab', ':', 'cd', ':', 'ef', ':', '01'], 'bbid-shaped-value'),
    (['ab', '-', 'cd', '-', 'ef', '-', '01', '-', '23', '-', '45'], 'device-address'),
    (['a1'*10], 'long-device-id'),
    (['gh', 'p_', 'x'*24], 'access-token'),
    (['-----BEGIN ', 'OPENSSH ', 'PRIVATE KEY-----'], 'private-key-marker'),
])
def test_generic_identifier_shapes_detected(parts, category):
    assert category in privacy.categories(''.join(parts).encode(), ())


def test_identity_crossing_scan_chunk_boundary_detected():
    data = b'x' * (1024*1024-7) + TOKEN.encode() + b'z'
    assert 'known-personal-identifier' in privacy.categories(data, [TOKEN])


def test_clean_export_has_exact_content_hashes(tmp_path):
    (tmp_path/'clean.txt').write_bytes(b'clean declarative example')
    result = privacy.review_tree(tmp_path)
    assert result['clean'] and len(result['items']) == 1
    assert result['items'][0]['bytes'] == 25


def test_symlink_not_followed(tmp_path):
    secret = tmp_path.parent/(tmp_path.name+'-outside')
    secret.write_text(TOKEN)
    (tmp_path/'link').symlink_to(secret)
    result = privacy.review_tree(tmp_path, tokens=[TOKEN])
    assert result['items'][0]['findings'] == ['non-ordinary-file-unreviewed']


def test_directory_symlink_not_followed(tmp_path):
    directory = tmp_path.parent/(tmp_path.name+'-outside')
    directory.mkdir();(directory/'data').write_text(TOKEN)
    (tmp_path/'link').symlink_to(directory, target_is_directory=True)
    assert privacy.review_tree(tmp_path)['clean'] is False


def test_empty_export_refuses(tmp_path):
    with pytest.raises(ValueError):privacy.review_tree(tmp_path)


def test_over_limit_files_are_flagged_not_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(privacy, 'MAX_FILE_BYTES', 4)
    (tmp_path/'large').write_bytes(b'12345')
    assert privacy.review_tree(tmp_path)['items'][0]['findings'] == ['file-limits-unreviewed']


def test_over_limit_archives_are_flagged_not_skipped(monkeypatch):
    monkeypatch.setattr(privacy, 'MAX_ARCHIVE_BYTES', 4)
    review = privacy.Review();review.inspect('example.zip', archive([('data', b'12345')]))
    assert review.items[0]['findings'] == ['archive-limits-unreviewed']


def test_encrypted_archives_are_flagged(monkeypatch):
    raw = bytearray(archive([('data', b'abc')]))
    # Set encryption bit in local and central headers; no key is attempted.
    import struct
    for signature, offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
        at = raw.index(signature)+offset
        struct.pack_into('<H', raw, at, struct.unpack_from('<H', raw, at)[0] | 1)
    review = privacy.Review();review.inspect('example.zip', raw)
    assert 'archive-entry-unreviewed' in review.items[0]['findings']


def test_cli_malformed_denylist_never_echoes_raw_data(tmp_path, capsys):
    (tmp_path/'private-list').write_text(TOKEN)
    assert privacy.main(['--root', str(tmp_path), '--denylist', str(tmp_path/'private-list')]) == 2
    assert TOKEN not in capsys.readouterr().out


def test_corrupt_compressed_archive_is_incomplete():
    import struct
    raw = bytearray(archive([('data', b'abcdef')]))
    name_len, extra_len = struct.unpack_from('<HH', raw, 26)
    start = 30 + name_len + extra_len
    raw[start] = (raw[start] & ~7) | 7
    review = privacy.Review();review.inspect('example.zip', raw)
    assert 'archive-read-unreviewed' in review.items[0]['findings']


@pytest.mark.parametrize('raw', [b'PK\x03\x04truncated', b'\x1f\x8bcompressed', b'7z\xbc\xaf\x27\x1cdata',
                                b'Rar!data', b'\0'*257+b'ustar'])
def test_unsupported_or_truncated_containers_are_not_clean(raw):
    review = privacy.Review();review.inspect('attachment', raw)
    assert review.items[0]['findings'] == ['container-format-unreviewed']


def test_archive_depth_limit_is_reported(monkeypatch):
    monkeypatch.setattr(privacy, 'MAX_ARCHIVE_DEPTH', 1)
    review = privacy.Review();review.inspect('outer', archive([('inner', archive([('data', b'content')]))]))
    assert 'archive-depth-unreviewed' in review.items[1]['findings']


def test_invalid_denylist_fails_closed():
    for tokens in ([None], ['xy'], ['x'*4097]):
        with pytest.raises(ValueError):privacy.Review(tokens)


def test_cli_missing_root_is_sanitized(tmp_path, capsys):
    assert privacy.main(['--root', str(tmp_path/'missing')]) == 2
    assert str(tmp_path) not in capsys.readouterr().out


def test_git_source_includes_untracked_and_excludes_ignored(tmp_path):
    import subprocess
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path/'.gitignore').write_text('private-local/\n')
    (tmp_path/'public.txt').write_text('safe')
    (tmp_path/'private-local').mkdir()
    (tmp_path/'private-local/data').write_text(TOKEN)
    result = privacy.review_tree(tmp_path, tokens=[TOKEN], git_source=True)
    assert result['clean'] and len(result['items']) == 2
    # Export mode scans the same ignored attachment; it cannot hide behind Git.
    assert privacy.review_tree(tmp_path, tokens=[TOKEN])['clean'] is False


def test_commit_metadata_scanned_and_not_echoed(tmp_path):
    import subprocess
    def git(*args):
        return subprocess.check_output(['git', '-c', 'user.name='+TOKEN,
            '-c', 'user.email=fixture-author@example.invalid', *args], cwd=tmp_path).decode().strip()
    git('init', '-q')
    (tmp_path/'public.txt').write_text('safe')
    git('add', 'public.txt');git('commit', '-q', '-m', 'Synthetic baseline')
    base = git('rev-parse', 'HEAD')
    git('commit', '-q', '--allow-empty', '-m', 'Synthetic follow-up')
    result = privacy.review_tree(tmp_path, tokens=[TOKEN], git_source=True, metadata_since=base)
    assert result['clean'] is False and len(result['items']) == 2
    assert result['items'][1]['findings'] == ['known-personal-identifier']
    assert TOKEN not in json.dumps(result)


def test_metadata_ref_cannot_be_an_option(tmp_path):
    import subprocess
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path/'public.txt').write_text('safe')
    with pytest.raises(subprocess.CalledProcessError):
        privacy.review_tree(tmp_path, git_source=True, metadata_since='--all')


def flagged_review():
    review = privacy.Review();review.inspect('synthetic', b'-----BEGIN '+b'PRIVATE KEY-----')
    result = review.report();item = result['items'][0]
    rules = {'schema':'ascent.privacy-dispositions.v1', 'items':[
        {key:item[key] for key in ('item_id', 'sha256', 'findings')} | {'reason':'format-validation-code'}]}
    return result, rules


def test_exact_review_retains_findings_and_raw_clean_state():
    report, rules = flagged_review()
    result = privacy.apply_review(report, rules)
    assert result['review_passed'] and not result['clean']
    assert result['items'][0]['findings'] == ['private-key-marker']


@pytest.mark.parametrize('field,value', [('sha256','0'*64), ('item_id','0'*64),
                                        ('findings',['access-token']), ('reason','ignore-everything')])
def test_changed_content_or_scope_cannot_inherit_review(field, value):
    result, rules = flagged_review();rules['items'][0][field] = value
    with pytest.raises(ValueError):privacy.apply_review(result, rules)


def test_duplicate_dispositions_refused():
    result, rules = flagged_review();rules['items'] *= 2
    with pytest.raises(ValueError):privacy.apply_review(result, rules)


def test_unlisted_finding_keeps_gate_closed():
    result, rules = flagged_review()
    other = privacy.Review([TOKEN]);other.inspect('other', TOKEN.encode())
    result['items'].extend(other.items)
    assert privacy.apply_review(result, rules)['review_passed'] is False


def test_incomplete_scan_cannot_be_waived():
    result, rules = flagged_review()
    result['items'][0]['findings'] = ['archive-read-unreviewed']
    rules['items'][0]['findings'] = ['archive-read-unreviewed']
    with pytest.raises(ValueError):privacy.apply_review(result, rules)


@pytest.mark.parametrize('finding', ['archive-unsafe-path', 'archive-duplicate-entry'])
def test_container_security_findings_cannot_be_waived(finding):
    result, rules = flagged_review()
    result['items'][0]['findings'] = [finding]
    rules['items'][0]['findings'] = [finding]
    with pytest.raises(ValueError):privacy.apply_review(result, rules)


def test_history_catches_identifier_deleted_from_current_tree(tmp_path):
    import subprocess
    def git(*args):
        return subprocess.check_output(['git', '-c', 'user.name=fixture-author',
            '-c', 'user.email=fixture-author@example.invalid', *args], cwd=tmp_path).decode().strip()
    git('init', '-q');(tmp_path/'public.txt').write_text('safe')
    git('add', 'public.txt');git('commit', '-q', '-m', 'Synthetic baseline')
    base = git('rev-parse', 'HEAD')
    (tmp_path/'temporary.txt').write_text(TOKEN)
    git('add', 'temporary.txt');git('commit', '-q', '-m', 'Synthetic intermediate')
    git('rm', '-q', 'temporary.txt');git('commit', '-q', '-m', 'Synthetic removal')
    assert privacy.review_tree(tmp_path, tokens=[TOKEN], git_source=True)['clean']
    result = privacy.review_tree(tmp_path, tokens=[TOKEN], git_source=True, history_since=base)
    assert result['clean'] is False
    assert any('known-personal-identifier' in item['findings'] for item in result['items'])
    assert TOKEN not in json.dumps(result)


def test_history_scope_requires_git_mode(tmp_path):
    (tmp_path/'public.txt').write_text('safe')
    with pytest.raises(ValueError):privacy.review_tree(tmp_path, history_since='HEAD')


def test_mixed_history_scopes_refused(tmp_path):
    (tmp_path/'public.txt').write_text('safe')
    with pytest.raises(ValueError):
        privacy.review_tree(tmp_path, metadata_since='HEAD', history_since='HEAD')


def test_known_personal_identifier_cannot_be_waived():
    review = privacy.Review([TOKEN]);review.inspect('synthetic', TOKEN.encode())
    result = review.report();item = result['items'][0]
    rules = {'schema':'ascent.privacy-dispositions.v1', 'items':[
        {key:item[key] for key in ('item_id','sha256','findings')} | {'reason':'public-product-prose'}]}
    with pytest.raises(ValueError):privacy.apply_review(result, rules)


@pytest.mark.parametrize('encoding', ['utf-8','utf-16-le','utf-16-be'])
def test_unicode_identifier_casefold_is_detected(encoding):
    token = 'synthetic-' + 'Stra' + '\u00dfe'
    assert 'known-personal-identifier' in privacy.categories(token.upper().encode(encoding), [token])
