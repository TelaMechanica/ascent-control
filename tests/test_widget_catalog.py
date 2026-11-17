"""Actual bounded ZIP discovery, file races and rejection; no widget execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

import pytest
from ascent_core import widget_catalog as C
from ascent_core import widget_catalog_io as IO
from ascent_core.widget_sdk import inspect_package, inspect_package_bytes, PackageInvalid, MAX_ARCHIVE_BYTES

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('catalog_sdk_example',ROOT/'tools/widget_sdk.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)


def package(path, *, identity='example-hello', version='0.1.0', text='Synthetic widget'):
    view=json.dumps({'type':'text','text':text}).encode()
    manifest={'schema':'ascent.widget.v0','id':identity,'version':version,'sdk':'0.1',
              'display_name':'Synthetic widget','capabilities':[],
              'files':{'view.json':hashlib.sha256(view).hexdigest()},'view':'view.json'}
    with zipfile.ZipFile(path,'w') as archive:
        archive.writestr('widget.json',json.dumps(manifest))
        archive.writestr('view.json',view)


def tree(root):
    return {p.relative_to(root).as_posix():(p.stat().st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob('*') if p.is_file()}


def test_scan_actual_example_is_deterministic_read_only_and_does_not_claim_installation(tmp_path):
    cli.build_example(tmp_path/'hello.zip');(tmp_path/'note.txt').write_text('ignored')
    before=tree(tmp_path)
    first=C.scan_folder(tmp_path);second=C.scan_folder(tmp_path)
    assert first==second and tree(tmp_path)==before
    assert first['complete'] and first['ignored_entries']==1
    assert not first['installation_checked'] and not first['registration_performed'] and not first['activation_performed']
    item=first['entries'][0]
    assert item['status']=='VALIDATED_PREVIEW'
    assert item['sha256']==hashlib.sha256((tmp_path/'hello.zip').read_bytes()).hexdigest()
    assert item['package']['executable'] is False and item['package']['publisher_verified'] is False
    assert str(tmp_path) not in json.dumps(first)


def test_empty_and_missing_folders_are_distinct_and_missing_folder_is_not_created(tmp_path):
    assert C.scan_folder(tmp_path)['status']=='OK'
    missing=tmp_path/'missing'
    assert C.scan_folder(missing)['status']=='FOLDER_MISSING'
    assert not missing.exists()


def test_discovery_is_top_level_only_and_ignores_unknown_extensions(tmp_path):
    nested=tmp_path/'nested';nested.mkdir();package(nested/'nested.zip')
    package(tmp_path/'future.ascent-widget')
    report=C.scan_folder(tmp_path)
    assert report['complete'] and report['entries']==[] and report['ignored_entries']==2


def test_corrupt_package_and_valid_package_have_independent_results_without_parser_text(tmp_path):
    package(tmp_path/'good.zip');(tmp_path/'bad.zip').write_text('synthetic-secret-not-an-archive')
    report=C.scan_folder(tmp_path)
    assert report['complete']
    assert [r['status'] for r in report['entries']]==['PACKAGE_REJECTED','VALIDATED_PREVIEW']
    assert 'synthetic-secret-not-an-archive' not in json.dumps(report)


@pytest.mark.parametrize('kind',['file-link','directory-link','hard-link','directory'])
def test_nonordinary_package_entries_are_refused_without_content_inspection(tmp_path,monkeypatch,kind):
    outside=tmp_path/'outside';outside.mkdir();package(outside/'fixture.zip')
    source=tmp_path/'catalog';source.mkdir();target=source/'unsafe.zip'
    try:
        if kind=='file-link':target.symlink_to(outside/'fixture.zip')
        elif kind=='directory-link':target.symlink_to(outside,target_is_directory=True)
        elif kind=='hard-link':os.link(outside/'fixture.zip',target)
        else:target.mkdir()
    except OSError:pytest.skip('Host cannot create the nonordinary fixture')
    monkeypatch.setattr(C,'inspect_package_bytes',lambda data:pytest.fail('must not inspect unsafe content'))
    report=C.scan_folder(source)
    assert report['complete'] and report['entries'][0]['status']=='UNSAFE_ENTRY'


def test_folder_and_parent_symlinks_are_refused(tmp_path):
    real=tmp_path/'real';real.mkdir();folder=real/'catalog';folder.mkdir()
    link=tmp_path/'linked'
    try:link.symlink_to(real,target_is_directory=True)
    except OSError:pytest.skip('Host cannot create symlink fixture')
    assert C.scan_folder(link)['status']=='FOLDER_UNSAFE'
    assert C.scan_folder(link/'catalog')['status']=='FOLDER_UNSAFE'


@pytest.mark.skipif(not hasattr(os,'mkfifo'),reason='POSIX FIFO fixture')
def test_fifo_package_does_not_block_or_get_read(tmp_path,monkeypatch):
    os.mkfifo(tmp_path/'pipe.zip')
    monkeypatch.setattr(IO,'_read_fd',lambda *a:pytest.fail('FIFO must not be read'))
    assert C.scan_folder(tmp_path)['entries'][0]['status']=='UNSAFE_ENTRY'


def test_oversized_package_is_rejected_before_read(tmp_path,monkeypatch):
    with (tmp_path/'large.zip').open('wb') as target:target.truncate(MAX_ARCHIVE_BYTES+1)
    monkeypatch.setattr(IO,'_read_fd',lambda *a:pytest.fail('oversized file must not be read'))
    assert C.scan_folder(tmp_path)['entries'][0]['status']=='PACKAGE_TOO_LARGE'


@pytest.mark.parametrize('limit',['entries','packages','bytes'])
def test_scan_limits_discard_partial_catalog(tmp_path,monkeypatch,limit):
    package(tmp_path/'one.zip');package(tmp_path/'two.zip',identity='example-other')
    if limit=='entries':monkeypatch.setattr(C,'MAX_DIRECTORY_ENTRIES',1)
    elif limit=='packages':monkeypatch.setattr(C,'MAX_PACKAGES',1)
    else:monkeypatch.setattr(C,'MAX_TOTAL_BYTES',(tmp_path/'one.zip').stat().st_size)
    report=C.scan_folder(tmp_path)
    assert not report['complete'] and report['entries']==[]
    assert report['status']=={'entries':'ENTRY_LIMIT','packages':'PACKAGE_LIMIT','bytes':'BYTE_LIMIT'}[limit]


@pytest.mark.skipif(os.name=='nt',reason='Case-distinct filenames need a case-sensitive fixture')
def test_case_colliding_source_names_are_not_read(tmp_path,monkeypatch):
    package(tmp_path/'one.zip');package(tmp_path/'ONE.ZIP')
    monkeypatch.setattr(IO,'_read_fd',lambda *a:pytest.fail('ambiguous name must not be read'))
    assert {r['status'] for r in C.scan_folder(tmp_path)['entries']}=={'SOURCE_NAME_CONFLICT'}


@pytest.mark.parametrize('name',['.hidden.zip','bad:name.zip','NUL.zip'])
def test_unsafe_names_are_not_returned_verbatim_or_read(tmp_path,monkeypatch,name):
    try:package(tmp_path/name)
    except OSError:pytest.skip('Host refuses the unsafe filename fixture')
    monkeypatch.setattr(IO,'_read_fd',lambda *a:pytest.fail('unsafe filename must not be read'))
    row=C.scan_folder(tmp_path)['entries'][0]
    assert row['source_name'] is None and row['status']=='UNSAFE_NAME'


@pytest.mark.parametrize('same_bytes',[True,False])
def test_same_identity_version_aliases_are_duplicates_or_conflicts_not_auto_updates(tmp_path,same_bytes):
    package(tmp_path/'one.zip')
    if same_bytes:shutil.copyfile(tmp_path/'one.zip',tmp_path/'two.zip')
    else:package(tmp_path/'two.zip',text='Different synthetic payload')
    report=C.scan_folder(tmp_path)
    assert {r['status'] for r in report['entries']}==({'DUPLICATE_COPY'} if same_bytes else {'VERSION_CONFLICT'})
    assert not report['activation_performed']


def test_distinct_versions_remain_available_without_latest_or_installed_inference(tmp_path):
    package(tmp_path/'one.zip');package(tmp_path/'two.zip',version='0.2.0')
    report=C.scan_folder(tmp_path)
    assert all(r['status']=='VALIDATED_PREVIEW' for r in report['entries'])
    assert all('installed' not in row and 'latest' not in row for row in report['entries'])


def test_in_memory_inspection_does_not_reopen_a_path_and_rejects_mutable_data(tmp_path):
    package(tmp_path/'example.zip');data=(tmp_path/'example.zip').read_bytes()
    (tmp_path/'example.zip').unlink()
    assert inspect_package_bytes(data)['validated']
    with pytest.raises(PackageInvalid):inspect_package_bytes(bytearray(data))


@pytest.mark.skipif(os.name=='nt',reason='Windows snapshot excludes concurrent writers/deleters')
def test_file_replacement_during_snapshot_never_publishes_old_valid_bytes(tmp_path,monkeypatch):
    path=tmp_path/'one.zip';package(path)
    read=IO._read_fd
    def replaced(fd,limit):
        data=read(fd,limit);path.unlink();package(path,identity='example-replacement');return data
    monkeypatch.setattr(IO,'_read_fd',replaced)
    report=C.scan_folder(tmp_path)
    assert not report['complete'] or report['entries'][0]['status']=='FILE_CHANGED'
    assert not any('package' in row for row in report['entries'])


def test_file_change_before_open_is_not_catalogued(tmp_path,monkeypatch):
    path=tmp_path/'one.zip';package(path)
    cls=IO._WindowsFolder if os.name=='nt' else IO._PosixFolder
    read=cls.read
    def changed(self,name,expected,limit):
        path.write_bytes(b'changed');return read(self,name,expected,limit)
    monkeypatch.setattr(cls,'read',changed)
    row=C.scan_folder(tmp_path)['entries'][0]
    assert row['status']=='FILE_CHANGED' and 'package' not in row


@pytest.mark.skipif(os.name=='nt',reason='Windows folder handle blocks deletion/rename')
def test_folder_replacement_during_scan_discards_all_rows(tmp_path,monkeypatch):
    folder=tmp_path/'catalog';folder.mkdir();package(folder/'one.zip')
    inspect=C.inspect_package_bytes
    def replaced(data):
        result=inspect(data);folder.rename(tmp_path/'old');folder.mkdir();return result
    monkeypatch.setattr(C,'inspect_package_bytes',replaced)
    report=C.scan_folder(folder)
    assert report['status']=='FOLDER_CHANGED' and report['entries']==[]


def test_inspection_failures_are_not_validated_or_reflected(tmp_path,monkeypatch):
    package(tmp_path/'one.zip')
    def fail(data):raise RuntimeError('synthetic-untrusted-parser-text')
    monkeypatch.setattr(C,'inspect_package_bytes',fail)
    report=C.scan_folder(tmp_path)
    assert report['entries'][0]['status']=='INSPECTION_FAILED'
    assert 'synthetic-untrusted-parser-text' not in json.dumps(report)


@pytest.mark.parametrize('version',['0.'+'1'*80+'.0','0.\u0661.0'])
def test_catalog_metadata_output_has_bounded_ascii_version(tmp_path,version):
    package(tmp_path/'one.zip',version=version)
    assert C.scan_folder(tmp_path)['entries'][0]['status']=='PACKAGE_REJECTED'


def test_cli_catalog_reports_without_registration_or_absolute_paths(tmp_path):
    cli.build_example(tmp_path/'hello.zip')
    result=subprocess.run([sys.executable,str(ROOT/'tools/widget_sdk.py'),'catalog',str(tmp_path)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    report=json.loads(result.stdout)
    assert not report['registration_performed'] and str(tmp_path) not in result.stdout
    (tmp_path/'broken.zip').write_bytes(b'broken')
    result=subprocess.run([sys.executable,str(ROOT/'tools/widget_sdk.py'),'catalog',str(tmp_path)],capture_output=True,text=True)
    assert result.returncode==1 and 'PACKAGE_REJECTED' in result.stdout


@pytest.mark.parametrize('reader',['path','bytes'])
def test_corrupt_central_directory_offset_is_a_package_rejection(tmp_path,reader):
    path=tmp_path/'corrupt-offset.zip';cli.build_example(path)
    data=bytearray(path.read_bytes());end=data.rfind(b'PK\x05\x06')
    offset=struct.unpack_from('<I',data,end+16)[0]
    struct.pack_into('<I',data,end+16,offset+1)
    path.write_bytes(data)
    with pytest.raises(PackageInvalid):
        inspect_package(path) if reader=='path' else inspect_package_bytes(bytes(data))
    assert C.scan_folder(tmp_path)['entries'][0]['status']=='PACKAGE_REJECTED'


@pytest.mark.skipif(os.name=='nt',reason='Windows denies the corresponding concurrent file writes')
def test_failed_snapshots_cannot_evade_total_read_budget(tmp_path,monkeypatch):
    package(tmp_path/'one.zip');package(tmp_path/'two.zip',identity='example-other')
    monkeypatch.setattr(C,'MAX_TOTAL_BYTES',MAX_ARCHIVE_BYTES+1)
    original=IO._PosixFolder.read;reads=[]
    def stale_after_read(self,name,expected,limit):
        data=original(self,name,expected,limit);reads.append(len(data))
        raise IO.ChangedEntry('Synthetic post-read identity failure')
    monkeypatch.setattr(IO._PosixFolder,'read',stale_after_read)
    report=C.scan_folder(tmp_path)
    assert report['status']=='BYTE_LIMIT' and not report['complete']
    assert report['entries']==[] and len(reads)==1
