"""Opt-in Windows catalog parity using disposable local-disk fixtures only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile


def run(settings):
    if os.name != 'nt':
        raise RuntimeError('Windows fixture only')
    sys.path.insert(0, settings['source'])
    from ascent_core import widget_catalog as C
    from ascent_core import widget_catalog_io as IO
    from ascent_core.widget_catalog_host import open_catalog_folder
    from ascent_core.widget_sdk import MAX_ARCHIVE_BYTES
    import _winapi
    parent=Path(settings['fixture_parent'])
    root=Path(tempfile.mkdtemp(prefix='catalog-owned-',dir=parent))
    folder=root/'Widgets';folder.mkdir()
    checks={}
    def verify(name,condition):
        checks[name]=bool(condition)
        if not condition:raise AssertionError(name)
    def package(path,text='Synthetic view'):
        view=json.dumps({'type':'text','text':text}).encode()
        doc={'schema':'ascent.widget.v0','id':'example-hello','version':'0.1.0','sdk':'0.1',
             'display_name':'Synthetic widget','capabilities':[],
             'files':{'view.json':hashlib.sha256(view).hexdigest()},'view':'view.json'}
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('widget.json',json.dumps(doc));archive.writestr('view.json',view)
    def status(name):
        return next(row['status'] for row in C.scan_folder(folder)['entries'] if row['source_name']==name)
    try:
        verify('empty',C.scan_folder(folder)['entries']==[])
        verify('missing',C.scan_folder(root/'missing')['status']=='FOLDER_MISSING' and not (root/'missing').exists())
        file=folder/'hello.zip';package(file);before=file.read_bytes()
        report=C.scan_folder(folder)
        verify('valid_file',report['status']=='OK' and report['entries'][0]['status']=='VALIDATED_PREVIEW')
        verify('read_only',file.read_bytes()==before and not report['registration_performed'] and not report['activation_performed'])
        verify('no_path_echo',str(root) not in json.dumps(report))
        (folder/'bad.zip').write_bytes(b'not an archive')
        verify('malformed',status('bad.zip')=='PACKAGE_REJECTED')
        shutil.copyfile(file,folder/'copy.zip')
        verify('duplicate',status('hello.zip')=='DUPLICATE_COPY' and status('copy.zip')=='DUPLICATE_COPY')
        package(folder/'copy.zip','Different synthetic view')
        verify('version_conflict',status('hello.zip')=='VERSION_CONFLICT' and status('copy.zip')=='VERSION_CONFLICT')
        (folder/'copy.zip').unlink()
        with (folder/'large.zip').open('wb') as target:target.truncate(MAX_ARCHIVE_BYTES+1)
        verify('oversize',status('large.zip')=='PACKAGE_TOO_LARGE')
        (folder/'large.zip').unlink()
        with IO.open_folder(folder) as held:
            try:folder.rename(root/'renamed')
            except OSError:blocked=True
            else:blocked=False
            verify('folder_delete_sharing',blocked)
            expected=held.stat('hello.zip');read=IO._read_fd
            attempts=[]
            def writer_attempt(fd,limit):
                try:
                    with file.open('wb') as stream:stream.write(b'not allowed')
                except OSError:attempts.append('blocked')
                else:attempts.append('unexpected')
                return read(fd,limit)
            IO._read_fd=writer_attempt
            try:data=held.read('hello.zip',expected,MAX_ARCHIVE_BYTES)
            finally:IO._read_fd=read
            verify('file_write_sharing',attempts==['blocked'] and data==before)
        with file.open('rb+'):
            verify('existing_writer',status('hello.zip')=='FILE_UNAVAILABLE')
        verify('file_after_writer',status('hello.zip')=='VALIDATED_PREVIEW')
        outside=root/'outside';outside.mkdir();package(outside/'outside.zip')
        os.link(outside/'outside.zip',folder/'hardlink.zip')
        verify('hardlink',status('hardlink.zip')=='UNSAFE_ENTRY')
        _winapi.CreateJunction(str(outside),str(folder/'junction.zip'))
        verify('junction_entry',status('junction.zip')=='UNSAFE_ENTRY')
        _winapi.CreateJunction(str(folder),str(root/'linked-root'))
        verify('junction_root',C.scan_folder(root/'linked-root')['status']=='FOLDER_UNSAFE')
        child=outside/'child';child.mkdir()
        _winapi.CreateJunction(str(outside),str(root/'linked-parent'))
        verify('junction_parent',C.scan_folder(root/'linked-parent'/'child')['status']=='FOLDER_UNSAFE')
        old=C.MAX_PACKAGES;C.MAX_PACKAGES=1
        try:report=C.scan_folder(folder)
        finally:C.MAX_PACKAGES=old
        verify('bounded_scan',report['status']=='PACKAGE_LIMIT' and report['entries']==[])
        opening=root/'opening';opening.mkdir();opened=[];destination=opening/'Widgets'
        response=open_catalog_folder(destination,opener=opened.append)
        verify('folder_open_fixed',response=={'ok':True,'open_requested':True} and opened==[destination] and destination.is_dir())
        verify('folder_open_request_only',str(root) not in json.dumps(response) and list(destination.iterdir())==[])
        blocked=root/'blocked';blocked.mkdir();(blocked/'Widgets').write_text('retain fixture')
        response=open_catalog_folder(blocked/'Widgets',opener=opened.append)
        verify('folder_open_file_refusal',not response['ok'] and (blocked/'Widgets').read_text()=='retain fixture' and opened==[destination])
        _winapi.CreateJunction(str(outside),str(opening/'junction'))
        response=open_catalog_folder(opening/'junction'/'Widgets',opener=opened.append)
        verify('folder_open_junction_refusal',not response['ok'] and not (outside/'Widgets').exists() and opened==[destination])
    except Exception as error:
        return {'platform':'Windows','passed':False,'checks':checks,'failed_check':str(error) if isinstance(error,AssertionError) else type(error).__name__,'fixture_retained':True}
    shutil.rmtree(root)
    return {'platform':'Windows','passed':True,'checks':checks,'fixture_removed':True,'receiver_accessed':False}


if __name__=='__main__':
    result=run(json.loads(Path(sys.argv[1]).read_text()))
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result['passed'] else 1)
