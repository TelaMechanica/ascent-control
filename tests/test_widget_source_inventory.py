"""An explicit native-widget inventory cannot weaken the desktop default gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/'tools/check_public_runtime.py'
spec=importlib.util.spec_from_file_location('runtime_inventory_under_test',TOOL)
checker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def write(root,name,data):
    path=root/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(data)


def manifest(root, *, widget='picker', roles=None, imports=None):
    roles=roles or {}
    files={}
    for path in root.rglob('*'):
        if path.is_file() and path.name!='widget-source.json':
            name=path.relative_to(root).as_posix();data=path.read_bytes()
            files[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'role':roles.get(name,'runtime')}
    doc={'schema':'ascent.widget.source_inventory.v1','widget':widget,'stage':'native-subset','files':files,
         'include_roots':['include'],'system_headers':['stdint.h'],'python_imports':imports or []}
    write(root,'release/widget-source.json',json.dumps(doc))
    return doc


@pytest.fixture
def export(tmp_path):
    root=tmp_path/'candidate';root.mkdir()
    write(root,'include/policy.h','#include <stdint.h>\nint sample(uint32_t value);\n')
    write(root,'src/policy.c','#include "policy.h"\nint sample(uint32_t value) { return value != 0; }\n')
    manifest(root)
    return root


def check(root):return checker.check_widget_inventory(root,'release/widget-source.json')


def save(root,doc):write(root,'release/widget-source.json',json.dumps(doc))


@pytest.mark.parametrize('widget',['picker','netrunner'])
def test_explicit_inventory_passes_without_desktop_inputs_and_is_not_release_approval(export,widget):
    manifest(export,widget=widget)
    result=check(export)
    assert result['widget']==widget and result['files']==2
    assert result['release_approved'] is False
    run=subprocess.run([sys.executable,str(TOOL),'--root',str(export),'--widget-inventory','release/widget-source.json'],capture_output=True,text=True)
    assert run.returncode==0 and json.loads(run.stdout)==result


def test_default_does_not_autodetect_widget_manifest(export):
    run=subprocess.run([sys.executable,str(TOOL),'--root',str(export)],capture_output=True,text=True)
    assert run.returncode!=0


def test_real_desktop_still_passes_unchanged_default():
    run=subprocess.run([sys.executable,str(TOOL)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    assert 'Reviewed runtime inventory' in run.stdout


@pytest.mark.parametrize('change',['modified','missing','extra','size','digest','empty','runtime-empty'])
def test_inventory_refuses_drift_and_invalid_records(export,change):
    path=export/'release/widget-source.json';doc=json.loads(path.read_text())
    if change=='modified':write(export,'src/policy.c','int changed;\n')
    elif change=='missing':(export/'src/policy.c').unlink()
    elif change=='extra':write(export,'unexpected.txt','not approved\n')
    elif change=='size':doc['files']['src/policy.c']['bytes']=True;save(export,doc)
    elif change=='digest':doc['files']['src/policy.c']['sha256']='0'*64;save(export,doc)
    elif change=='empty':doc['files']={};save(export,doc)
    else:
        write(export,'note.txt','review text\n')
        (export/'src/policy.c').unlink();(export/'include/policy.h').unlink()
        manifest(export,roles={'note.txt':'document'})
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('bad',['../escape.c','/absolute.c','src/../policy.c','src//policy.c','src\\policy.c','src/NUL.h','src/value.h.'])
def test_inventory_paths_are_canonical_and_portable(export,bad):
    doc=json.loads((export/'release/widget-source.json').read_text())
    doc['files'][bad]=doc['files'].pop('src/policy.c');save(export,doc)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('kind',['file','directory','manifest-parent'])
def test_symlinks_cannot_escape_or_enter_the_inventory(export,tmp_path,kind):
    target=tmp_path/'outside';target.mkdir();(target/'outside.h').write_text('int external;\n')
    try:
        if kind=='file':(export/'extra.h').symlink_to(target/'outside.h')
        elif kind=='directory':(export/'linked').symlink_to(target,target_is_directory=True)
        else:
            data=(export/'release/widget-source.json').read_bytes();(target/'widget-source.json').write_bytes(data)
            (export/'release/widget-source.json').unlink();(export/'release').rmdir()
            (export/'release').symlink_to(target,target_is_directory=True)
    except OSError:
        pytest.skip('Host cannot create the adversarial symlink fixture')
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('include',['"missing.h"','"../../../outside.h"','"/absolute.h"','POLICY_HEADER','<undeclared.h>'])
def test_repinning_hashes_does_not_authorize_undeclared_or_computed_includes(export,include):
    write(export,'src/policy.c','#include '+include+'\nint sample;\n');manifest(export)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


def test_ambiguous_local_headers_are_refused(export):
    write(export,'src/policy.h','int other;\n');manifest(export)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


def test_runtime_cannot_depend_on_test_header(export):
    manifest(export,roles={'include/policy.h':'test'})
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('body',['import socket\n','__import__("json")\n','exec("pass")\n','from . import local\n'])
def test_python_runtime_dependency_checks_cannot_be_bypassed_by_repinning(export,body):
    write(export,'policy.py',body);manifest(export,imports=['json'])
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


def test_declared_standard_python_import_is_static_only(export):
    write(export,'policy.py','import json\nVALUE = json.loads("{}")\n');manifest(export,imports=['json'])
    assert check(export)['runtime_files']==3


def test_native_source_cannot_be_hidden_as_documentation(export):
    manifest(export,roles={'src/policy.c':'document'})
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


def test_duplicate_json_keys_and_case_collisions_refuse(export):
    path=export/'release/widget-source.json';old=path.read_text()
    path.write_text(old.replace('"widget": "picker"','"widget": "picker", "widget": "netrunner"'))
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)
    doc=manifest(export)
    doc['files']['include/Policy.h']=dict(doc['files']['include/policy.h']);save(export,doc)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


def test_cli_refusal_does_not_echo_candidate_values(export):
    marker='synthetic-private-marker'
    write(export,'src/policy.c',marker)
    result=subprocess.run([sys.executable,str(TOOL),'--root',str(export),'--widget-inventory','release/widget-source.json'],capture_output=True,text=True)
    assert result.returncode==1
    assert marker not in result.stdout+result.stderr
    assert str(export) not in result.stdout+result.stderr


@pytest.mark.parametrize('directive',['#include_next "policy.h"','#import "policy.h"','%:include "policy.h"','#inc\\\nlude "missing.h"'])
def test_alternate_and_spliced_include_directives_cannot_escape_review(export,directive):
    write(export,'src/policy.c',directive+'\nint sample;\n');manifest(export)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('field,value',[('schema','unknown'),('widget','mapster'),('stage','production')])
def test_profile_does_not_promote_unknown_widgets_or_release_scope(export,field,value):
    doc=json.loads((export/'release/widget-source.json').read_text());doc[field]=value;save(export,doc)
    with pytest.raises(checker.WidgetInventoryInvalid):check(export)


@pytest.mark.parametrize('directory',['.git','.private-migration','localdata'])
def test_inventory_itself_cannot_hide_in_excluded_or_private_metadata(export,directory):
    data=(export/'release/widget-source.json').read_text()
    write(export,directory+'/widget-source.json',data)
    with pytest.raises(checker.WidgetInventoryInvalid):
        checker.check_widget_inventory(export,directory+'/widget-source.json')
