"""Check desktop runtime inputs or an explicit standalone native-widget inventory.

Inventory agreement is not privacy clearance, publisher trust or release approval.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


class WidgetInventoryInvalid(ValueError):
    pass


def _reject(message):
    raise WidgetInventoryInvalid(message)


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:_reject('Duplicate inventory key')
        result[key]=value
    return result


def _relative(value):
    if not isinstance(value,str) or not value or len(value)>240 or (any(ord(c)<32 for c in value) or any(c in value for c in ('\\',':','<','>','"','|','?','*'))):
        _reject('Invalid inventory path')
    path=PurePosixPath(value)
    if not path.parts or path.is_absolute() or path.as_posix()!=value or any(part in ('','.','..') for part in path.parts):
        _reject('Noncanonical inventory path')
    for part in path.parts:
        stem=part.split('.')[0].upper()
        if part.endswith((' ','.')) or stem in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}:
            _reject('Reserved inventory path')
    return value


def _ordinary(path):
    if not stat.S_ISREG(path.lstat().st_mode):_reject('Nonordinary inventory input')
    if path.stat().st_size>16*1024*1024:_reject('Inventory input too large')


def _strings(value):
    if not isinstance(value,list) or any(not isinstance(v,str) for v in value) or len(set(value))!=len(value):
        _reject('Invalid inventory list')
    return value


def _without_comments(text):
    tokens=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',re.S)
    return tokens.sub(lambda m: '\n'*m.group().count('\n') if m.group().startswith(('/*','//')) else m.group(),text)


def check_widget_inventory(root, inventory):
    root=Path(root)
    if root.is_symlink() or not root.is_dir():_reject('Invalid source root')
    root=root.resolve()
    relative=_relative(inventory)
    if any(part in ('.git','.private-migration','localdata') for part in PurePosixPath(relative).parts):_reject('Inventory cannot be private metadata')
    manifest=root/relative
    if any(parent.is_symlink() for parent in [manifest,*manifest.parents] if parent.is_relative_to(root)):_reject('Symlink in inventory path')
    _ordinary(manifest)
    if manifest.stat().st_size>2*1024*1024:_reject('Inventory manifest too large')
    doc=json.loads(manifest.read_text(encoding='utf-8'),object_pairs_hook=_pairs)
    fields={'schema','widget','stage','files','include_roots','system_headers','python_imports'}
    if not isinstance(doc,dict) or set(doc)!=fields or doc['schema']!='ascent.widget.source_inventory.v1':
        _reject('Unknown widget inventory schema')
    if doc['widget'] not in ('picker','netrunner') or doc['stage']!='native-subset':
        _reject('Unsupported widget inventory scope')
    files=doc['files']
    if not isinstance(files,dict) or not files or len(files)>5000 or relative in files:
        _reject('Invalid inventory file set')
    names=set();folded=set();runtime=set();total=0
    for name,item in files.items():
        _relative(name)
        if name.casefold() in folded:_reject('Case-colliding inventory paths')
        folded.add(name.casefold());names.add(name)
        if not isinstance(item,dict) or set(item)!={'sha256','bytes','role'}:_reject('Invalid file record')
        if not isinstance(item['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',item['sha256']):_reject('Invalid file digest')
        if type(item['bytes']) is not int or not 0<=item['bytes']<=16*1024*1024:_reject('Invalid file size')
        if item['role'] not in ('runtime','test','tool','document','build'):_reject('Invalid file role')
        path=PurePosixPath(name)
        if any(part in ('.git','.private-migration','localdata') for part in path.parts) or path.suffix.lower() in ('.key','.pem','.ppk','.sealed','.bundle','.pyc','.pyo'):
            _reject('Nonpublic inventory input')
        if path.suffix.lower() in ('.c','.h','.inc') and (path.suffix!=path.suffix.lower() or item['role'] not in ('runtime','test')):_reject('Native source role mismatch')
        if item['role']=='runtime':
            if path.suffix not in ('.c','.h','.inc','.py'):_reject('Unsupported runtime source')
            runtime.add(name)
    if not runtime:_reject('Empty runtime inventory')
    actual=set()
    for directory,dirs,leaves in os.walk(root,followlinks=False):
        parent=Path(directory)
        for name in [*dirs,*leaves]:
            if (parent/name).is_symlink():_reject('Symlink in source tree')
        if parent==root and '.git' in dirs:dirs.remove('.git')
        for name in leaves:
            if parent==root and name=='.git':continue
            path=parent/name
            _ordinary(path)
            rel=path.relative_to(root).as_posix()
            if rel!=relative:actual.add(rel)
    if actual!=names:_reject('Source inventory differs')
    for name,item in files.items():
        path=root/name;data=path.read_bytes();total+=len(data)
        if total>128*1024*1024:_reject('Source tree too large')
        if len(data)!=item['bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:_reject('Source content differs')
    include_roots=_strings(doc['include_roots'])
    for name in include_roots:
        _relative(name)
        if not (root/name).is_dir():_reject('Missing include root')
    headers=_strings(doc['system_headers'])
    for name in headers:_relative(name)
    imports=_strings(doc['python_imports'])
    if any(not name.isidentifier() or name not in sys.stdlib_module_names for name in imports):
        _reject('Nonstandard Python import declaration')
    local_modules={PurePosixPath(name).stem for name in runtime if name.endswith('.py') and '/' not in name}
    for name,item in files.items():
        path=root/name
        if path.suffix in ('.c','.h','.inc'):
            text=path.read_text(encoding='utf-8').replace('\\\n','').replace('\\\r\n','')
            text=_without_comments(text)
            for line in text.splitlines():
                if not re.match(r'^\s*(?:#|%:)\s*(?:include|include_next|import)\b',line):continue
                match=re.fullmatch(r'\s*#\s*include\s*(?:"([^"\n]+)"|<([^>\n]+)>)\s*',line)
                if not match:_reject('Computed or malformed native include')
                quoted,system=match.groups()
                if system:
                    if system not in headers:_reject('Undeclared system include')
                    continue
                if any(c in quoted for c in ('\\',':','\x00')) or Path(quoted).is_absolute():_reject('Unsafe native include')
                choices=[path.parent/quoted,*[root/d/quoted for d in include_roots]]
                targets=set()
                for candidate in choices:
                    resolved=candidate.resolve()
                    if not resolved.is_relative_to(root):_reject('Native include escapes source tree')
                    rel=resolved.relative_to(root).as_posix()
                    if rel in files:targets.add(rel)
                if len(targets)!=1:_reject('Missing or ambiguous native include')
                target=next(iter(targets))
                if files[target]['role'] not in ('runtime','test'):_reject('Native include role mismatch')
                if item['role']=='runtime' and files[target]['role']!='runtime':_reject('Runtime includes test source')
        elif path.suffix=='.py' and item['role']=='runtime':
            tree=ast.parse(path.read_bytes())
            for node in ast.walk(tree):
                modules=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
                if isinstance(node,ast.ImportFrom) and node.level:_reject('Relative Python import requires review')
                if any(module.split('.')[0] not in set(imports)|local_modules for module in modules):_reject('Undeclared Python import')
                if isinstance(node,ast.Call):
                    if isinstance(node.func,ast.Name) and node.func.id in ('eval','exec','compile','__import__'):_reject('Dynamic Python execution requires review')
                    if isinstance(node.func,ast.Attribute) and node.func.attr in ('import_module','spec_from_file_location','exec_module'):_reject('Dynamic Python import requires review')
    return {'profile':'standalone-widget','widget':doc['widget'],'stage':doc['stage'],'files':len(files),'runtime_files':len(runtime),'release_approved':False}


def check_desktop(root):
    receipt=json.loads((root/'docs/SHARED_SOURCE_IMPORT.json').read_text())
    expected={item['path']:item for item in receipt['files'] if item['path'].startswith('runtime/')}
    actual={p.relative_to(root).as_posix() for p in (root/'runtime').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    profile=json.loads((root/'release/public-payload.json').read_text())
    desktop={item['source']:item for item in profile['files'] if item['source'].startswith('runtime/')}
    reviewed=set(expected)|set(desktop)
    if actual!=reviewed:
        raise SystemExit('Runtime inventory differs from the reviewed import manifest.')
    from verify_public_build import check_python
    for name,item in desktop.items():
        path=root/name
        if path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
            raise SystemExit(name+': desktop source differs from the reviewed payload')
        if path.suffix=='.py':check_python(path)
    allowed={'__future__','math','re','struct'}
    for name,item in expected.items():
        data=(root/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise SystemExit(name+': source changed without a reviewed manifest update')
        for node in ast.walk(ast.parse(data)):
            imports=[]
            if isinstance(node,ast.Import):imports=[alias.name for alias in node.names]
            if isinstance(node,ast.ImportFrom):
                if node.level:raise SystemExit(name+': relative import requires dependency review')
                imports=[node.module or '']
            if any(value.split('.')[0] not in allowed for value in imports):
                raise SystemExit(name+': import outside the reviewed pure runtime closure')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'__import__','eval','exec','compile'}:
                raise SystemExit(name+': dynamic execution requires dependency review')
    print('Reviewed runtime inventory, source hashes and static dependency closure passed.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--widget-inventory',help='Explicit reviewed source inventory, relative to root; never auto-detected')
    args=parser.parse_args()
    if args.widget_inventory:
        try:
            result=check_widget_inventory(args.root,args.widget_inventory)
        except (WidgetInventoryInvalid,OSError,UnicodeError,ValueError,RecursionError,SyntaxError):
            parser.exit(1,'Standalone widget inventory rejected.\n')
        print(json.dumps(result,sort_keys=True))
    else:check_desktop(args.root.resolve())


if __name__=='__main__':main()
