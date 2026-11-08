"""Check the explicit public payload, private boundary and staged dependencies."""
from pathlib import Path
import argparse, ast, hashlib, json, os, stat, subprocess, sys

sys.dont_write_bytecode=True
BLOCKED=('service_mode','private_receiver','widget_','picker','netrunner','caddx_picker',
         'caddx_vrx_runtime','caddx_cot','caddx_kmz','caddx_map_composite',
         'caddx_industrial_rtsp','caddx_fcc_unlock','caddx_wallpaper',
         'receiver_operations','receiver_fleet','update_enroll')


def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as source:
        while block:=source.read(1024*1024):value.update(block)
    return value.hexdigest()


def plain(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
        raise ValueError('Public package contains a non-ordinary file: '+path.name)


def check_python(path):
    for node in ast.walk(ast.parse(path.read_bytes())):
        imports=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
        if any(name.split('.')[0].startswith(BLOCKED) for name in imports):raise ValueError(path.name+': private import')
        if isinstance(node,ast.Call):
            func=node.func
            if isinstance(func,ast.Name) and func.id in ('__import__','eval','exec','compile'):raise ValueError(path.name+': unreviewed dynamic execution')
            if isinstance(func,ast.Attribute) and func.attr in ('import_module','spec_from_file_location','exec_module'):
                allowed=path.name=='caddx_firmware_variant.py' and func.attr in ('spec_from_file_location','exec_module')
                if not allowed:raise ValueError(path.name+': unreviewed dynamic import')
                if func.attr=='spec_from_file_location' and (not node.args or not isinstance(node.args[0],ast.Constant) or node.args[0].value!='_ascent_image_tool'):
                    raise ValueError(path.name+': unexpected verifier loader')


def expected_files(profile,dependencies):
    expected={entry['target']:entry for entry in profile['files']}
    for key in ('native','camera'):
        for name,entry in dependencies[key]['files'].items():
            target='runtime/device_tools/'+name
            if target in expected:raise ValueError('Duplicate public package target')
            expected[target]=entry
    return expected


def verify(root,reference,phase):
    root=Path(root).resolve();reference=Path(reference).resolve()
    profile=json.loads((reference/'release/public-payload.json').read_text())
    deps=json.loads((reference/'release/dependencies.json').read_text())
    expected=expected_files(profile,deps)
    if profile['version']!='0.43.56' or profile['licensor']!='TelaMechanica':raise ValueError('Unexpected public release identity')
    for target,entry in expected.items():
        path=root/(entry.get('source',target) if phase=='source' and 'source' in entry else target)
        plain(path)
        if path.stat().st_size!=entry['bytes'] or sha(path)!=entry['sha256']:raise ValueError('Public payload differs: '+target)
    runtime=root/'runtime'
    actual={p.relative_to(root).as_posix() for p in runtime.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    wanted={p for p in expected if p.startswith('runtime/')}
    if phase=='publish' and actual!=wanted:raise ValueError('Published runtime inventory differs from the public allowlist')
    for path in runtime.glob('*.py'):
        if path.stem.startswith(BLOCKED):raise ValueError('Private runtime module present')
        check_python(path)
    for name in ('pyembed','gstreamer'):
        pins=profile['dependencies'][name]
        found={p.relative_to(root/name).as_posix() for p in (root/name).rglob('*') if p.is_file()}
        if found!=set(pins):raise ValueError(name+': dependency inventory differs; missing='+repr(sorted(set(pins)-found))+'; unexpected='+repr(sorted(found-set(pins))))
        for rel,want in pins.items():
            path=root/name/rel;plain(path)
            if sha(path)!=want:raise ValueError(name+': dependency file differs')
    for path in root.rglob('*'):
        if phase=='publish' and (path.suffix in ('.pyc','.pyo','.sealed','.pem','.ppk','.key') or path.name=='__pycache__'):
            raise ValueError('Non-public package content: '+path.name)
    if (runtime/'localdata').exists():raise ValueError('Local application state must not enter the public build')
    native=runtime/'device_tools/native_builder/windows-x64/manifest.json'
    if sha(native)!=deps['native_manifest_sha256']:raise ValueError('Native bundle manifest differs')
    sys.path.insert(0,str(runtime))
    import firmware_builder as builder
    if os.name=='nt':
        worker=runtime/'windows_device_inventory.py'
        observed=subprocess.run([sys.executable,'-I',str(worker),r'VID_1D(6[B-F]|7[0-9A-F]|8[0-4])'],capture_output=True,text=True,timeout=10)
        if observed.returncode!=0:raise ValueError('Packaged Windows inventory worker did not run')
        inventory=json.loads(observed.stdout)
        if inventory.get('platform')!='Windows' or inventory.get('supported') is not True or not all(isinstance(inventory.get(k),list) for k in ('usb','network')):
            raise ValueError('Packaged Windows inventory worker returned an invalid document')
        probe=builder.preflight(builder_dir=str(runtime/'device_tools/mode_a'),use_cache=False)
        if probe.get('via')!='windows-native' or not probe.get('can_build'):raise ValueError('Public native builder preflight failed')
        for target in ('z8','z40','hub'):
            if builder.inspect_camera_support(str(runtime/'device_tools/mode_a'),target) is None:raise ValueError('Public camera support is absent')
        if not builder.preflight(target='hdpro')['can_build']:raise ValueError('HD Pro tester build preflight failed')
    return {'version':profile['version'],'payload_files':len(expected),'camera_payloads':19,
            'hdpro':'tester builds available; hardware NOT_TESTED','private_runtime_modules':0,'wsl_required':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--reference',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--phase',choices=('source','publish'),required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.root,args.reference,args.phase)))


if __name__=='__main__':main()
