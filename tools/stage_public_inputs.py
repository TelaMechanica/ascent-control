"""Stage exact public release inputs without private source or installed AC."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, os, shutil, stat, urllib.request, zipfile


def digest(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as source:
        while block:=source.read(1024*1024):result.update(block)
    return result.hexdigest()


def safe_name(name):
    parts=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or '\x00' in name or parts.is_absolute() or str(parts)!=name or any(p in ('.','..') for p in name.split('/')):
        raise ValueError('Unsafe release input path')
    return name


def acquire(record, supplied, cache):
    path=Path(supplied) if supplied else cache/record['name']
    if not path.exists():
        if supplied:raise ValueError('Specified release archive is absent')
        cache.mkdir(parents=True,exist_ok=True)
        with urllib.request.urlopen(record['url'],timeout=90) as response,path.open('xb') as output:
            total=0
            while block:=response.read(1024*1024):
                total+=len(block)
                if total>record['bytes']:raise ValueError('Release archive exceeds its pinned size')
                output.write(block)
    if path.is_symlink() or path.stat().st_size!=record['bytes'] or digest(path)!=record['sha256']:
        raise ValueError('Release archive differs from its pinned identity')
    return path


def plain_parents(path, root):
    current=path.parent
    while True:
        if current.exists():
            info=current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400 or not stat.S_ISDIR(info.st_mode):
                raise ValueError('Release input parent is not an ordinary directory')
        if current==root:break
        current=current.parent


def unpack(archive, record, output):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        entries=[n for n in bundle.namelist() if not n.endswith('/')]
        if len(entries)!=len(set(entries)) or set(entries)!=set(record['files']):raise ValueError('Release archive inventory differs')
        for name in entries:
            safe_name(name)
            if name.split('/')[0] not in {'native_builder','camera_support','sources','licenses'}:raise ValueError('Unexpected release input role')
            meta=bundle.getinfo(name);wanted=record['files'][name]
            if meta.file_size!=wanted['bytes'] or stat.S_ISLNK(meta.external_attr>>16):raise ValueError('Unsafe release archive entry')
            dest=output.joinpath(*name.split('/'));plain_parents(dest,output)
            if os.path.lexists(dest):
                info=dest.lstat()
                if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400 or digest(dest)!=wanted['sha256']:raise ValueError('Existing staged input differs; preserve it and use a fresh build tree')
                continue
            dest.parent.mkdir(parents=True,exist_ok=True)
            with bundle.open(name) as source,dest.open('xb') as target:shutil.copyfileobj(source,target)
            if digest(dest)!=wanted['sha256']:raise ValueError('Extracted release input hash differs')


def stage(root, native=None, camera=None, cache=None):
    root=Path(root).resolve();records=json.loads((root/'release/dependencies.json').read_text())
    cache=Path(cache) if cache else root/'.stage/downloads'
    output=root/'runtime/device_tools'
    for key,supplied in [('native',native),('camera',camera)]:unpack(acquire(records[key],supplied,cache),records[key],output)
    scripts=root/'firmware/mode_a';staged=output/'mode_a';staged.mkdir(exist_ok=True)
    native_manifest=json.loads((output/'native_builder/windows-x64/manifest.json').read_text())
    actual={p.name:digest(p) for p in scripts.glob('*.py')}
    if actual!=native_manifest['builder_files']:raise ValueError('Public camera source differs from qualified scripts')
    for name,wanted in actual.items():
        target=staged/name
        if target.exists():
            if target.is_symlink() or digest(target)!=wanted:raise ValueError('Staged camera source differs')
        else:shutil.copy2(scripts/name,target)
    return {'native_tools':'verified','camera_files':19,'source_images_required':False,'wsl_required':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--native-archive',type=Path)
    parser.add_argument('--camera-archive',type=Path)
    parser.add_argument('--cache',type=Path)
    args=parser.parse_args()
    print(json.dumps(stage(args.root,args.native_archive,args.camera_archive,args.cache)))


if __name__=='__main__':main()
