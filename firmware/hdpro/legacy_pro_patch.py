"""Apply an exact-donor HD Pro engineering patch without an ARM compiler.

This operates on application files only. It does not admit an AC build target,
establish updater compatibility, qualify hardware or communicate with a device.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

MAX_BASE=8*1024*1024
MAX_EXTENSION=1024*1024
MAX_SPEC=1024*1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path,maximum):
    with Path(path).open('rb') as source:
        data=source.read(maximum+1)
    if len(data)>maximum:
        raise ValueError('HD Pro patch input exceeds its size limit')
    return data


def apply(donor: bytes, spec: dict, extension: bytes) -> bytes:
    if (spec.get('schema')!='ascent-hdpro-engineering-patch-v1' or
            spec.get('hardware_qualified') is not False or
            spec.get('ac_target_admitted') is not False):
        raise ValueError('Unrecognized or misclassified HD Pro engineering patch')
    if (not donor or len(donor)>MAX_BASE or len(donor)!=spec.get('base_bytes') or
            sha(donor)!=spec.get('base_sha256')):
        raise ValueError('HD Pro patch requires its exact reviewed donor application')
    if (len(extension)>MAX_EXTENSION or len(extension)!=spec.get('extension_bytes') or
            sha(extension)!=spec.get('extension_sha256')):
        raise ValueError('HD Pro extension identity mismatch')
    patches=spec.get('patches')
    if not isinstance(patches,list) or not 1<=len(patches)<=256:
        raise ValueError('Invalid HD Pro patch count')
    output=bytearray(donor)
    end=0
    for item in patches:
        offset=item.get('offset');size=item.get('size')
        if (type(offset) is not int or type(size) is not int or
                offset<end or size<1 or size>65536 or offset+size>len(donor)):
            raise ValueError('Invalid, overlapping or out-of-bounds HD Pro patch')
        replacement=item.get('replacement_hex')
        if not isinstance(replacement,str) or len(replacement)!=size*2:
            raise ValueError('Invalid HD Pro patch replacement')
        replacement=bytes.fromhex(replacement)
        if sha(donor[offset:offset+size])!=item.get('previous_sha256'):
            raise ValueError('HD Pro patch site identity mismatch')
        output[offset:offset+size]=replacement
        end=offset+size
    output.extend(extension)
    if len(output)!=spec.get('result_bytes') or sha(output)!=spec.get('result_sha256'):
        raise ValueError('HD Pro patched application identity mismatch')
    return bytes(output)


def patch_file(donor_path,spec_path,extension_path,output_path):
    spec=json.loads(bounded_read(spec_path,MAX_SPEC))
    if not isinstance(spec,dict):
        raise ValueError('HD Pro patch specification must be an object')
    data=apply(bounded_read(donor_path,MAX_BASE),spec,bounded_read(extension_path,MAX_EXTENSION))
    # Perform every identity check before creating an output. Never replace an
    # existing file, including another experiment or the selected donor itself.
    with Path(output_path).open('xb') as destination:
        destination.write(data)
    return {'ok':True,'sha256':sha(data),'bytes':len(data),
            'hardware_qualified':False,'ac_target_admitted':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--donor',required=True,type=Path)
    parser.add_argument('--spec',required=True,type=Path)
    parser.add_argument('--extension',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(patch_file(args.donor,args.spec,args.extension,args.out),indent=2))


if __name__=='__main__':
    main()
