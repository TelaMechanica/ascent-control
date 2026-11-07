"""Build an exact-donor HD Pro test image with the established Mode A checks.

This creates a local image. It neither flashes a device nor qualifies hardware.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import os
import sys

DONOR_SHA256 = 'f166927ff1e0090666236f6003bdd306961304e7dec606d347a63d3894fbd7d0'
APP_SHA256 = '3ebdc5825e018da16c7c07101324568d35fd846eb41aaf4caad96749061974ad'
UPDATER_SHA256 = '61ddd37b5a6a074a320fd250c3a543b6267bf06999348f258ef5a28fa232cba2'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(donor_path, mode_a, helper, work, output, report_path):
    require(not output.exists() and not report_path.exists(), 'Output already exists')
    donor = donor_path.read_bytes()
    require(sha(donor) == DONOR_SHA256, 'HD Pro requires the exact normal 19.2.14 donor')
    work.mkdir(parents=True, exist_ok=False)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(mode_a))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import mode_a_build as M
    import legacy_pro_patch as P
    os.environ['ASCENT_MKFS_INVENTORY'] = '1'
    verifier = mode_a / 'ascent_g_sky_image_tool.py'
    gate1_dir = work / 'gate1'
    gate1_dir.mkdir()
    gate1 = M.gate1(donor_path, gate1_dir, helper, str(verifier), work / 'donor_rebuilt.img')
    require(gate1.get('PASS') is True and gate1['donor_sha256'] == sha(donor), 'Donor gate 1 failed')
    T, verifier_sha = M.load_verifier(str(verifier))
    require(gate1['verifier_sha256'] == verifier_sha, 'Gate 1 verifier differs')
    character = T.characterize(donor_path)
    T.verify(donor, donor=character)
    M.check_asw_seal(donor)
    volume, before_ubi = M.volume_of(T, donor, 5)
    original = M.INV.inventory(volume, with_content=True)
    assets = Path(__file__).resolve().parent / 'portable_patch'
    spec = json.loads((assets / 'hdpro-19.2.14-patch.json').read_text())
    patched = P.apply(original['entries']['/fpv/ar_ldyhs_sky']['content'], spec,
                      (assets / 'hdpro-19.2.14-extension.bin').read_bytes())
    require(sha(patched) == APP_SHA256, 'Patched application identity differs')
    modified = copy.deepcopy(original)
    modified['entries']['/fpv/ar_ldyhs_sky'].update(content=patched, size=len(patched), sha256=sha(patched))
    delta = M.compare_inventories(original, modified)
    require(len(delta) == 1 and delta[0].startswith('CHANGED /fpv/ar_ldyhs_sky:'), 'Unexpected semantic change')
    rebuild = work / 'image'
    rebuild.mkdir()
    component, filesystem = M._regen_fs_component(T, donor, 5, modified, rebuild, helper)
    candidate = M.assemble_asw(T, donor, {5: component})
    checks = {'existing_verifier': T.verify(candidate, donor=character), 'asw_seal': M.check_asw_seal(candidate)}
    before = T.parse_asw(donor)['components']
    after = T.parse_asw(candidate)['components']
    require(len(before) == len(after), 'Component count differs')
    unchanged = []
    for a, b in zip(before, after):
        require(all(a[key] == b[key] for key in ('id', 'offset', 'partition_bytes', 'upgrade', 'dual')), 'Component geometry differs')
        if a['id'] != 5:
            require(a['sha256'] == b['sha256'], 'Non-grafted component changed')
            unchanged.append(a['id'])
    require(unchanged == [0, 1, 2, 4], 'Unexpected preserved components')
    require(all(0x70 <= i < 0x78 for i in range(0x80) if donor[i] != candidate[i]), 'Unexpected header change')
    new_volume, after_ubi = M.volume_of(T, candidate, 5)
    actual = M.INV.inventory(new_volume, with_content=True)
    require(not M.compare_inventories(modified, actual), 'Regenerated filesystem differs')
    require(M.compare_inventories(original, actual) == delta, 'Unexpected filesystem change')
    require(actual['entries']['/fpv/ar_ldyhs_sky']['content'] == patched, 'Application readback differs')
    require(actual['entries']['/fpv/ar_fpvhs_upgrade']['sha256'] == UPDATER_SHA256, 'Updater changed')
    require(all(before_ubi[k] == after_ubi[k] for k in ('image_seq', 'peb_size', 'vid_hdr_offset', 'data_offset', 'leb_size')), 'UBI geometry changed')
    require({k:v for k,v in before_ubi['vtbl'][0].items() if k != 'reserved_pebs'} ==
            {k:v for k,v in after_ubi['vtbl'][0].items() if k != 'reserved_pebs'}, 'Volume table changed')
    before_sb, after_sb = T.ubifs_superblock(volume), T.ubifs_superblock(new_volume)
    require(all(before_sb[k] == after_sb[k] for k in M.SB_FIELDS_MUST_MATCH), 'Superblock geometry changed')
    require(after_ubi['vtbl'][0]['reserved_pebs'] == after_sb['leb_cnt'], 'Volume reservation differs')
    window = M.check_window(new_volume, 5)
    result = {'PASS': True, 'target': 'hdpro', 'image': {'sha256': sha(candidate), 'bytes': len(candidate)},
              'donor_sha256': sha(donor), 'application_sha256': sha(patched), 'gate1': gate1,
              'only_semantic_change': delta, 'unchanged_components': unchanged, 'filesystem': filesystem,
              'checks': checks, 'deflate_window': window, 'hardware_qualified': False,
              'build_availability': 'TESTING', 'hardware_accessed': False}
    with output.open('xb') as destination:
        destination.write(candidate)
    require(output.stat().st_size == len(candidate) and sha(output.read_bytes()) == result['image']['sha256'], 'Written image differs')
    with report_path.open('x', encoding='utf-8') as destination:
        json.dump(result, destination, indent=2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('donor', 'mode-a', 'helper', 'work', 'out', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = build(args.donor, args.mode_a, args.helper, args.work, args.out, args.report)
    print(json.dumps({'PASS': result['PASS'], **result['image'], 'hardware_qualified': False}))


if __name__ == '__main__':
    main()
