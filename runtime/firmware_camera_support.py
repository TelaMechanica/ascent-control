"""Pinned internal camera inputs; no vendor payload bytes are stored in source."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat

SCHEMA = "ascent.camera.support.v1"
SOURCE_IMAGES = {'hub': {'sha256': 'a5b22b7b7a07b05771ff83088ccb998c14448f73e6bb53a3737da5d3f58d1cf6',
         'size': 17609625,
         'filename': 'Ascent_G_Sky_18_21_4_Hub_6.img',
         'variant': 'hub',
         'version': '18.21.4',
         'subversion': 6},
 'z40': {'sha256': 'dd17cffd7c8fe255999f8227575b912d4e6411c0cbf5791be6aaf609cbfe9630',
         'size': 12557533,
         'filename': 'Ascent_G_Sky_17_5_8_z40_2.img',
         'variant': 'z40',
         'version': '17.5.8',
         'subversion': 2},
 'z8': {'sha256': 'cdf3cd01520194c0f80d90f83db98451ea5b68b293d4f75252a42555aa259228',
        'size': 12557532,
        'filename': 'Ascent_G_Sky_17_5_8_z8_2.img',
        'variant': 'z8',
        'version': '17.5.8',
        'subversion': 2},
 'n18213': {'sha256': '806f91fd48f58878afcd08f71917f72f942f930921fd49bcfdd430a2269f0cd1',
            'size': 17216417,
            'filename': 'Ascent_G_Sky_18_21_3.img',
            'variant': 'normal',
            'version': '18.21.3',
            'subversion': None}}
FILES = {'hub/usrdata/fpv/ar_ldyhs_sky': {'sha256': 'c84eb115ec5070aea26f38b071891f0ae41b6bb9f1acc1b173676e1a2e1327cf',
                                  'size': 2680168,
                                  'role': 'hub',
                                  'device_path': '/fpv/ar_ldyhs_sky',
                                  'payload': 'payload/00.bin'},
 'hub/usrdata/fpv/boot_lt6911uxe/LT6911UXE_H2CSI_1920x1080_SV2_8_26020601.bin': {'sha256': '4171b74e9888c91f9f312587cbb95f392fa2b25af5a9c626a1fdaa2c99c73918',
                                                                                 'size': 32768,
                                                                                 'role': 'hub',
                                                                                 'device_path': '/fpv/boot_lt6911uxe/LT6911UXE_H2CSI_1920x1080_SV2_8_26020601.bin',
                                                                                 'payload': 'payload/01.bin'},
 'hub/usrdata/fpv/boot_lt6911uxe/edid_1920x1080.bin': {'sha256': 'eaa8909b38428ab148a0c36a6c804c02d305dc22ca20f00b3776e849394d63c1',
                                                       'size': 120,
                                                       'role': 'hub',
                                                       'device_path': '/fpv/boot_lt6911uxe/edid_1920x1080.bin',
                                                       'payload': 'payload/02.bin'},
 'hub/usrdata/fpv/boot_lt6911uxe/lt6911uxe_upgrade': {'sha256': '22ba1da054cc18ec7135037c480f3da17a0329221cfac9b418a173ec10eb96a6',
                                                      'size': 12192,
                                                      'role': 'hub',
                                                      'device_path': '/fpv/boot_lt6911uxe/lt6911uxe_upgrade',
                                                      'payload': 'payload/03.bin'},
 'hub/usrdata/fpv/fpv_mipihub_ctrl.sh': {'sha256': '766a4a0300a968712f495736c32f869fa116d1269cb71292f9371e8fe433e513',
                                         'size': 6623,
                                         'role': 'hub',
                                         'device_path': '/fpv/fpv_mipihub_ctrl.sh',
                                         'payload': 'payload/04.bin'},
 'hub/usrdata/fpv/ko_cv610_20s/sys_config.ko': {'sha256': '3cf9abbee1682ff12b2bf4db5230a70ba0cfa15ad48c92eb5a36a18c67bc5464',
                                                'size': 13592,
                                                'role': 'hub',
                                                'device_path': '/fpv/ko_cv610_20s/sys_config.ko',
                                                'payload': 'payload/05.bin'},
 'hub/usrdata/fpv/mipi_hub.ini': {'sha256': 'edb6b910ad9ae387c2b7c76bce7833a8ce5440817812d026c14f1c8e2ffeaa6d',
                                  'size': 173,
                                  'role': 'hub',
                                  'device_path': '/fpv/mipi_hub.ini',
                                  'payload': 'payload/06.bin'},
 'hub/usrdata/fpv/mipi_hub.json': {'sha256': '50b28cfa85335b31ac1d82be6a76a2960a77ab6f025b500f5abd2c8c871b6191',
                                   'size': 580,
                                   'role': 'hub',
                                   'device_path': '/fpv/mipi_hub.json',
                                   'payload': 'payload/07.bin'},
 'hub/usrdata/fpv/msp_rc_cfg.json': {'sha256': '6e3809b8722fdb0a8dbcb25ad482db7af3e85e0cb9e82ddbf7e98c356ea138f7',
                                     'size': 252,
                                     'role': 'hub',
                                     'device_path': '/fpv/msp_rc_cfg.json',
                                     'payload': 'payload/08.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z40_xg1.bin': {'sha256': 'a3fbd5a0bb4726e70a0147c73d3dab76e2cd4dff628dc6771b6b0e2125ad5f3a',
                                                          'size': 144722,
                                                          'role': 'hub',
                                                          'device_path': '/fpv/tunning/cam_imx586_50fps_z40_xg1.bin',
                                                          'payload': 'payload/09.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z40_xg2.bin': {'sha256': '2d0a8da754e03e4b35c92e8794f76e10b8e4ab12dab3aca80cd4fd7acb150db7',
                                                          'size': 144722,
                                                          'role': 'hub',
                                                          'device_path': '/fpv/tunning/cam_imx586_50fps_z40_xg2.bin',
                                                          'payload': 'payload/10.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z40_xg4.bin': {'sha256': '4f6f5f4cee5d29ad01d5ca0af67f7fb514ecea63fc6745772eeae1be12362b09',
                                                          'size': 144722,
                                                          'role': 'hub',
                                                          'device_path': '/fpv/tunning/cam_imx586_50fps_z40_xg4.bin',
                                                          'payload': 'payload/11.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z8_xg1.bin': {'sha256': 'be8442b295ea7a57a09bd52e1fdd5e34bbdaa7798016378935742f0f3e9d85ec',
                                                         'size': 144722,
                                                         'role': 'hub',
                                                         'device_path': '/fpv/tunning/cam_imx586_50fps_z8_xg1.bin',
                                                         'payload': 'payload/12.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z8_xg2.bin': {'sha256': '085d84d0334fa81919b308405bbbaeec778f5ab09c7c9f973f0c29b4febaab4b',
                                                         'size': 144722,
                                                         'role': 'hub',
                                                         'device_path': '/fpv/tunning/cam_imx586_50fps_z8_xg2.bin',
                                                         'payload': 'payload/13.bin'},
 'hub/usrdata/fpv/tunning/cam_imx586_50fps_z8_xg4.bin': {'sha256': 'a7364b734de962ba5b3ad27adb8e42dafe923422580181fcb82b43bae33ae817',
                                                         'size': 144722,
                                                         'role': 'hub',
                                                         'device_path': '/fpv/tunning/cam_imx586_50fps_z8_xg4.bin',
                                                         'payload': 'payload/14.bin'},
 'hub/usrdata/fpv/tunning/cam_ps5280_50fps_z40.bin': {'sha256': '8965b2a0ac37f2e012238d209bcad0dc33988dc112600565f0d17139dd46e048',
                                                      'size': 144722,
                                                      'role': 'hub',
                                                      'device_path': '/fpv/tunning/cam_ps5280_50fps_z40.bin',
                                                      'payload': 'payload/15.bin'},
 'n18213/usrdata/fpv/ar_ldyhs_sky': {'sha256': '35ceb1672002e205d7d4f29b646c1c681af8fcc5ebcf110f3d545562441b6cbd',
                                     'size': 2478160,
                                     'role': 'n18213',
                                     'device_path': '/fpv/ar_ldyhs_sky',
                                     'payload': 'payload/16.bin'},
 'z40/usrdata/fpv/ar_ldyhs_sky': {'sha256': '7559294c7f35797f916ca8dbe32d490e13c110f26cdcfd379eda871398209648',
                                  'size': 2529316,
                                  'role': 'z40',
                                  'device_path': '/fpv/ar_ldyhs_sky',
                                  'payload': 'payload/17.bin'},
 'z8/usrdata/fpv/ar_ldyhs_sky': {'sha256': '49d6b180417b266242cbdd811c6b27cecbecc3c064b4f6bec0eaad17590da59b',
                                 'size': 2525208,
                                 'role': 'z8',
                                 'device_path': '/fpv/ar_ldyhs_sky',
                                 'payload': 'payload/18.bin'}}
TARGET_ROLES = {'z40': ('hub', 'z40'), 'z8': ('hub', 'z8'), 'hub': ('hub', 'n18213')}
PACK_ID = 'camera-support-19.2.14-v1'


class CameraSupportError(ValueError):
    """An installed camera support pack is incomplete or untrusted."""


def default_pack_dir(builder_dir):
    return Path(builder_dir).parent / 'camera_support' / 'v1'


def source_versions():
    return {role: {'variant': value['variant'], 'version': value['version'],
                   'sub_version': str(value['subversion']) if value['subversion'] is not None else None}
            for role, value in SOURCE_IMAGES.items()}


def manifest():
    """Return only compiled-in metadata; payload contents remain external inputs."""
    return {'schema': SCHEMA, 'pack_id': PACK_ID, 'targets': sorted(TARGET_ROLES),
            'source_images': copy.deepcopy(SOURCE_IMAGES), 'source_versions': source_versions(),
            'files': copy.deepcopy(FILES)}


def _plain(path, directory=False):
    try:
        info = path.lstat()
    except OSError as error:
        raise CameraSupportError('Missing camera support input') from error
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise CameraSupportError('Camera support paths must be ordinary files and directories')


def _ancestors(path):
    for parent in [path, *path.parents]:
        _plain(parent, directory=True)


def _read(path, expected):
    _plain(path)
    if path.stat().st_size != expected['size']:
        raise CameraSupportError('Camera support payload size mismatch')
    data = path.read_bytes()
    if len(data) != expected['size'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
        raise CameraSupportError('Camera support payload hash mismatch')
    return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CameraSupportError('Duplicate camera support manifest key')
        result[key] = value
    return result


def _validate_support_pack(pack_dir):
    """Validate the exact compiled-in pack; a manifest cannot introduce new hashes."""
    root = Path(os.path.abspath(pack_dir))
    _ancestors(root)
    expected = {'manifest.json', *[value['payload'] for value in FILES.values()]}
    actual = set()
    def walk(directory):
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            if path.is_dir() and not path.is_symlink():
                _plain(path, directory=True)
                if relative != 'payload':
                    raise CameraSupportError('Unexpected camera support directory')
                walk(path)
            else:
                _plain(path)
                actual.add(relative)
    walk(root)
    if actual != expected:
        raise CameraSupportError('Camera support file inventory mismatch')
    document = root / 'manifest.json'
    _plain(document)
    if document.stat().st_size > 1024 * 1024:
        raise CameraSupportError('Camera support manifest is too large')
    try:
        received = json.loads(document.read_text(encoding='utf-8'), object_pairs_hook=_unique)
    except (OSError, UnicodeError, ValueError) as error:
        raise CameraSupportError('Invalid camera support manifest') from error
    # Canonical JSON also distinguishes booleans/numbers from their Python-equal values.
    if json.dumps(received, sort_keys=True) != json.dumps(manifest(), sort_keys=True):
        raise CameraSupportError('Camera support manifest differs from pinned metadata')
    for value in FILES.values():
        _read(root / value['payload'], value)
    return {'pack_dir': str(root), 'pack_id': PACK_ID, 'source_versions': source_versions(),
            'file_count': len(FILES), 'bytes': sum(value['size'] for value in FILES.values())}


def validate_support_pack(pack_dir):
    try:
        return _validate_support_pack(pack_dir)
    except CameraSupportError:
        raise
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise CameraSupportError('Cannot validate camera support pack') from error


def inspect_support_pack(builder_dir, target):
    if target not in TARGET_ROLES:
        raise CameraSupportError('Unsupported camera support target')
    root = default_pack_dir(builder_dir)
    if not os.path.lexists(root):
        return None
    result = validate_support_pack(root)
    result['target'] = target
    return result


def _target_files(target):
    if target not in TARGET_ROLES:
        raise CameraSupportError('Unsupported camera support target')
    selected = {}
    for key, value in FILES.items():
        if value['role'] not in TARGET_ROLES[target]:
            continue
        if value['role'] == 'hub' and target != 'hub':
            path = value['device_path']
            if path != '/fpv/ar_ldyhs_sky' and not (
                    path.startswith('/fpv/tunning/') and ('_' + target) in path):
                continue
        selected[key] = value
    return selected


def materialize_target(pack_dir, target, fresh_extract_dir):
    """Copy only verified target inputs into a new build extraction directory."""
    selected = _target_files(target)
    validate_support_pack(pack_dir)
    root = Path(os.path.abspath(pack_dir))
    out = Path(os.path.abspath(fresh_extract_dir))
    _ancestors(out.parent)
    if os.path.lexists(out):
        raise CameraSupportError('Camera support output must be a fresh directory')
    out.mkdir()
    for key, value in selected.items():
        data = _read(root / value['payload'], value)
        destination = out / key  # Only compiled-in, fixed POSIX-relative paths.
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
    return {role: out / role for role in TARGET_ROLES[target]}
