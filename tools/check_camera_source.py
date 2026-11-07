"""Check the standalone camera source receipt and Python import boundary."""
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'firmware/mode_a'
EXTERNAL = {'capstone', 'elftools', 'unicorn'}
MODULES = frozenset('arm_tools ascent_g_sky_image_tool deflate_distance direct_camera emu extract fextent fs_backend hub_build hub_gate2 mode_a_build rc_displayport rc_displayport_transport sensor_lifecycle ubifs_inventory variant_identity verify_hub_app verify_hub_config verify_variant_identity verify_z40_app verify_z8_app z40_build z8_build z8_gate2'.split())

def check():
    receipt = json.loads((ROOT / 'docs/CAMERA_SOURCE_RECEIPT.json').read_text())
    expected = receipt['files']
    actual = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in SOURCE.rglob('*') if p.is_file() and '__pycache__' not in p.parts
              and p.suffix != '.pyc'}
    if actual != expected:
        raise SystemExit('Camera source inventory or hash differs from receipt')
    modules = {p.stem for p in SOURCE.glob('*.py')}
    if modules != MODULES:
        raise SystemExit('Unexpected camera Python module set')
    imports = set()
    for path in SOURCE.glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text(), filename=path.name)):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    raise SystemExit('Unexpected relative import: ' + path.name)
                imports.add((node.module or '').split('.')[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '__import__':
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    raise SystemExit('Unreviewed dynamic import: ' + path.name)
                imports.add(str(node.args[0].value).split('.')[0])
    unexpected = imports - modules - sys.stdlib_module_names - EXTERNAL
    if unexpected:
        raise SystemExit('Unreviewed camera dependencies: ' + ', '.join(sorted(unexpected)))
    for entry in receipt['entrypoints']:
        if entry not in modules:
            raise SystemExit('Missing entry point: ' + entry)
    print(f'Camera source: {len(actual)} pinned files, {len(modules)} Python modules; import boundary passed.')

if __name__ == '__main__':
    check()
