"""Runtime file dependencies include workers launched outside Python imports."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_script_references_are_explicit_package_inputs():
    profile = json.loads((ROOT / 'release/public-payload.json').read_text())
    shipped = {Path(entry['target']).name for entry in profile['files']}
    required = set()
    for source in (ROOT / 'runtime').glob('*.py'):
        for node in ast.walk(ast.parse(source.read_bytes())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*\.(?:py|ps1)', node.value):
                    required.add(node.value)
    assert 'windows_device_inventory.py' in required
    assert required <= shipped, 'Unpackaged script references: ' + repr(sorted(required - shipped))


def test_inventory_worker_runs_as_an_actual_child_process():
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'runtime/windows_device_inventory.py'),
                             r'VID_1D(6[B-F]|7[0-9A-F]|8[0-4])'],
                            capture_output=True, text=True, timeout=15)
    if sys.platform == 'win32':
        assert result.returncode == 0, result.stderr
        doc = json.loads(result.stdout)
        assert doc['supported'] is True and doc['platform'] == 'Windows'
        assert isinstance(doc['usb'], list) and isinstance(doc['network'], list)
    else:
        assert result.returncode == 3
        assert 'requires Windows' in result.stderr


def test_mandatory_embedded_runtime_files_have_pins():
    profile = json.loads((ROOT / 'release/public-payload.json').read_text())
    assert {'python.exe', 'pythonw.exe', 'python312.zip', 'python312._pth'} <= set(profile['dependencies']['pyembed'])
    assert {'bin/gstreamer-1.0-0.dll', 'bin/gstvideo-1.0-0.dll', 'licenses/LGPL-2.1.txt'} <= set(profile['dependencies']['gstreamer'])
