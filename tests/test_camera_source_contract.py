"""The public camera inventory refuses changed bytes and undeclared imports."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('camera_source_checker', ROOT / 'tools/check_camera_source.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

def isolated(tmp_path, monkeypatch):
    shutil.copytree(ROOT / 'firmware/mode_a', tmp_path / 'firmware/mode_a',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    (tmp_path / 'docs').mkdir()
    shutil.copyfile(ROOT / 'docs/CAMERA_SOURCE_RECEIPT.json', tmp_path / 'docs/CAMERA_SOURCE_RECEIPT.json')
    monkeypatch.setattr(checker, 'ROOT', tmp_path)
    monkeypatch.setattr(checker, 'SOURCE', tmp_path / 'firmware/mode_a')

def test_checked_in_camera_source_is_closed():
    checker.check()

@pytest.mark.parametrize('operation', ['modify', 'remove', 'add'])
def test_source_inventory_refuses_changes(tmp_path, monkeypatch, operation):
    isolated(tmp_path, monkeypatch)
    path = checker.SOURCE / 'arm_tools.py'
    if operation == 'modify':
        path.write_text(path.read_text() + '\n# changed\n')
    elif operation == 'remove':
        path.unlink()
    else:
        (checker.SOURCE / 'unexpected.py').write_text('import os\n')
    with pytest.raises(SystemExit, match='inventory or hash'):
        checker.check()

def test_receipt_update_does_not_authorize_private_import(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    path = checker.SOURCE / 'arm_tools.py'
    path.write_text(path.read_text() + '\nimport service_mode_firmware\n')
    receipt_path = tmp_path / 'docs/CAMERA_SOURCE_RECEIPT.json'
    receipt = json.loads(receipt_path.read_text())
    receipt['files']['firmware/mode_a/arm_tools.py'] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(SystemExit, match='Unreviewed camera dependencies'):
        checker.check()
