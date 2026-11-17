"""Opt-in Windows parity; no installed application or receiver is accessed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

ROOT=Path(__file__).resolve().parents[1]
pytestmark=pytest.mark.skipif(os.environ.get('ASCENT_TEST_WIDGET_CATALOG_WINDOWS')!='1',
                            reason='Explicit Windows local-disk catalog fixture opt-in required')


def test_actual_windows_handles_and_junction_refusal():
    python=Path(os.environ.get('ASCENT_WINDOWS_PYTHON','missing'))
    parent=Path(os.environ.get('ASCENT_CATALOG_WINDOWS_FIXTURES','missing'))
    assert python.is_file() and parent.is_dir(), 'Set trusted Windows Python and owned local-disk fixture parent'
    def win(path):
        if sys.platform=='win32':return str(path.resolve())
        return subprocess.check_output(['wslpath','-w',str(path.resolve())],text=True).strip()
    parent_evidence=ROOT/'artifacts/widget-catalog-windows';parent_evidence.mkdir(parents=True,exist_ok=True)
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent_evidence))
    config=evidence/'private-input.json'
    config.write_text(json.dumps({'source':win(ROOT),'fixture_parent':win(parent)}))
    result=subprocess.run([str(python),'-I',win(ROOT/'tools/testing/widget_catalog_windows_worker.py'),win(config)],
                          capture_output=True,text=True,timeout=60)
    (evidence/'private-worker.log').write_text(result.stdout+result.stderr)
    assert result.returncode==0, 'Inspect local-only Windows catalog evidence under artifacts'
    report=json.loads(result.stdout)
    assert report['passed'] and report['platform']=='Windows'
    assert len(report['checks'])==18 and all(report['checks'].values())
    assert report['fixture_removed'] and report['receiver_accessed'] is False
