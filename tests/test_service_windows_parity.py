"""Opt-in Windows OpenSSH against the same owned WSL localhost fixture."""
import getpass
import json
import os
from pathlib import Path
import subprocess
import uuid
import pytest
from test_service_loopback_ssh import fixture_server

pytestmark = pytest.mark.skipif(os.environ.get('ASCENT_TEST_WINDOWS_SSH') != '1',
    reason='Explicit Windows/WSL SSH fixture opt-in required')


def test_windows_pinned_handshake_and_authority_guards(fixture_server):
    source = Path(__file__).resolve().parents[1]
    root, port, _, _ = fixture_server
    python = Path(os.environ.get('ASCENT_WINDOWS_PYTHON', 'missing-windows-python'))
    assert python.is_file(), 'Set ASCENT_WINDOWS_PYTHON to a trusted Windows Python executable mounted in WSL'
    def win(path):
        return subprocess.check_output(['wslpath', '-w', str(path)], text=True).strip()
    config = root/'private-windows-config.json'
    config.write_text(json.dumps({'source': win(source), 'fixture': win(root),
                                 'port': port, 'username': getpass.getuser()}))
    launcher = root/'run-worker.ps1'
    launcher.write_text('param([string]$Python,[string]$Worker,[string]$Config)\n'
                        '$ErrorActionPreference="Stop"\n& $Python $Worker $Config\nexit $LASTEXITCODE\n')
    shell = Path('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
    assert shell.is_file(), 'Opt-in requires Windows PowerShell interoperability'
    result = subprocess.run([str(shell), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', win(launcher),
                             win(python), win(source/'tools/testing/windows_ssh_worker.py'), win(config)],
                            capture_output=True, text=True, timeout=45)
    if result.returncode:
        # Local-only failure evidence; never include this ignored log in exports.
        log = source/'artifacts'/('private-windows-parity-' + uuid.uuid4().hex + '.log')
        log.write_text(result.stdout + result.stderr)
        pytest.fail('Windows fixture failed; inspect local-only private parity log under artifacts')
    report = json.loads(result.stdout)
    assert report['platform'] == 'Windows' and report['fixture_only'] is True
    assert report['receiver_actions'] == 0
    assert {case['case'] for case in report['results']} == {
        'windows_pinned_handshake_fresh_twice', 'windows_wrong_server_key_denied',
        'windows_wrong_client_key_denied', 'windows_mid_lease_revocation_denied',
        'windows_post_handshake_revision_change_denied'}
    assert all(case['passed'] is True for case in report['results'])
