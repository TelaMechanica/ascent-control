"""Opt-in actual C# host probe with an owned executable; no installed app/state."""
import json
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_harness_compiles_the_actual_host_sources():
    import xml.etree.ElementTree as ET
    project = ROOT/'tools/testing/interpreter_probe/InterpreterProbe.csproj'
    includes = {entry.attrib['Include'] for entry in ET.parse(project).iter('Compile')}
    assert '../../../src/Ascent.Desktop/BackendHost.cs' in includes
    assert '../../../src/Ascent.Desktop/BoundedLogWriter.cs' in includes
    assert not list(ET.parse(project).iter('PackageReference'))


@pytest.mark.skipif(os.environ.get('ASCENT_TEST_WINDOWS_PROBE') != '1',
                    reason='Explicit owned Windows interpreter probe opt-in')
def test_actual_host_interpreter_probe_is_bounded():
    executable = Path(os.environ.get('ASCENT_WINDOWS_PROBE_EXE', 'missing'))
    assert executable.is_file() and executable.name == 'InterpreterProbe.exe'
    def win(path):
        return subprocess.check_output(['wslpath', '-w', str(path)], text=True).strip()
    shell = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        win(ROOT/'tools/testing/Test-InterpreterProbe.ps1'), '-ExecutablePath', win(executable)],
        capture_output=True, text=True, timeout=75)
    assert result.returncode == 0, 'Owned interpreter probe failed; retain local diagnostics privately'
    report = json.loads(result.stdout)
    assert report['hardware_access'] is False and report['installed_state_access'] is False
    assert {case['mode'] for case in report['cases']} == {'valid','old','invalid','stderr','stdout','hang'}
    assert all(case['passed'] and not case['watchdog_stopped'] for case in report['cases'])
    assert all(case['milliseconds'] < 7000 for case in report['cases'])
