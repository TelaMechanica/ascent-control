"""Regression for the actual Windows OpenSSH minimal-environment startup failure."""
from pathlib import PureWindowsPath
import pytest
from ascent_core.service_access import AccessDenied
from ascent_core.service_loopback_ssh import _environment


def test_windows_environment_uses_only_empty_owned_profile_roots(monkeypatch):
    monkeypatch.setenv('SSH_AUTH_SOCK', 'synthetic-agent')
    monkeypatch.setenv('SSH_ASKPASS', 'synthetic-helper')
    monkeypatch.setenv('USERPROFILE', 'synthetic-personal-profile')
    root = PureWindowsPath('C:/fixture-root')
    env = _environment(root, windows=True, system_root='C:/Windows')
    assert set(env) == {'LANG', 'LC_ALL', 'PATH', 'SystemRoot', 'ProgramData', 'USERPROFILE', 'TEMP', 'TMP'}
    assert all(env[name] == str(root) for name in ('ProgramData', 'USERPROFILE', 'TEMP', 'TMP'))
    assert env['PATH'] == str(PureWindowsPath('C:/Windows/System32'))
    assert not any('synthetic-' in value for value in env.values())


@pytest.mark.parametrize('system_root', [None, '', 'relative-root'])
def test_missing_windows_system_root_fails_closed(system_root):
    with pytest.raises(AccessDenied, match='WINDOWS_ENVIRONMENT_REQUIRED'):
        _environment(PureWindowsPath('C:/fixture-root'), windows=True, system_root=system_root)


def test_posix_environment_does_not_inherit_ambient_ssh_variables(monkeypatch):
    monkeypatch.setenv('SSH_AUTH_SOCK', 'synthetic-agent')
    monkeypatch.setenv('GIT_SSH_COMMAND', 'synthetic-helper')
    assert set(_environment(PureWindowsPath('C:/unused'), windows=False)) == {'LANG', 'LC_ALL', 'PATH'}


def test_windows_stderr_is_drained_without_retaining_diagnostics(monkeypatch):
    import io
    import subprocess
    from ascent_core.service_loopback_ssh import _windows_run
    captured = {}
    class Process:
        stderr = io.BytesIO(b'synthetic-sensitive-diagnostic')
        def __enter__(self): return self
        def __exit__(self, *args): self.stderr.close()
        def wait(self, timeout=None): return 0
    def launch(args, **kwargs):
        captured.update(kwargs)
        return Process()
    monkeypatch.setattr(subprocess, 'Popen', launch)
    assert _windows_run(['synthetic-ssh'], {'LANG': 'C'}) == 0
    assert captured['stderr'] == subprocess.PIPE
    assert captured['stdout'] == subprocess.DEVNULL
    assert 'shell' not in captured


def test_windows_timeout_kills_and_reaps_process(monkeypatch):
    import io
    import subprocess
    from ascent_core.service_loopback_ssh import _windows_run
    events = []
    class Process:
        stderr = io.BytesIO()
        def __enter__(self): return self
        def __exit__(self, *args): self.stderr.close()
        def wait(self, timeout=None):
            events.append(('wait', timeout))
            if timeout is not None: raise subprocess.TimeoutExpired('synthetic-ssh', timeout)
            return -1
        def kill(self): events.append(('kill',))
    monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: Process())
    with pytest.raises(subprocess.TimeoutExpired): _windows_run(['synthetic-ssh'], {})
    assert events == [('wait', 5), ('kill',), ('wait', None)]
