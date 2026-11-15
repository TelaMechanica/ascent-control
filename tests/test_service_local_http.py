"""Actual HTTP handler guards local credential preparation; fixtures only."""
import http.client
import json
import sys
from pathlib import Path
from threading import Thread
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'runtime'))
import dev_harness as app

TOKEN = '7' * 64


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(app, '_HOST_SESSION_TOKEN', TOKEN)
    instance = app.AscentHTTPServer(('localhost', 0), app.Handler)
    thread = Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown(); instance.server_close(); thread.join(timeout=5)


def request(server, method, path, *, token=None, body=None, origin=None):
    connection = http.client.HTTPConnection('localhost', server.server_address[1], timeout=3)
    headers = {'Content-Type': 'application/json'}
    if token is not None: headers['X-Ascent-Host-Token'] = token
    if origin is not None: headers['Origin'] = origin
    connection.request(method, path, json.dumps(body) if body is not None else None, headers)
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result


@pytest.mark.parametrize('token', [None, '8'*64, 'bad', TOKEN + 'x'])
def test_native_client_without_host_secret_cannot_touch_store(server, monkeypatch, token):
    monkeypatch.setattr(app, '_host_credential_store', lambda: pytest.fail('unauthorized store access'))
    for method, path in [('GET', '/api/service-mode/local/status'), ('POST', '/api/service-mode/local/prepare')]:
        status, doc = request(server, method, path, token=token, body={'confirmed': True})
        assert status == 403 and doc['error'] == 'DESKTOP_HOST_SESSION_REQUIRED'


def test_confirmation_required_before_store_access(server, monkeypatch):
    monkeypatch.setattr(app, '_host_credential_store', lambda: pytest.fail('must not touch store'))
    status, doc = request(server, 'POST', '/api/service-mode/local/prepare', token=TOKEN, body={'confirmed': False})
    assert status == 409 and doc['error'] == 'LOCAL_PREPARATION_CONFIRMATION_REQUIRED'


def test_foreign_origin_with_token_still_refused(server, monkeypatch):
    monkeypatch.setattr(app, '_host_credential_store', lambda: pytest.fail('must not touch store'))
    assert request(server, 'POST', '/api/service-mode/local/prepare', token=TOKEN,
                   body={'confirmed': True}, origin='http://foreign.invalid')[0] == 403


def test_authorized_local_status_does_not_claim_receiver_access(server, monkeypatch):
    class Store:
        def status(self): return {'credential_present': False, 'receiver_access': False}
    monkeypatch.setattr(app, '_host_credential_store', Store)
    status, doc = request(server, 'GET', '/api/service-mode/local/status', token=TOKEN)
    assert status == 200 and doc['ok'] is True
    assert doc['receiver_access'] is False and doc['receiver_setup_available'] is False
    assert TOKEN not in json.dumps(doc)


def test_no_host_session_disables_even_matching_request(server, monkeypatch):
    monkeypatch.setattr(app, '_HOST_SESSION_TOKEN', '')
    monkeypatch.setattr(app, '_host_credential_store', lambda: pytest.fail('must not touch store'))
    assert request(server, 'GET', '/api/service-mode/local/status', token=TOKEN)[0] == 403


def test_host_proof_authenticates_backend_without_exposing_secret(server):
    import hmac, hashlib
    challenge = '9' * 64
    status, doc = request(server, 'GET', '/api/app/host-proof?challenge=' + challenge)
    assert status == 200
    assert doc == {'proof': hmac.new(TOKEN.encode(), ('ascent-host-proof:' + challenge).encode(), hashlib.sha256).hexdigest()}
    assert TOKEN not in json.dumps(doc)
    assert request(server, 'GET', '/api/app/host-proof?challenge=bad')[0] == 403


def test_settings_render_truth_and_escaping():
    import subprocess
    source = Path(__file__).resolve().parents[1]
    result = subprocess.run(['node', 'tests/service_local_preparation_render.cjs'], cwd=source, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_backend_disables_persistent_bytecode():
    # The actual packaged Windows workflow additionally checks the on-disk tree.
    assert app.sys.dont_write_bytecode is True
