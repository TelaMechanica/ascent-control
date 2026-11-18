"""Trusted startup, fixed folder ownership and real HTTP route refusal."""
import json
import http.client
import time
from pathlib import Path
import pytest
from test_service_local_http import app, server, request, TOKEN


def complete(instance):
    end = time.monotonic() + 2
    while time.monotonic() < end:
        doc = instance.widget_catalog_status()
        if doc and not doc['scan_in_progress']:
            return doc
        time.sleep(.005)
    pytest.fail('catalog did not finish')


def test_startup_is_explicit_idempotent_and_keeps_fixed_nonconfigurable_root(server, monkeypatch, tmp_path):
    first = tmp_path / 'first'
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: first)
    monkeypatch.setattr(app.local_settings, 'save_root', lambda: pytest.fail('configurable save root used'))
    assert server.widget_catalog_status() is None
    server.start_widget_catalog()
    doc = complete(server)
    assert doc['result']['status'] == 'FOLDER_MISSING' and not first.exists()
    assert server._catalog.folder == first / 'Widgets'
    generation = doc['generation']
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: tmp_path / 'other')
    server.start_widget_catalog()
    assert server.widget_catalog_status()['generation'] == generation
    assert server._catalog.folder == first / 'Widgets'
    assert str(tmp_path) not in json.dumps(doc) and TOKEN not in json.dumps(doc)


@pytest.mark.parametrize('method,path', [('GET', '/api/widgets/local/catalog'), ('POST', '/api/widgets/local/rescan'), ('POST', '/api/widgets/local/open-folder')])
@pytest.mark.parametrize('token', [None, '8' * 64, 'bad'])
def test_unauthorized_calls_cannot_reach_catalog(server, monkeypatch, method, path, token):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('unauthorized catalog'))
    code, body = request(server, method, path, token=token, body={})
    assert code == 403 and body['error'] == 'DESKTOP_HOST_SESSION_REQUIRED'


def test_absent_startup_is_not_implicitly_created_by_http(server, monkeypatch):
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: pytest.fail('request chose folder'))
    for method, path in [('GET', '/api/widgets/local/catalog'), ('POST', '/api/widgets/local/rescan')]:
        code, body = request(server, method, path, token=TOKEN, body={} if method == 'POST' else None)
        assert code == 503 and body['error'] == 'CATALOG_NOT_STARTED'


@pytest.mark.parametrize('path,body', [('/api/widgets/local/rescan', {'folder': 'synthetic-root'}),
                                     ('/api/widgets/local/rescan', {'confirmed': True}),
                                     ('/api/widgets/local/rescan?folder=synthetic-root', {}),
                                     ('/api/widgets/local/rescan', []),
                                     ('/api/widgets/local/catalog?folder=synthetic-root', None)])
def test_path_and_body_parameters_are_refused_before_catalog_access(server, monkeypatch, path, body):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('parameter reached catalog'))
    method = 'GET' if '/catalog?' in path else 'POST'
    code, result = request(server, method, path, token=TOKEN, body=body)
    assert code == 400 and result['error'] == 'INVALID_CATALOG_REQUEST'


def test_status_rescan_and_shutdown_do_not_touch_service_or_receiver(server, monkeypatch, tmp_path):
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: tmp_path)
    monkeypatch.setattr(app, '_host_credential_store', lambda: pytest.fail('catalog touched credentials'))
    monkeypatch.setattr(app, '_receiver_service', lambda: pytest.fail('catalog touched receiver'))
    server.start_widget_catalog()
    first = complete(server)
    code, doc = request(server, 'GET', '/api/widgets/local/catalog', token=TOKEN)
    assert code == 200 and doc['generation'] == first['generation']
    code, doc = request(server, 'POST', '/api/widgets/local/rescan', token=TOKEN, body={})
    assert code == 202 and doc['generation'] == first['generation'] + 1
    last = complete(server)
    assert last['result']['status'] == 'FOLDER_MISSING' and not (tmp_path / 'Widgets').exists()
    assert not last['registration_performed'] and not last['activation_performed']
    server.server_close()
    assert server.widget_catalog_status()['phase'] == 'CLOSED'
    assert server.start_widget_catalog() is None


@pytest.mark.parametrize('method,path', [('POST', '/api/widgets/local/catalog'), ('GET', '/api/widgets/local/rescan')])
def test_wrong_method_cannot_reach_catalog(server, monkeypatch, method, path):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('wrong method reached catalog'))
    assert request(server, method, path, token=TOKEN, body={})[0] == 405


def test_foreign_origin_cannot_reach_catalog_even_with_token(server, monkeypatch):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('foreign origin reached catalog'))
    assert request(server, 'POST', '/api/widgets/local/rescan', token=TOKEN, body={}, origin='https://widget.invalid')[0] == 403


def test_no_native_session_disables_startup(server, monkeypatch):
    monkeypatch.setattr(app, '_HOST_SESSION_TOKEN', '')
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: pytest.fail('untrusted startup'))
    assert server.start_widget_catalog() is None


def test_main_starts_catalog_and_closes_it_on_exit(monkeypatch):
    calls = []
    class OwnedServer:
        server_address = ('127.0.0.1', 40000)
        def __init__(self, *args): pass
        def start_widget_catalog(self): calls.append('start')
        def serve_forever(self): calls.append('serve'); raise KeyboardInterrupt
        def server_close(self): calls.append('close')
    monkeypatch.setattr(app, 'AscentHTTPServer', OwnedServer)
    monkeypatch.setattr(app.sys, 'argv', ['host', '--no-browser'])
    monkeypatch.setitem(app.SERVER_REF, 'server', None)
    app.main()
    assert calls == ['start', 'serve', 'close']


def test_boot_discovery_and_explicit_rescan_observe_only_current_package_metadata(server, monkeypatch, tmp_path):
    from test_widget_catalog import package, tree
    folder = tmp_path / 'Widgets'
    folder.mkdir()
    package(folder / 'fixture.zip', version='0.1.0', text='must not render this view')
    before = tree(folder)
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: tmp_path)
    server.start_widget_catalog()
    first = complete(server)
    assert tree(folder) == before
    assert first['result']['entries'][0]['package']['version'] == '0.1.0'
    assert 'must not render this view' not in json.dumps(first)
    package(folder / 'fixture.zip', version='0.2.0')
    assert server.widget_catalog_status()['result']['entries'][0]['package']['version'] == '0.1.0'
    assert request(server, 'POST', '/api/widgets/local/rescan', token=TOKEN, body={})[0] == 202
    latest = complete(server)
    assert latest['result']['entries'][0]['package']['version'] == '0.2.0'
    assert not latest['result']['entries'][0]['package']['executable']


def test_folder_open_action_uses_captured_root_and_schedules_observation(server, monkeypatch, tmp_path):
    import ascent_core.widget_catalog_host as host
    calls = []
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: tmp_path)
    monkeypatch.setattr(host, 'open_catalog_folder', lambda path: calls.append(path) or {'ok': True, 'open_requested': True})
    server.start_widget_catalog()
    generation = complete(server)['generation']
    monkeypatch.setattr(app.local_settings, 'config_root', lambda: tmp_path / 'other')
    code, result = request(server, 'POST', '/api/widgets/local/open-folder', token=TOKEN, body={'path': 'synthetic-other'})
    assert code == 400 and not calls
    code, result = request(server, 'POST', '/api/widgets/local/open-folder', token=TOKEN, body={})
    assert code == 200 and result == {'ok': True, 'open_requested': True}
    assert calls == [tmp_path / 'Widgets']
    assert complete(server)['generation'] == generation + 1
    assert request(server, 'GET', '/api/widgets/local/open-folder', token=TOKEN)[0] == 405
    assert str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize('method,path,body', [
    ('GET', '/api/widgets/local/catalog', {'folder': 'synthetic-other'}),
    ('POST', '/api/widgets/local/rescan', {'padding': 'x' * 100}),
    ('POST', '/api/widgets/local/open-folder', {'padding': 'x' * 100}),
])
def test_catalog_body_parameters_and_oversize_are_refused_before_adapters(server, monkeypatch, method, path, body):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('body reached catalog'))
    monkeypatch.setattr(server, 'open_widget_catalog_folder', lambda: pytest.fail('body reached opener'))
    assert request(server, method, path, token=TOKEN, body=body)[0] == 400


@pytest.mark.parametrize('header', ['duplicate-length', 'transfer-coding'])
def test_ambiguous_catalog_body_framing_is_refused_before_adapters(server, monkeypatch, header):
    monkeypatch.setattr(server, 'widget_catalog_status', lambda **kw: pytest.fail('framing reached catalog'))
    connection = http.client.HTTPConnection('localhost', server.server_address[1], timeout=3)
    connection.putrequest('POST', '/api/widgets/local/rescan')
    connection.putheader('X-Ascent-Host-Token', TOKEN)
    connection.putheader('Content-Length', '0')
    if header == 'duplicate-length':
        connection.putheader('Content-Length', '0')
    else:
        connection.putheader('Transfer-Encoding', 'chunked')
    connection.endheaders()
    response = connection.getresponse()
    assert response.status == 400
    assert json.loads(response.read())['error'] == 'INVALID_CATALOG_REQUEST'
    connection.close()
