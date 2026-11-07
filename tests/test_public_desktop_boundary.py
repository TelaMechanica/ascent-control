"""Exercise the real public handler; no device transport or installation."""
import http.client
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import dev_harness as app


@pytest.fixture
def server():
    server=app.AscentHTTPServer(('127.0.0.1',0),app.Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    yield server
    server.shutdown();server.server_close();thread.join(timeout=5)


def request(server,method,path,body=None,headers=None):
    conn=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
    data=None if body is None else json.dumps(body)
    conn.request(method,path,body=data,headers={'Content-Type':'application/json',**(headers or {})})
    reply=conn.getresponse();result=(reply.status,json.loads(reply.read()))
    conn.close();return result


@pytest.mark.parametrize('path',[
    '/api/service-mode/activate','/api/device-service-mode','/api/widgets/runtime/install',
    '/api/widgets/manager/action','/api/picker/select','/api/receiver/restore',
    '/api/fcc','/api/relay/press','/api/netrunner/enable','/api/cot/receiver',
])
def test_private_operations_are_absent_from_both_verbs(server,path):
    assert request(server,'GET',path)[0]==404
    assert request(server,'POST',path,{'apply':True,'confirmed':True})[0]==405


def test_old_edition_override_and_stamp_do_not_enable_private_code(monkeypatch,tmp_path,server):
    monkeypatch.setenv('ASCENT_EDITION','industrial')
    (tmp_path/'ascent_edition.txt').write_text('industrial')
    monkeypatch.setattr(app,'ROOT',tmp_path)
    assert app._resolve_edition()=='consumer'
    status,doc=request(server,'GET','/api/app')
    assert status==200 and doc['edition']=='consumer' and doc['service_mode_available'] is False
    assert not hasattr(app,'service_mode_activate') and not hasattr(app,'_widget_runtime_session')


@pytest.mark.parametrize('origin',['http://example.invalid','null','http://127.0.0.1:1'])
def test_cross_site_post_refuses_before_any_setting_change(server,monkeypatch,origin):
    monkeypatch.setattr(app.local_settings,'set_auto_connect',lambda *_:pytest.fail('must not write'))
    status,doc=request(server,'POST','/api/settings/auto-connect',{'enabled':True},{'Origin':origin})
    assert status==403 and doc['error']=='LOCAL_ORIGIN_REQUIRED'


def test_same_origin_and_desktop_http_client_are_supported(server,monkeypatch):
    calls=[]
    monkeypatch.setattr(app.local_settings,'set_auto_connect',lambda value:calls.append(value) or {'auto_connect':value})
    origin='http://127.0.0.1:'+str(server.server_address[1])
    assert request(server,'POST','/api/settings/auto-connect',{'enabled':True},{'Origin':origin})[0]==200
    assert request(server,'POST','/api/settings/auto-connect',{'enabled':False})[0]==200
    assert calls==[True,False]


def test_foreign_host_header_is_refused(server):
    assert request(server,'GET','/api/app',headers={'Host':'example.invalid:'+str(server.server_address[1])})[0]==403


def test_public_ui_behavior_and_private_request_absence():
    result=subprocess.run(['node','tests/public_ui_render_check.cjs'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
