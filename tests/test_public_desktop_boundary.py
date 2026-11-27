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
    # Retired edition tokens (consumer/industrial) no longer resolve to anything;
    # both the env override and the install-root stamp fail safe to AC, which does
    # not expose Service Mode. Enabling it requires a deliberate 'acplus' stamp.
    monkeypatch.setenv('ASCENT_EDITION','industrial')
    (tmp_path/'ascent_edition.txt').write_text('industrial')
    monkeypatch.setattr(app,'ROOT',tmp_path/'runtime')
    assert app._resolve_edition()=='ac'
    status,doc=request(server,'GET','/api/app')
    assert status==200 and doc['edition']=='ac' and doc['service_mode_available'] is False
    assert not hasattr(app,'service_mode_activate') and not hasattr(app,'_widget_runtime_session')


def test_installed_stamp_wins_over_inherited_environment_override(monkeypatch,tmp_path):
    # Edition is product configuration: an installed AC copy must stay AC even if
    # the environment inherits ASCENT_EDITION=acplus. The install-root stamp is the
    # product identity and wins; the env override only resolves an UNSTAMPED build.
    monkeypatch.setattr(app,'ROOT',tmp_path/'runtime')
    monkeypatch.setenv('ASCENT_EDITION','acplus')
    (tmp_path/'ascent_edition.txt').write_text('ac')
    assert app._resolve_edition()=='ac'            # stamp beats the ambient override
    (tmp_path/'ascent_edition.txt').write_text('acplus')
    assert app._resolve_edition()=='acplus'        # an acplus stamp is deliberate
    (tmp_path/'ascent_edition.txt').unlink()
    assert app._resolve_edition()=='acplus'         # only an UNSTAMPED build honours env
    monkeypatch.delenv('ASCENT_EDITION',raising=False)
    assert app._resolve_edition()=='ac'             # unstamped + no env => AC fail-safe


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


def test_netrunner_widget_install_requires_native_host_and_explicit_confirmation(server, monkeypatch):
    token = 'a' * 64
    monkeypatch.setattr(app, '_HOST_SESSION_TOKEN', token)
    calls = []

    class Receiver:
        def apply_netrunner_widget_action(self, **kwargs):
            calls.append(kwargs)
            return 'synthetic-transaction'

    monkeypatch.setattr(app, '_receiver_service', lambda: Receiver())
    path = '/api/widgets/manager/action'
    body = {'widget_id': 'netrunner', 'action': 'install', 'confirm': True,
            'expected_target': {'serial_number': '1234'}}
    headers = {'X-Ascent-Host-Token': token}
    assert request(server, 'POST', path, body)[0] == 403
    assert request(server, 'POST', path, {**body, 'confirm': False}, headers)[0] == 409
    assert request(server, 'POST', path + '?path=alternate', body, headers)[0] == 409
    assert not calls
    status, result = request(server, 'POST', path, body, headers)
    assert status == 200 and result['transaction_id'] == 'synthetic-transaction'
    assert calls[0]['reviewed_target'] == body['expected_target']
    assert calls[0]['release_pins']['netrunner-pro-2.10.1']['profile'] == 'pro-18.21.10'


def test_msi_uses_shared_lineage_and_migrates_separate_plus():
    from xml.etree import ElementTree

    ns = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
    package = ElementTree.parse(ROOT / "installer" / "AscentControl.wxs").find("wix:Package", ns)
    assert package.attrib["Name"] == "Ascent Control"
    assert package.attrib["UpgradeCode"] == "353ECEAF-B574-563B-9587-39464C4F0131"
    major = package.find("wix:MajorUpgrade", ns)
    assert major.attrib["Schedule"] == "afterInstallInitialize"
    assert major.attrib["AllowSameVersionUpgrades"] == "yes"
    legacy = package.find("wix:Upgrade", ns)
    assert legacy.attrib["Id"] == "95810E93-1BC3-5750-9CC8-99249572FC78"
    rows = legacy.findall("wix:UpgradeVersion", ns)
    assert rows[0].attrib["IncludeMaximum"] == "yes"
    assert rows[1].attrib["OnlyDetect"] == "yes"
