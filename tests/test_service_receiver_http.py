"""Actual HTTP routing and shared operation guard; trusted controller double only."""
import pytest
from test_service_local_http import app, server, request, TOKEN


@pytest.mark.parametrize('action', ['inspect', 'verify'])
def test_receiver_endpoint_denies_without_host_session(server,monkeypatch,action):
    monkeypatch.setattr(app,'_receiver_service',lambda:pytest.fail('must not construct controller'))
    status,doc=request(server,'POST','/api/service-mode/local/receiver/'+action,body={})
    assert status==403 and doc['error']=='DESKTOP_HOST_SESSION_REQUIRED'


@pytest.mark.parametrize('body', [{'host':'synthetic.invalid'}, {'command':'true'}, {'key_path':'synthetic'}])
def test_request_cannot_select_endpoint_command_or_key_path(server,monkeypatch,body):
    monkeypatch.setattr(app,'_receiver_service',lambda:pytest.fail('must reject before controller'))
    status,doc=request(server,'POST','/api/service-mode/local/receiver/inspect',token=TOKEN,body=body)
    assert status==409 and doc['error']=='INVALID_SERVICE_REQUEST'


def test_receiver_readiness_respects_existing_operation_lock(server,monkeypatch):
    monkeypatch.setattr(app,'_receiver_service',lambda:pytest.fail('busy must not construct controller'))
    assert app.DEVICE_MUTATION_LOCK.acquire(blocking=False)
    try:
        status,doc=request(server,'POST','/api/service-mode/local/receiver/inspect',token=TOKEN,body={})
        assert status==409 and doc['error']=='DEVICE_BUSY'
    finally:app.DEVICE_MUTATION_LOCK.release()


def test_observation_route_is_explicit_and_not_authentication(server,monkeypatch):
    class Controller:
        def inspect(self):return {'ssh_authenticated':False,'initial_access_available':False}
    monkeypatch.setattr(app,'_receiver_service',Controller)
    status,doc=request(server,'POST','/api/service-mode/local/receiver/inspect',token=TOKEN,body={})
    assert status==200 and doc=={'ok':True,'ssh_authenticated':False,'initial_access_available':False}
    assert app.DEVICE_MUTATION_LOCK.acquire(blocking=False)
    app.DEVICE_MUTATION_LOCK.release()


@pytest.mark.parametrize('body', [
 {'action':'prepare','key_type':'ecdsa','confirmed':False},
 {'action':'status','key_type':'rsa','confirmed':False},
 {'action':'prepare','key_type':'ecdsa','confirmed':True,'path':'synthetic'},
])
def test_credential_requests_cannot_replace_consent_or_fixed_store_policy(server,monkeypatch,body):
    monkeypatch.setattr(app,'_selected_service_credential',lambda kind:pytest.fail('invalid request must not open store'))
    status,doc=request(server,'POST','/api/service-mode/local/credential',token=TOKEN,body=body)
    assert status==409 and doc['ok'] is False


def test_credential_request_requires_host_session(server,monkeypatch):
    monkeypatch.setattr(app,'_selected_service_credential',lambda kind:pytest.fail('unauthorized store access'))
    status,doc=request(server,'POST','/api/service-mode/local/credential',body={'action':'status','key_type':'ed25519','confirmed':False})
    assert status==403
