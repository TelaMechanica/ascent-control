"""Real local HTTP traffic: refused requests never reach action handlers."""
import http.client
import threading
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import dev_harness as D

@pytest.fixture
def api(monkeypatch):
    calls=[]
    monkeypatch.setattr(D, 'max_ethernet_key', lambda body: calls.append(body) or {'ok':True})
    srv=D.AscentHTTPServer(('127.0.0.1',0),D.Handler)
    thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
    yield srv.server_port,calls
    srv.shutdown();srv.server_close();thread.join(2)

def request(api, method='POST', host=None, origin=None, site=None, duplicate=False):
    port,_=api
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
    conn.putrequest(method,'/api/network/max/key' if method=='POST' else '/api/app',skip_host=True)
    if host is not None:conn.putheader('Host',host.format(port=port))
    if duplicate:conn.putheader('Host',f'localhost:{port}')
    if origin is not None:conn.putheader('Origin',origin.format(port=port))
    if site is not None:conn.putheader('Sec-Fetch-Site',site)
    conn.putheader('Content-Length','2' if method=='POST' else '0');conn.endheaders()
    if method=='POST':conn.send(b'{}')
    response=conn.getresponse();status=response.status;response.read();conn.close();return status

@pytest.mark.parametrize('host,origin,site,duplicate',[
 ('attacker.invalid:{port}',None,None,False),
 ('127.0.0.1:1',None,None,False),
 (None,None,None,False),
 ('127.0.0.1:{port}','https://attacker.invalid',None,False),
 ('127.0.0.1:{port}','null',None,False),
 ('127.0.0.1:{port}','http://localhost:{port}',None,False),
 ('127.0.0.1:{port}','http://127.0.0.1:1',None,False),
 ('127.0.0.1:{port}',None,'cross-site',False),
 ('127.0.0.1:{port}',None,None,True),
 ('127.0.0.1:{port}/path',None,None,False),
])
def test_refused_before_action(api,host,origin,site,duplicate):
    assert request(api,host=host,origin=origin,site=site,duplicate=duplicate)==403
    assert api[1]==[]

@pytest.mark.parametrize('host,origin',[
 ('127.0.0.1:{port}',None),
 ('localhost:{port}',None),
 ('127.0.0.1:{port}','http://127.0.0.1:{port}'),
 ('localhost:{port}','http://localhost:{port}'),
])
def test_desktop_and_same_origin_allowed(api,host,origin):
    assert request(api,host=host,origin=origin)==200
    assert api[1]==[{}]

def test_get_is_also_guarded(api):
    assert request(api,method='GET',host='attacker.invalid:{port}')==403
    assert request(api,method='GET',host='127.0.0.1:{port}')==200
