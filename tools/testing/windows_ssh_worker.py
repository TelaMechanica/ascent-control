"""Local disposable Windows parity worker; no output of identifiers or key paths."""
import sys,json,os,tempfile,shutil,subprocess
from pathlib import Path
from threading import RLock
config=json.loads(Path(sys.argv[1]).read_text())
sys.path.insert(0,config['source'])
from ascent_core.service_access import ServiceAccess,ServiceState,ReceiverBinding,AccessDenied
from ascent_core.service_records import HostKeyObservation,host_key_fingerprint
from ascent_core.service_loopback_ssh import LoopbackReadOnlySshBackend,LoopbackSshProbe
with tempfile.TemporaryDirectory(prefix='ascent-windows-ssh-') as folder:
 root=Path(folder)
 for name in ('client','wrong-client'):
  dest=root/name;shutil.copyfile(Path(config['fixture'])/name,dest)
  subprocess.run(['icacls',str(dest),'/inheritance:r','/grant:r',os.environ['USERNAME']+':(R)'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 binding=ReceiverBinding(1,'synthetic-receiver',f"loopback-fixture-{config['port']}")
 state=[ServiceState(True,True,binding)]
 public=(Path(config['fixture'])/'host.pub').read_text().strip()
 wrong=(Path(config['fixture'])/'wrong-host.pub').read_text().strip()
 record=[{'schema':'ascent.service-enrollment.v0','receiver_identity':binding.receiver_identity,'credential_revision':1,'host_key_sha256':host_key_fingerprint(public),'enrolled':True}]
 observation=[HostKeyObservation(binding,public)]
 ssh=Path(os.environ['SystemRoot'])/'System32/OpenSSH/ssh.exe'
 probe=LoopbackSshProbe(binding=binding,port=config['port'],username=config['username'],identity_file=root/'client',ssh_binary=ssh)
 backend=LoopbackReadOnlySshBackend(probe=probe,state=lambda:state[0],record_for=lambda identity:json.dumps(record[0]).encode(),observation_for=lambda selected:observation[0])
 access=ServiceAccess(state=lambda:state[0],backend=backend,operation_lock=RLock())
 results=[]
 with access.lease(binding) as lease:
  for _ in range(2):assert backend.verify_step(lease)['authenticated_transport'] is True
  results.append({'case':'windows_pinned_handshake_fresh_twice','passed':True})
 record[0]['host_key_sha256']=host_key_fingerprint(wrong);observation[0]=HostKeyObservation(binding,wrong)
 with access.lease(binding) as lease:
  try:backend.verify_step(lease)
  except AccessDenied as error:assert str(error)=='SSH_AUTHENTICATED_NOOP_FAILED'
  else:raise AssertionError('Impostor key accepted')
 results.append({'case':'windows_wrong_server_key_denied','passed':True})
 record[0]['host_key_sha256']=host_key_fingerprint(public);observation[0]=HostKeyObservation(binding,public);probe._identity_file=root/'wrong-client'
 with access.lease(binding) as lease:
  try:backend.verify_step(lease)
  except AccessDenied as error:assert str(error)=='SSH_AUTHENTICATED_NOOP_FAILED'
  else:raise AssertionError('Unauthorized client accepted')
 results.append({'case':'windows_wrong_client_key_denied','passed':True})
 probe._identity_file=root/'client'
 with access.lease(binding) as lease:
  backend.verify_step(lease);state[0]=ServiceState(False,False,binding)
  try:backend.verify_step(lease)
  except AccessDenied as error:assert str(error)=='SERVICE_MODE_UNAVAILABLE'
  else:raise AssertionError('Revocation ignored')
 results.append({'case':'windows_mid_lease_revocation_denied','passed':True})
 state[0]=ServiceState(True,True,binding)
 original=probe.noop
 def revision_change(*args):
  original(*args);record[0]['credential_revision']+=1
 probe.noop=revision_change
 with access.lease(binding) as lease:
  try:backend.verify_step(lease)
  except AccessDenied as error:assert str(error)=='ENROLLMENT_REVISION_CHANGED'
  else:raise AssertionError('Stale result accepted')
 results.append({'case':'windows_post_handshake_revision_change_denied','passed':True})
 assert backend._sessions=={}


# Isolated credential persistence proof. These are new synthetic keys in the
# worker's task-owned temporary directory, never installed operator credentials.
from ascent_core.service_credentials import CurrentUserDpapi, ProtectedCredentialStore, generate_windows_credential, CredentialError
with tempfile.TemporaryDirectory(prefix='ascent-protected-store-test-') as folder:
 vault=ProtectedCredentialStore(Path(folder)/'vault')
 status=generate_windows_credential(vault)
 assert status['credential_present'] is True and status['protection']=='dpapi-current-user'
 private=vault.load().private_key
 encrypted=(Path(folder)/'vault/credential.dpapi').read_bytes()
 assert private not in encrypted and b'BEGIN OPENSSH PRIVATE KEY' not in encrypted
 assert vault.load().private_key==private
 try: generate_windows_credential(vault)
 except CredentialError as error: assert str(error)=='CREDENTIAL_ALREADY_PRESENT'
 else: raise AssertionError('Existing credential replaced')
 assert (Path(folder)/'vault/credential.dpapi').read_bytes()==encrypted
 protector=CurrentUserDpapi()
 canary=b'synthetic-dpapi-canary'
 wrapped=protector.protect(canary)
 assert wrapped!=canary and protector.unprotect(wrapped)==canary
 try:protector.unprotect(b'not-a-dpapi-envelope')
 except CredentialError:pass
 else:raise AssertionError('Malformed DPAPI envelope accepted')


# Exercise the actual application HTTP backend in a new profile. No GUI launch,
# discovery request, receiver request or installed settings/credential access.
import socket,http.client,secrets,hmac,hashlib,time,ipaddress
with tempfile.TemporaryDirectory(prefix='ascent-local-app-test-') as folder:
 root=Path(folder)
 host=str(ipaddress.IPv4Address(0x7f000001))
 with socket.socket() as reserve:
  reserve.bind((host,0));port=reserve.getsockname()[1]
 token=secrets.token_hex(32)
 app_root=Path(config.get('app_root',config['source']))
 python=app_root/'pyembed/python.exe'
 if not python.is_file():python=Path(sys.executable)
 env=dict(os.environ)
 env.update(LOCALAPPDATA=str(root/'local-appdata'),APPDATA=str(root/'roaming-appdata'),
            USERPROFILE=str(root/'empty-profile'),ASCENT_HOST_SESSION_TOKEN=token)
 def request(method,path,body=None,authorized=False):
  connection=http.client.HTTPConnection(host,port,timeout=3)
  headers={'Content-Type':'application/json'}
  if authorized:headers['X-Ascent-Host-Token']=token
  connection.request(method,path,body=None if body is None else json.dumps(body),headers=headers)
  reply=connection.getresponse();data=json.loads(reply.read());status=reply.status
  connection.close();return status,data
 with (Path(sys.argv[1]).parent/'private-backend-child.log').open('wb') as log:
  child=subprocess.Popen([str(python),str(app_root/'runtime/dev_harness.py'),'--listen',host,
      '--port',str(port),'--no-browser'],env=env,stdin=subprocess.DEVNULL,
      stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
  try:
   for _ in range(80):
    assert child.poll() is None,'Isolated application backend exited before readiness'
    try:
     status,metadata=request('GET','/api/app')
     if status==200:break
    except OSError:pass
    time.sleep(.1)
   else:raise AssertionError('Isolated application backend readiness timeout')
   assert metadata['service_mode_available'] is False
   assert metadata['local_credential_preparation'] is True
   challenge=secrets.token_hex(32)
   status,proof=request('GET','/api/app/host-proof?challenge='+challenge)
   assert status==200 and proof['proof']==hmac.new(token.encode(),('ascent-host-proof:'+challenge).encode(),hashlib.sha256).hexdigest()
   assert token not in json.dumps(metadata)
   assert request('GET','/api/service-mode/local/status')[0]==403
   status,doc=request('GET','/api/service-mode/local/status',authorized=True)
   assert status==200 and doc['local_credential']['credential_present'] is False
   status,doc=request('POST','/api/service-mode/local/prepare',{'confirmed':True},authorized=True)
   assert status==200 and doc['local_credential']['credential_present'] is True
   assert doc['local_credential']['protection']=='dpapi-current-user'
   assert doc['receiver_access'] is False and doc['receiver_setup_available'] is False
   assert 'PRIVATE KEY' not in json.dumps(doc) and str(root) not in json.dumps(doc)
   assert request('POST','/api/service-mode/local/prepare',{'confirmed':True},authorized=True)[0]==409
   assert request('POST','/api/service-mode/activate',{'confirmed':True},authorized=True)[0]==405
   status,doc=request('GET','/api/service-mode/local/status',authorized=True)
   assert status==200 and doc['local_credential']['credential_present'] is True
   if config.get('app_root'):
    assert not any((app_root/'runtime').rglob('*.pyc'))
    assert not any((app_root/'ascent_core').rglob('*.pyc'))
  finally:
   if child.poll() is None:child.terminate();child.wait(timeout=5)
 print(json.dumps({'platform':'Windows','python':sys.version.split()[0],'results':results,
  'receiver_actions':0,'fixture_only':True,'installed_credentials_accessed':False,
  'credential_checks':{'real_dpapi_roundtrip':True,'malformed_envelope_denied':True,
   'generated_key_encrypted_at_rest':True,'existing_credential_preserved':True},
  'app_checks':{'backend_host_proof':True,'unauthorized_http_denied':True,
   'real_local_preparation':True,'existing_credential_preserved':True,'receiver_activation_unavailable':True},
  'packaged_backend':bool(config.get('app_root'))}))
