"""Local disposable Windows parity worker; no output of identifiers or key paths."""
import sys,json,os,tempfile,shutil,subprocess
from pathlib import Path
from threading import RLock
config=json.loads(Path(sys.argv[1]).read_text())
sys.path.insert(0,config['source'])
from ascent_core.service_access import ServiceAccess,ServiceState,ReceiverBinding,AccessDenied
from ascent_core.service_records import HostKeyObservation,host_key_fingerprint
from ascent_core.service_loopback_ssh import LoopbackReadOnlySshBackend,LoopbackSshProbe
# Test-only bounded diagnostics retained privately on a failed fixture call.
# Production clients continue to discard diagnostics. No receiver is contacted.
import ascent_core.service_loopback_ssh as fixture_transport
from threading import Thread
def fixture_run(args,environment):
 with subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
      stderr=subprocess.PIPE,env=environment,creationflags=subprocess.CREATE_NO_WINDOW) as process:
  diagnostic=bytearray()
  def drain():
   while True:
    chunk=process.stderr.read(4096)
    if not chunk:break
    diagnostic.extend(chunk[:max(0,8192-len(diagnostic))])
  reader=Thread(target=drain,daemon=True);reader.start()
  try:code=process.wait(timeout=5)
  except subprocess.TimeoutExpired:
   process.kill();process.wait();raise
  finally:reader.join(timeout=1)
  if code:
   (Path(config['fixture'])/'private-ssh-client.log').write_bytes(bytes(diagnostic))
  return code
fixture_transport._windows_run=fixture_run
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


# Qualify the new P-256 credential and receiver record codec with real DPAPI.
# These records are serialization fixtures, not evidence of receiver enrollment.
from ascent_core.service_enrollment import ProtectedEnrollments, ReceiverEnrollment
from ascent_core.windows_key_material import materialized_credential
with tempfile.TemporaryDirectory(prefix='ascent-p256-record-test-') as folder:
 root=Path(folder)
 vault=ProtectedCredentialStore(root/'p256')
 generate_windows_credential(vault,key_type='ecdsa')
 credential=vault.load()
 assert credential.public_key.startswith('ecdsa-sha2-nistp256 ')
 client_pin=host_key_fingerprint(credential.public_key)
 with materialized_credential(credential) as (identity,environment,tools):
  assert identity.read_bytes()==credential.private_key
  assert 'SSH_AUTH_SOCK' not in environment
 assert not identity.exists()
 enrollments=ProtectedEnrollments(root/'receivers')
 record=ReceiverEnrollment('synthetic-receiver',credential.public_key,client_pin)
 enrollments.save_new(record)
 assert enrollments.lookup('synthetic-receiver')==ReceiverEnrollment.decode(record.encode())
 before={p.name:p.read_bytes() for p in (root/'receivers').iterdir()}
 assert len(before)==1 and all(b'synthetic-receiver' not in data for data in before.values())
 enrollments.save_new(record)
 assert before=={p.name:p.read_bytes() for p in (root/'receivers').iterdir()}


# Exercise real Winsock interface/source pinning against our owned listener.
# Loopback qualification is not USB/NIC or physical receiver qualification.
import ctypes,socket,ipaddress
from types import SimpleNamespace
from ascent_core.service_channel import windows_source_socket
loopback=str(ipaddress.IPv4Address(0x7f000001))
index=ctypes.c_ulong()
api=ctypes.WinDLL('iphlpapi')
get_interface=api.GetBestInterface
get_interface.argtypes=[ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong)]
get_interface.restype=ctypes.c_ulong
assert get_interface(int.from_bytes(socket.inet_aton(loopback),'little'),ctypes.byref(index))==0
with socket.socket() as listener:
 listener.bind((loopback,0));listener.listen(1);listener.settimeout(2)
 fixture_port=listener.getsockname()[1]
 class FixtureSocket:
  def __init__(self,*args):self.stream=socket.socket(*args)
  def setsockopt(self,*args):return self.stream.setsockopt(*args)
  def bind(self,*args):return self.stream.bind(*args)
  def settimeout(self,*args):return self.stream.settimeout(*args)
  def connect(self,address):
   assert address==(loopback,22)
   self.stream.connect((loopback,fixture_port))
  def close(self):self.stream.close()
 selected=SimpleNamespace(interface_index=index.value,source_ip=loopback,host=loopback)
 stream=windows_source_socket(selected,lambda:None,socket_factory=FixtureSocket)
 try:
  peer,address=listener.accept()
  with peer:assert address[0]==loopback and stream.stream.getsockname()[0]==loopback
 finally:stream.close()


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
  'windows_loopback_source_binding':True,
  'receiver_storage_checks':{'p256_generated':True,'temporary_key_removed':True,'real_dpapi_record_roundtrip':True,'existing_record_preserved':True},
  'credential_checks':{'real_dpapi_roundtrip':True,'malformed_envelope_denied':True,
   'generated_key_encrypted_at_rest':True,'existing_credential_preserved':True},
  'app_checks':{'backend_host_proof':True,'unauthorized_http_denied':True,
   'real_local_preparation':True,'existing_credential_preserved':True,'receiver_activation_unavailable':True},
  'packaged_backend':bool(config.get('app_root'))}))
