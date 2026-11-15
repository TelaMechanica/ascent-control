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
 print(json.dumps({'platform':'Windows','python':sys.version.split()[0],'results':results,'receiver_actions':0,'fixture_only':True}))
