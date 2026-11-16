"""P-256 representation checks and independent OpenSSH interoperability."""
import base64
import hashlib
import shutil
import struct
import subprocess
import pytest
from ascent_core.service_access import AccessDenied
from ascent_core.service_records import host_key_fingerprint


def packet(*parts): return b''.join(struct.pack('>I', len(part)) + part for part in parts)


def key_for(point):
    raw = packet(b'ecdsa-sha2-nistp256', b'nistp256', point)
    return 'ecdsa-sha2-nistp256 ' + base64.b64encode(raw).decode()


def test_actual_generated_p256_key_matches_openssh(tmp_path):
    keygen = shutil.which('ssh-keygen'); assert keygen
    path = tmp_path/'synthetic'
    subprocess.run([keygen, '-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-C', 'synthetic-fixture', '-f', str(path)], check=True)
    public = path.with_suffix('.pub').read_text().strip()
    actual = subprocess.run([keygen, '-l', '-E', 'sha256', '-f', str(path.with_suffix('.pub'))], capture_output=True, text=True, check=True)
    assert host_key_fingerprint(public) == actual.stdout.split()[1]


@pytest.mark.parametrize('point', [b'', b'\x04'+bytes(63), b'\x03'+bytes(64), b'\x04'+bytes(64), b'\x04'+b'\xff'*64])
def test_invalid_curve_points_refused(point):
    with pytest.raises(AccessDenied, match='INVALID'): host_key_fingerprint(key_for(point))


def test_wrong_curve_and_trailing_data_refused(tmp_path):
    keygen = shutil.which('ssh-keygen'); assert keygen
    path = tmp_path/'synthetic'
    subprocess.run([keygen, '-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-C', 'synthetic-fixture', '-f', str(path)], check=True)
    public = path.with_suffix('.pub').read_text().split()
    raw = base64.b64decode(public[1])
    for changed in (raw+b'x', raw.replace(b'nistp256', b'nistp384')):
        with pytest.raises(AccessDenied): host_key_fingerprint(public[0]+' '+base64.b64encode(changed).decode())
