from pathlib import Path
import subprocess
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import caddx_hid as H
import hid_source
import hashlib
from test_hid_source_identity import connection,stream


def test_live_buttons_survive_poll_and_host_status():
    result=subprocess.run(['node','tests/public_live_interaction.cjs'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('product',['Contoso X1','contoso_x1','ContosoX1','Example Fabrikam','FABRIKAM Controller','Fabrikam'])
def test_restricted_controllers_refused_before_identity_change(product,monkeypatch):
    monkeypatch.setattr(hid_source,'_PRIVATE_CONTROLLER_FAMILIES',frozenset(hashlib.sha256(s.encode()).hexdigest() for s in ('contoso','fabrikam')))
    current=stream();current.source_event(connection())
    with pytest.raises(H.HidError) as error:current.source_event(connection('other',product=product))
    assert error.value.code=='HID_AC_PLUS_ONLY'
    assert current._hid_source['epoch']=='one'


@pytest.mark.parametrize('product',['EdgeTX Joystick','RadioMaster Boxer','TBS Tango 2','Generic gamepad'])
def test_public_controllers_remain_available(product):
    current=stream();assert current.source_event(connection(product=product)) is not False
    assert current.rc_source_status()['device_present']
