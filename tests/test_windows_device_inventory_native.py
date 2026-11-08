"""Native inventory preserves exact PnP/network correlation and refuses ambiguity."""
import sys,copy
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import windows_device_inventory as W


def rows():
    return ([{'known':True,'PNPClass':'Ports','Name':'USB Serial Device (COM10)','PNPDeviceID':'USB\\VID_1D77&PID_A4A2&MI_02','ContainerId':'cid'},
             {'known':True,'PNPClass':'Net','Name':'Remote NDIS','PNPDeviceID':'USB\\VID_1D77&PID_A4A2&MI_00','ContainerId':'cid','adapter_id':'guid'}],
            {'guid':{'Name':'Ethernet4','ifIndex':34,'Status':'Up','IPv4':[{'IPAddress':'192.168.3.103','PrefixLength':24,'AddressState':4}]}})


def test_native_join_carries_observed_container_and_actual_interface():
    pnp,adapters=rows();result=W.merge(pnp,adapters)
    assert len(result['usb'])==2 and len(result['network'])==1
    net=result['network'][0]
    assert net['ContainerId']=='cid'and net['ifIndex']==34 and net['IPv4']==adapters['guid']['IPv4']
    assert all('known'not in row and'adapter_id'not in row for row in result['usb'])


def test_missing_or_duplicate_network_guid_is_never_guessed():
    pnp,adapters=rows();wrong=copy.deepcopy(pnp);wrong[1]['adapter_id']='other'
    with pytest.raises(W.NativeInventoryError,match='no current'):W.merge(wrong,adapters)
    pnp.append({**pnp[1],'ContainerId':'another device'})
    with pytest.raises(W.NativeInventoryError,match='Two device nodes'):W.merge(pnp,adapters)


def test_absent_container_remains_absent_instead_of_inferred_from_usb():
    pnp,adapters=rows();pnp[1]['ContainerId']=None
    assert W.merge(pnp,adapters)['network'][0]['ContainerId']is None


def test_non_windows_native_entry_is_explicitly_unavailable():
    if W.os.name=='nt':pytest.skip('Windows API is available on Windows')
    with pytest.raises(W.NativeInventoryUnavailable):W.collect('VID_1D77')
