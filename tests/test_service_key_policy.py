"""Synthetic compatibility regressions; no conversion, credential or receiver I/O."""
import pytest
from ascent_core.service_access import AccessDenied
from ascent_core.service_key_policy import compatible_key_types, require_compatible_key_type, recommend_key_type


@pytest.mark.parametrize('name,firmware',[
 ('Ascent_G_Gnd','synthetic'),('Ascent_G_GND_fixture','synthetic'),
 ('Ascent_VRX','Ascent_G_Gnd_19_2_14'),('Ascent_VRX','Ascent_G_GND_fixture'),
])
def test_gnd_constraint_uses_name_and_firmware(name,firmware):
    assert compatible_key_types(name,firmware)==('ecdsa',)
    assert recommend_key_type(['ed25519','ecdsa'],name,firmware)=='ecdsa'
    assert recommend_key_type(['ed25519'],name,firmware) is None
    with pytest.raises(AccessDenied,match='ALGORITHM_INCOMPATIBLE'):
        require_compatible_key_type('ed25519',name,firmware)
    assert require_compatible_key_type('ecdsa',name,firmware)=='ecdsa'


def test_retained_ecdsa_preferred_without_destroying_explicit_choices():
    available=['ed25519','ecdsa']
    assert recommend_key_type(available)=='ecdsa'
    assert available==['ed25519','ecdsa']
    assert recommend_key_type(['ed25519'])=='ed25519'
    assert recommend_key_type([]) is None


@pytest.mark.parametrize('name,firmware',[(None,None),('synthetic','synthetic'),('Ascent_VRX','19.2.14')])
def test_unknown_compatibility_stays_unknown(name,firmware):
    assert compatible_key_types(name,firmware) is None
    assert require_compatible_key_type('ed25519',name,firmware)=='ed25519'


def test_unsupported_algorithm_refused():
    with pytest.raises(AccessDenied,match='TYPE_UNSUPPORTED'):
        require_compatible_key_type('rsa',None)


def test_controller_refuses_incompatible_key_before_loading_or_authenticating():
    from types import SimpleNamespace
    from ascent_core.service_receiver import ReceiverService, Observation
    import time
    target=SimpleNamespace(device_name='Ascent_VRX',firmware='Ascent_G_Gnd_19_2_14')
    class Selector:
        def check(self,current):assert current is target
    service=ReceiverService(selector=Selector(),
        credentials=lambda kind:pytest.fail('incompatible request must not load a key'),
        enrollments=None,transport=None,enabled=lambda:True)
    service._observations['synthetic-observation']=Observation(target,'unused','synthetic-pin',time.monotonic()+30)
    with pytest.raises(AccessDenied,match='ALGORITHM_INCOMPATIBLE'):
        service.verify('synthetic-observation','synthetic-pin',confirmed=True,key_type='ed25519')


def test_controller_checks_actual_key_not_only_declared_key_type():
    from types import SimpleNamespace
    from ascent_core.service_receiver import ReceiverService, Observation
    import time
    target=SimpleNamespace(device_name='Ascent_VRX',firmware='Ascent_G_Gnd_19_2_14')
    class Selector:
        def check(self,current):assert current is target
    class Vault:
        def load(self):return SimpleNamespace(public_key='ssh-ed25519 synthetic-placeholder')
    service=ReceiverService(selector=Selector(),credentials=lambda kind:Vault(),
        enrollments=None,transport=None,enabled=lambda:True)
    service._observations['synthetic-observation']=Observation(target,'unused','synthetic-pin',time.monotonic()+30)
    with pytest.raises(AccessDenied,match='ALGORITHM_INCOMPATIBLE'):
        service.verify('synthetic-observation','synthetic-pin',confirmed=True,key_type='ecdsa')


@pytest.mark.parametrize('public_key,error', [
    ('ssh-ed25519 synthetic-placeholder','CLIENT_KEY_ALGORITHM_MISMATCH'),
    ('ssh-rsa synthetic-placeholder','CLIENT_KEY_TYPE_UNSUPPORTED'),
    ('','CLIENT_KEY_TYPE_UNSUPPORTED'),
    (None,'CLIENT_KEY_TYPE_UNSUPPORTED'),
])
def test_unknown_platform_still_refuses_mislabeled_or_unsupported_material(public_key,error):
    from types import SimpleNamespace
    from ascent_core.service_receiver import ReceiverService, Observation
    import time
    target=SimpleNamespace(device_name='synthetic',firmware='synthetic')
    class Selector:
        def check(self,current):assert current is target
    class Vault:
        def load(self):return SimpleNamespace(public_key=public_key)
    class Enrollment:
        def lookup(self,*args):pytest.fail('invalid key reached enrollment records')
    service=ReceiverService(selector=Selector(),credentials=lambda kind:Vault(),
        enrollments=Enrollment(),transport=None,enabled=lambda:True)
    service._observations['synthetic-observation']=Observation(target,'unused','synthetic-pin',time.monotonic()+30)
    with pytest.raises(AccessDenied,match=error):
        service.verify('synthetic-observation','synthetic-pin',confirmed=True,key_type='ecdsa')
