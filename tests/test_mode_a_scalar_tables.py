"""Packed calibration values must not become pointers merely by resembling addresses."""
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'firmware/mode_a'))
import z40_build as build


def fixture(section):
    instance=build.Build.__new__(build.Build)
    def section_of(address):
        if 0x100000 <= address < 0x110000:return '.text'
        return section
    instance.H=SimpleNamespace(section_of=section_of,syms={
        'g_sns_imx586_obj':(0x299f64,48,'STT_OBJECT'),
        'g_sns_farsight_obj':(0x29a924,48,'STT_OBJECT')})
    instance.report={'relocations':[],'refused':[]}
    instance.map_data=lambda value,user:('fptr',value+0x100000)
    return instance


@pytest.mark.parametrize('value',[0x230001,0x1f0018,0x240600,0x281914,0x1a001e,0x23001e,0x2d0028])
def test_real_relocator_preserves_address_shaped_scalar_tables(value):
    instance=fixture('.rodata');data=struct.pack('<II',value,value)
    assert instance.relocate_words(data,0x238c28,'calibration',destination=0x2b0000)==data
    assert not instance.report['relocations']


def test_mode_table_numeric_clock_value_is_not_a_string_pointer():
    instance=fixture('.data.rel.ro');data=struct.pack('<I',0x1b5480)
    assert instance.relocate_words(data,0x290524,'mode',destination=0x2b0000)==data


def test_sensor_scalar_pairs_preserved_while_callback_fields_relocated():
    instance=fixture('.data');base=0x2995e0;data=bytearray(0x9c8)
    struct.pack_into('<II',data,0x170,0x23001e,0x2d0028)
    field=0x299f64-base;struct.pack_into('<I',data,field,0x100dc9)
    result=instance.relocate_words(data,base,'sensor',destination=0x2a8c80)
    assert result[0x170:0x178]==data[0x170:0x178]
    assert struct.unpack_from('<I',result,field)[0]==0x200dc9
    assert len(instance.report['relocations'])==1


def test_sensor_callback_slot_with_numeric_data_refuses():
    instance=fixture('.data')
    with pytest.raises(build.BuildError,match='non-callback'):
        instance.relocate_words(struct.pack('<I',0x230001),0x299f64,'bad_callback',destination=0x2a8c80)


def test_scalar_table_requires_emitted_destination_evidence():
    with pytest.raises(build.BuildError,match='destination proof'):
        fixture('.rodata').relocate_words(bytes(16),0x238c28,'missing')


def test_unrelated_pointer_record_retains_existing_relocation():
    instance=fixture('.data.rel.ro')
    result=instance.relocate_words(struct.pack('<I',0x100dc9),0x29012c,'named_mode',destination=0x2a8c80)
    assert struct.unpack('<I',result)[0]==0x200dc9


def test_independent_emitted_table_gate_rejects_scalar_corruption(monkeypatch):
    import fextent
    from emu import scalar_sensor_data_preservation, EmuError
    original=struct.pack('<I',0x230001)
    images={'vendor':SimpleNamespace(data=original,off=lambda address:0),
            'mutant':SimpleNamespace(data=struct.pack('<I',0x2c7b8c),off=lambda address:0)}
    monkeypatch.setattr(fextent,'Image',lambda path:images[path])
    report={'scalar_tables_preserved':[{'source':'0x23fb0c','destination':'0x2c0000','bytes':4}],
            'sensor_data_images':[{}]}
    with pytest.raises(EmuError,match='scalar ISP table was rewritten'):
        scalar_sensor_data_preservation('vendor','mutant',report)


def test_hub_real_carry_closure_analyzes_named_sensor_helper(monkeypatch):
    import hub_build
    for name in ('HUB_LAYER','HUB_GLUE','REDIRECT_FUNCS','CARRY_EXTRA'):
        monkeypatch.setattr(hub_build,name,[])
    sensor=hub_build.SENSOR_UNIT[0]+0x100
    image=SimpleNamespace(
        syms={'main':(0x60001,4,'STT_FUNC'),
              'g_sns_imx586_obj':(0,48,'STT_OBJECT'),
              'g_sns_farsight_obj':(0,48,'STT_OBJECT')},
        data=bytes(48),off=lambda address:0,
        func_starts={0x60000:'main',sensor:'named_sensor_helper'},
        section_of=lambda address:'.text',
        elf=SimpleNamespace(get_section_by_name=lambda name:{'sh_addr':0x50000,'sh_size':0x200000}))
    instance=hub_build.HubBuild.__new__(hub_build.HubBuild);instance.H=image
    instance._extent=lambda entry:SimpleNamespace(entry=entry,pic=[],calls=[(entry,sensor|1,'BL')] if entry==0x60000 else [])
    functions=instance.carry_functions()
    assert 'named_sensor_helper' in functions
    assert functions['named_sensor_helper'].entry==sensor
