"""Actual Thumb control-flow analysis: cross-block callbacks must never disappear."""
import struct
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'firmware/mode_a'))
import fextent as fe
import z40_build as build
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

class ThumbFixture:
    def __init__(self, source, external=None):
        self.base=0x10000
        self.data=build.assemble(source,self.base,{'external':0x11001} if external else {},name='got_provenance_fixture')
        self.func_starts={self.base:'fixture'}
        self.plt={0x11000:external} if external else {}
        self.got=(0x20000,0x21000)
        self.md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);self.md.detail=True
    def off(self,address):return address-self.base
    def u32(self,address):return struct.unpack_from('<I',self.data,self.off(address))[0]
    def section_of(self,address):return '.text' if self.base<=address<self.base+len(self.data) else None
    def disasm1(self,address):return next(self.md.disasm(self.data[self.off(address):],address,count=1))

PREFIX='''push {r4,r6,lr}
ldr r6, .Lgot
.Lbase: add r6,pc
'''
SUFFIX='''pop {r4,r6,pc}
.align 2
.Lgot: .word 0x20000-0x10008
.Lindex: .word 0x900
.Lindex600: .word 0x600
.ltorg
'''

@pytest.mark.parametrize('branch',['cbz r0,.Luse','cmp r0,#0\nbeq .Luse','b .Luse'])
def test_callee_saved_got_base_survives_basic_block_boundary(branch):
    image=ThumbFixture(PREFIX+branch+'\nmovs r4,#1\n.Luse:\nldr r3,.Lindex\nldr r0,[r6,r3]\n'+SUFFIX)
    extent=fe.extent(image,image.base)
    assert [(offset,base) for _,_,offset,base in extent.gotloads]==[(0x900,0x20000)]

def test_ambiguous_got_base_refuses_instead_of_using_one_branch():
    source=PREFIX+'''cbz r0,.Luse
movs r6,#0
.Luse:
ldr r3,.Lindex
ldr r0,[r6,r3]
'''+SUFFIX
    with pytest.raises(fe.ExtentError,match='ambiguous GOT reference'):
        fe.extent(ThumbFixture(source),0x10000)

def test_register_copy_retains_got_provenance_across_branch():
    source=PREFIX+'''mov r4,r6
b .Luse
.Luse:
ldr r3,.Lindex600
ldr r0,[r4,r3]
'''+SUFFIX
    assert [x[2] for x in fe.extent(ThumbFixture(source),0x10000).gotloads]==[0x600]


def test_all_literal_alternatives_at_a_join_are_relocated():
    source=PREFIX+"""cbz r0,.Lother
ldr r3,.Lindex
b .Luse
.Lother: ldr r3,.Lindex600
.Luse: ldr r0,[r6,r3]
"""+SUFFIX
    assert sorted(x[2] for x in fe.extent(ThumbFixture(source),0x10000).gotloads)==[0x600,0x900]


def test_got_base_survives_an_ordinary_aapcs_call():
    source=PREFIX+'bl external\nb .Luse\n.Luse: ldr r3,.Lindex\nldr r0,[r6,r3]\n'+SUFFIX
    assert [x[2] for x in fe.extent(ThumbFixture(source,'puts'),0x10000).gotloads]==[0x900]


def test_noreturn_failure_path_cannot_pollute_a_later_join():
    source=PREFIX+"""mov r4,r6
cbz r0,.Luse
movs r4,#0
bl external
.Luse: ldr r3,.Lindex
ldr r0,[r4,r3]
"""+SUFFIX
    assert [x[2] for x in fe.extent(ThumbFixture(source,'__stack_chk_fail'),0x10000).gotloads]==[0x900]
