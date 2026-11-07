"""Execute real ARM linkage instructions; libc interception must not hide bad entries."""
import struct
import sys
from pathlib import Path
import pytest
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm_const import UC_ARM_REG_R12, UC_ARM_REG_PC
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'firmware/mode_a'))
import fextent as fe


class PltFixture:
    plt_target = fe.Image.plt_target
    def __init__(self, thumb=False):
        self.label = 0x10000
        self.plt_labels = {'sprintf': self.label}
        # ADD ip,pc,#0x200000; ADD ip,ip,#0x9000; LDR pc,[ip,#0x570]!
        self.data = (b'\x78\x47\xfd\xe7' if thumb else b'') + struct.pack('<III', 0xe28fc602, 0xe28cca09, 0xe5bcf570)
    def off(self, address): return address - self.label
    def u32(self, address): return struct.unpack_from('<I', self.data, self.off(address))[0]


def execute(fixture, entry):
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    machine.mem_map(0x10000, 0x1000)
    machine.mem_write(0x10000, fixture.data)
    arm = fixture.label + (4 if fixture.data.startswith(b'\x78\x47') else 0)
    slot = arm + 8 + 0x200000 + 0x9000 + 0x570
    machine.mem_map(slot & ~0xfff, 0x1000)
    machine.mem_map(0x300000, 0x1000)
    machine.mem_write(slot, struct.pack('<I', 0x300000))
    machine.reg_write(UC_ARM_REG_R12, 0xdead0000)
    machine.emu_start(entry, 0x300000, count=8)
    return machine.reg_read(UC_ARM_REG_PC), machine.reg_read(UC_ARM_REG_R12), slot


@pytest.mark.parametrize('thumb', [False, True])
def test_actual_arm_stub_resolves_got_from_poisoned_ip(thumb):
    fixture = PltFixture(thumb)
    entry = fixture.plt_target('sprintf', to_arm=True)
    pc, ip, slot = execute(fixture, entry)
    assert pc == 0x300000 and ip == slot


def test_actual_thumb_veneer_switches_to_arm_before_resolution():
    fixture = PltFixture(True)
    pc, ip, slot = execute(fixture, fixture.plt_target('sprintf', to_arm=False) | 1)
    assert pc == 0x300000 and ip == slot


def test_skipped_arm_prefix_reproduces_invalid_access():
    fixture = PltFixture()
    with pytest.raises(UcError): execute(fixture, fixture.label + 4)


def test_arm_only_stub_cannot_be_used_as_thumb_entry():
    with pytest.raises(fe.ExtentError, match='no Thumb'): PltFixture().plt_target('sprintf', to_arm=False)


def test_unrecognized_plt_prefix_refuses():
    fixture = PltFixture(); fixture.data = bytes(12)
    with pytest.raises(fe.ExtentError, match='unsupported ARM'): fixture.plt_target('sprintf', to_arm=True)

@pytest.mark.parametrize('skipped', [False, True])
def test_tail_veneer_executes_arm_entry_without_hiding_skipped_prefix(skipped):
    fixture = PltFixture()
    target = fixture.label + (4 if skipped else 0)
    fixture.data += bytes(0x80 - len(fixture.data)) + b'\xdf\xf8\x00\xf0' + struct.pack('<I', target)
    if skipped:
        with pytest.raises(UcError): execute(fixture, 0x10081)
    else:
        pc, ip, slot = execute(fixture, 0x10081)
        assert pc == 0x300000 and ip == slot

@pytest.mark.parametrize('thumb', [False, True])
def test_real_builder_consumers_select_executable_arm_entry(thumb):
    import z40_build
    from types import SimpleNamespace
    fixture = PltFixture(thumb)
    builder = z40_build.Build.__new__(z40_build.Build)
    builder.N = fixture
    builder.H = SimpleNamespace(plt={0x20000: 'sprintf'})
    mapped = builder.map_call(0x20000, 'blx')
    for entry in (mapped[2], builder.plt_arm('sprintf')):
        pc, ip, slot = execute(fixture, entry)
        assert pc == 0x300000 and ip == slot

@pytest.mark.parametrize('writable', [False, True])
def test_emulator_enforces_emitted_elf_permissions(tmp_path, writable):
    import z40_build
    from emu import Emu, EmuError
    target = 0x20020 if writable else 0x10020
    code = z40_build.assemble(f'ldr r1, ={target:#x}\nmovs r0,#1\nstr r0,[r1]\nbx lr\n.ltorg\n', 0x10000, {}, name='permission_fixture')
    identity = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', identity, 2, 40, 1, 0x10001, 52, 0, 0x5000400, 52, 32, 2, 0, 0, 0)
    loads = struct.pack('<8I', 1, 0x1000, 0x10000, 0x10000, len(code), 0x1000, 5, 0x1000)
    loads += struct.pack('<8I', 1, 0x2000, 0x20000, 0x20000, 4, 0x1000, 6, 0x1000)
    data = bytearray(0x2004); data[:len(header)] = header; data[52:52+len(loads)] = loads
    data[0x1000:0x1000+len(code)] = code
    path = tmp_path/'permissions.elf'; path.write_bytes(data)
    machine = Emu(path, {})
    if writable:
        machine.call(0x10001)
        assert machine.u32(target) == 1
    else:
        with pytest.raises(EmuError, match='WRITE_PROT'): machine.call(0x10001)
