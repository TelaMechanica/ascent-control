"""Offline execution gate for the two Hub config read paths; never opens a device."""
from emu import Emu, STACK_TOP
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_SP,
)
import fextent as FE
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM


def verify_config(hub, normal, output, report):
    """Check actual relocated call sites and execute actual output instructions.

    File availability and the original JSON loader are mocked at their ABI boundaries.
    Malformed/unreadable persistent documents must reach that loader and cannot be
    hidden by a successful packaged-seed fallback. This is software evidence only.
    """
    h, n = FE.Image(hub), FE.Image(normal)
    sym = {name: int(value, 16) for name, value in report['sym'].items()}
    wrapper = sym['hub_config_load'] & ~1
    out = FE.Image(output)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True
    redirects = []
    for name, spec in report['carried_functions'].items():
        original = int(spec['hub_entry'], 16) & ~1
        f = FE.extent(h, original)
        for site, target, kind in f.calls:
            if target is None or (target & ~1) != (h.syms['json_load_file'][0] & ~1):
                continue
            relocated = (sym[name] & ~1) + site - original
            ins = next(md.disasm(out.data[out.off(relocated):out.off(relocated) + 4], relocated))
            assert ins.mnemonic in ('bl', 'b.w', 'b') and ins.operands[0].type == ARM_OP_IMM
            assert (ins.operands[0].imm & ~1) == wrapper, (name, hex(site), ins.op_str)
            redirects.append(name)
    assert 'fpv_msp_rc_config_init' in redirects, redirects
    assert len(redirects) >= 2, redirects
    cases = []
    regs = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)
    for filename in ('msp_rc_cfg.json', 'mipi_hub.json'):
        for state, errno, loader_result in (
            ('present', 0, 0x60008000), ('missing', 2, 0x60009000),
            ('malformed', 0, 0), ('denied', 13, 0), ('io_error', 5, 0),
        ):
            seed, factory = '/usrdata/fpv/' + filename, '/factory/' + filename
            cases.append(_execute(output, n, wrapper, seed,
                                  seed if state == 'missing' else factory,
                                  errno, loader_result, regs, state))
    for path in ('/factory/fpv_config.json', '/factory/msp_rc_cfg.json',
                 '/usrdata/fpv/msp_rc_cfg.json.extra', '/usrdata/fpv/other.json'):
        cases.append(_execute(output, n, wrapper, path, path, None, 0x60008000,
                              regs, 'passthrough'))
    return {'PASS': True, 'redirected_callers': redirects, 'cases': cases,
            'hardware_qualification': 'NOT TESTED'}


def _execute(output, n, wrapper, path, expected, errno_value, result, regs, state):
    e = Emu(output, n.plt)
    errno_addr = e.alloc(4); e.w32(errno_addr, errno_value or 0)
    path_addr = e.alloc(len(path) + 1, path.encode() + b'\0')
    args = (path_addr, 260, e.alloc(200), 0x12345678)
    observed, probes = [], []
    old_libc = e._libc
    def libc(name):
        assert e.reg(UC_ARM_REG_SP) % 8 == 0
        if name == 'access':
            probes.append(e.cstr(e.reg(UC_ARM_REG_R0)).decode())
            assert errno_value is not None, 'passthrough must not probe the filesystem'
            assert probes[-1] == expected or state == 'missing'
            assert e.reg(UC_ARM_REG_R1) == 0
            return 0 if not errno_value else -1
        if name == '__errno_location':
            return errno_addr
        return old_libc(name)
    e._libc = libc
    saved = {r: 0xA5000000 + i for i, r in enumerate(regs)}
    for r, value in saved.items(): e.mu.reg_write(r, value)
    def loader(vm):
        observed.append(vm.cstr(vm.reg(UC_ARM_REG_R0)).decode())
        assert observed[-1] == expected
        assert tuple(vm.reg(r) for r in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)) == args[1:]
        assert vm.reg(UC_ARM_REG_SP) == STACK_TOP - 0x1000
        return result
    e.stubs[n.syms['json_load_file'][0] & ~1] = loader
    assert e.call(wrapper, *args, max_insn=500) == result
    assert len(observed) == 1
    assert all(e.reg(r) == value for r, value in saved.items())
    assert e.reg(UC_ARM_REG_SP) == STACK_TOP - 0x1000
    assert len(probes) == (0 if errno_value is None else 1)
    return {'path': path, 'state': state, 'loaded': observed[0], 'PASS': True}
