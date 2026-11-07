"""Minimal Unicorn harness for an ARM ET_EXEC: maps PT_LOAD segments, intercepts PLT calls
with a tiny Python libc, and lets a test call a Thumb function and inspect memory.

Only what the Z40 verification needs. Every PLT call it does not implement is a hard error,
so a test can never silently skip behaviour.
"""
from __future__ import annotations

import io
from pathlib import Path

import struct

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm_const import *

STACK_TOP = 0x7f000000
HEAP = 0x60000000
SENTINEL = 0x7e000000
FILEBASE = 0x5f000000


class EmuError(RuntimeError):
    pass


class Emu:
    def __init__(self, path, plt: dict):
        self.data = Path(path).read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        # enable VFP/NEON (CPACR + FPEXC)
        self.mu.reg_write(UC_ARM_REG_C1_C0_2, self.mu.reg_read(UC_ARM_REG_C1_C0_2) | (0xF << 20))
        self.mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        mapped = []
        for s in self.elf.iter_segments():
            if s["p_type"] != "PT_LOAD":
                continue
            lo, hi = s["p_vaddr"] & ~0xFFF, (s["p_vaddr"] + s["p_memsz"] + 0xFFF) & ~0xFFF
            for a, b in mapped:
                if lo < b and hi > a:
                    lo = max(lo, b)
            if hi > lo:
                self.mu.mem_map(lo, hi - lo)
                mapped.append((lo, hi))
            self.mu.mem_write(s["p_vaddr"], self.data[s["p_offset"]:s["p_offset"] + s["p_filesz"]])
        self.mu.mem_map(STACK_TOP - 0x200000, 0x200000)
        self.mu.mem_map(HEAP, 0x1000000)
        self.mu.mem_map(SENTINEL, 0x1000)
        self.mu.mem_map(FILEBASE, 0x10000)
        self.mu.mem_write(SENTINEL, b"\x00\xbf" * 8)
        self.heap = HEAP
        self.plt = plt                        # ARM entry addr -> name (and Thumb stub addr -> name)
        self.log = []                         # (name, args...) for every PLT call
        self.files = {}                       # fake FILE* -> path
        self.writes = []                      # (path, data)
        self.stubs = {}                       # addr -> python callable(emu) -> r0 (non-PLT functions)
        self.stop_at = set()
        # apply data relocations the dynamic linker would perform (GLOB_DAT / ABS32 to
        # undefined symbols such as __stack_chk_guard, stderr): point them at fake storage
        rel = self.elf.get_section_by_name(".rel.dyn")
        dyn = self.elf.get_section_by_name(".dynsym")
        self.dynvars = {}
        if rel:
            for r in rel.iter_relocations():
                sym = dyn.get_symbol(r["r_info_sym"])
                if r["r_info_type"] in (21, 2) and sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                    if sym.name not in self.dynvars:
                        self.dynvars[sym.name] = self.alloc(64, (b"\x5a\xa5\x3c\xc3" if "guard" in sym.name else b"") + b"\0" * 60)
                    self.mu.mem_write(r["r_offset"], struct.pack("<I", self.dynvars[sym.name]))
        # Match ELF segment permissions for CPU accesses. Direct mem_write remains
        # available to explicitly modeled loaders/mutations, not executing code.
        for segment in self.elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            lo = segment['p_vaddr'] & ~0xfff
            hi = (segment['p_vaddr'] + segment['p_memsz'] + 0xfff) & ~0xfff
            flags = segment['p_flags']
            permissions = ((UC_PROT_READ if flags & 4 else 0) |
                           (UC_PROT_WRITE if flags & 2 else 0) |
                           (UC_PROT_EXEC if flags & 1 else 0))
            self.mu.mem_protect(lo, hi - lo, permissions)
        self.mu.hook_add(UC_HOOK_CODE, self._code)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.fault = None

    # memory helpers ---------------------------------------------------------------
    def alloc(self, n, init=b""):
        a = (self.heap + 15) & ~15
        self.heap = a + max(n, len(init), 1)
        if init:
            self.mu.mem_write(a, init)
        return a

    def cstr(self, a, n=512):
        b = bytes(self.mu.mem_read(a, n))
        return b.split(b"\0")[0]

    def u32(self, a):
        return struct.unpack("<I", self.mu.mem_read(a, 4))[0]

    def w32(self, a, v):
        self.mu.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))

    def reg(self, r):
        return self.mu.reg_read(r)

    # libc ------------------------------------------------------------------------
    def _fmt(self, fmt, args):
        out, i, ai = b"", 0, 0
        while i < len(fmt):
            c = fmt[i:i + 1]
            if c != b"%":
                out += c
                i += 1
                continue
            j = i + 1
            while fmt[j:j + 1] in b"-+ #0123456789.lhz":
                j += 1
            conv = fmt[j:j + 1]
            spec = fmt[i:j + 1].replace(b"l", b"").replace(b"h", b"").replace(b"z", b"")
            if conv == b"%":
                out += b"%"
            elif conv == b"s":
                out += self.cstr(args[ai]); ai += 1
            elif conv in b"diuxXc":
                v = args[ai]; ai += 1
                if conv in b"di" and v >= 0x80000000:
                    v -= 1 << 32
                out += (spec.decode() % v).encode() if conv != b"c" else bytes([v & 0xFF])
            elif conv in b"fF":
                out += b"<f>"; ai += 2
            else:
                out += b"<?>"; ai += 1
            i = j + 1
        return out

    def _args(self, n):
        regs = [self.reg(UC_ARM_REG_R0), self.reg(UC_ARM_REG_R1), self.reg(UC_ARM_REG_R2), self.reg(UC_ARM_REG_R3)]
        sp = self.reg(UC_ARM_REG_SP)
        return regs + [self.u32(sp + 4 * k) for k in range(max(0, n - 4))]

    def _libc(self, name):
        a = self._args(12)
        if name in ("strcmp",):
            x, y = self.cstr(a[0]), self.cstr(a[1])
            return (x > y) - (x < y)
        if name == "strlen":
            return len(self.cstr(a[0], 4096))
        if name == "strcpy":
            self.mu.mem_write(a[0], self.cstr(a[1]) + b"\0"); return a[0]
        if name == "memcpy":
            self.mu.mem_write(a[0], bytes(self.mu.mem_read(a[1], a[2]))); return a[0]
        if name == "memset":
            self.mu.mem_write(a[0], bytes([a[1] & 0xFF]) * a[2]); return a[0]
        if name == "memcmp":
            x, y = bytes(self.mu.mem_read(a[0], a[2])), bytes(self.mu.mem_read(a[1], a[2]))
            return (x > y) - (x < y)
        if name in ("sprintf",):
            s = self._fmt(self.cstr(a[1]), a[2:])
            self.mu.mem_write(a[0], s + b"\0"); return len(s)
        if name in ("vsnprintf", "vsprintf"):
            buf, fmt_a, ap = (a[0], a[2], a[3]) if name == "vsnprintf" else (a[0], a[1], a[2])
            out = self._fmt(self.cstr(fmt_a), [self.u32(ap + 4 * k) for k in range(16)])
            if name == "vsnprintf":
                out = out[:max(0, a[1] - 1)] if a[1] else b""
            if buf and (name != "vsnprintf" or a[1]):
                self.mu.mem_write(buf, out + b"\0")
            return len(out)
        if name in ("printf",):
            self.log.append(("printf", self._fmt(self.cstr(a[0]), a[1:]))); return 0
        if name in ("puts", "perror"):
            self.log.append((name, self.cstr(a[0]))); return 0
        if name in ("usleep", "system", "access"):
            self.log.append((name, a[0] if name == "usleep" else self.cstr(a[0])))
            return 0 if name != "access" else self.access_result(self.cstr(a[0]))
        if name == "fopen":
            p = self.cstr(a[0])
            f = FILEBASE + 16 * (len(self.files) + 1)
            self.files[f] = p
            self.log.append(("fopen", p, self.cstr(a[1])))
            return f if self.fopen_ok(p) else 0
        if name in ("fputs",):
            self.writes.append((self.files.get(a[1]), self.cstr(a[0]))); return 0
        if name == "fprintf":
            self.writes.append((self.files.get(a[0]), self._fmt(self.cstr(a[1]), a[2:]))); return 0
        if name == "fclose":
            return 0
        if name in ("malloc", "calloc"):
            n = a[0] if name == "malloc" else a[0] * a[1]
            return self.alloc(n, b"\0" * n)
        if name == "__errno_location":
            if not hasattr(self, "errno_cell"):
                self.errno_cell = self.alloc(4, struct.pack("<I", 2))   # ENOENT after a failed fopen
            return self.errno_cell
        if name == "strerror":
            return self.alloc(32, b"No such file or directory\0")
        if name == "free":
            return 0
        if name == "__stack_chk_fail":
            raise EmuError("stack protector fired")
        raise EmuError(f"unimplemented PLT call {name}")

    def access_result(self, path):
        return 0

    def fopen_ok(self, path):
        return True

    # hooks -----------------------------------------------------------------------
    def _ret(self, r0):
        lr = self.reg(UC_ARM_REG_LR)
        self.mu.reg_write(UC_ARM_REG_R0, r0 & 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_PC, lr)          # lr carries the Thumb bit when needed

    def _code(self, uc, addr, size, _):
        if addr in self.stop_at or addr == SENTINEL:
            uc.emu_stop()
            return
        if addr in self.plt:
            thumb_entry = bytes(uc.mem_read(addr, 4)) == b'\x78\x47\xfd\xe7'
            if bool(self.reg(UC_ARM_REG_CPSR) & 0x20) != thumb_entry:
                raise EmuError(f'wrong instruction mode at PLT entry {addr:#x}')
            name = self.plt[addr]
            self.log.append(("call", name))
            r0 = self._libc(name)
            self._ret(r0)
            return
        if addr in self.stubs:
            r0 = self.stubs[addr](self)
            self._ret(r0 if r0 is not None else 0)

    def _unmapped(self, uc, access, addr, size, value, _):
        self.fault = (access, hex(addr), hex(self.reg(UC_ARM_REG_PC)))
        return False

    # call ------------------------------------------------------------------------
    def call(self, fn, *args, stop=None, max_insn=2_000_000):
        sp = STACK_TOP - 0x1000
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        stack = list(args[4:])
        sp -= 4 * len(stack)
        sp &= ~7
        for i, v in enumerate(stack):
            self.w32(sp + 4 * i, v)
        for r, v in zip(regs, args[:4]):
            self.mu.reg_write(r, v & 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_SP, sp)
        self.mu.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
        self.stop_at = set(stop or [])
        self.fault = None
        try:
            self.mu.emu_start(fn | 1, SENTINEL, count=max_insn)
        except Exception as e:
            raise EmuError(f"emulation fault {e} {self.fault}")
        return self.reg(UC_ARM_REG_R0)


def sensor_callback_registration(path, object_address, init_entry, *, zero_cell=None):
    """Exercise the real ISP registration validator with a modeled backend.

    The transplanted sensor callback runs unmodified, including construction of
    its ISP callback table and the donor's public pointer validation. Hardware
    backend work, AE/AWB backend work and mutexes are explicitly modeled only.
    This proves callback construction/validation, never sensor or radio operation.
    """
    import fextent as FE

    class Registration(Emu):
        def _libc(self, name):
            if name in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init",
                        "pthread_mutex_destroy"):
                self.log.append(("modeled_single_thread_mutex", name))
                return 0
            return super()._libc(name)

    image = FE.Image(path)
    e = Registration(path, image.plt)
    e.call(init_entry)
    if zero_cell is not None:
        e.w32(zero_cell, 0)
    tables = []

    def backend(em):
        pointer = em.reg(UC_ARM_REG_R2)
        words = [em.u32(pointer + 4 * i) for i in range(12)]
        # A nonzero data address is not a sensor callback. This validation is
        # independent of the reference-analysis machinery used by the builder.
        if not all(words[:10]):
            raise EmuError("sensor callback table lost a required transplanted callback")
        for target in words:
            if target and not (target & 1 and any(
                    segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
                    and segment["p_vaddr"] <= (target & ~1)
                    < segment["p_vaddr"] + segment["p_memsz"]
                    for segment in image.elf.iter_segments())):
                raise EmuError(f"sensor callback is not executable Thumb code: {target:#x}")
        tables.append(words)
        return 0

    e.stubs[image.syms["isp_sensor_reg_callback"][0] & ~1] = backend
    for name in ("ot_mpi_ae_sensor_reg_callback", "ot_mpi_awb_sensor_reg_callback"):
        e.stubs[image.syms[name][0] & ~1] = lambda em: 0
    ae, awb = e.alloc(64, bytes(64)), e.alloc(64, bytes(64))
    result = e.call(e.u32(object_address), 0, ae, awb)
    return {"result": result, "accepted_callback_tables": tables,
            "hardware_access": False, "backend_modeled": True}


def plt_instruction_resolution(path, report):
    """Validate relocated call mode/entry and execute actual ARM PLT instructions.

    Only the dynamic linker's resolved GOT pointer is modeled. No PLT address is
    intercepted here: a skipped ADD ip,pc instruction must cause a failed access.
    """
    import fextent as FE
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    from unicorn import UcError
    image = FE.Image(path)
    calls = 0
    for relocation in report.get('relocations', []):
        mapped = relocation.get('map', [])
        if relocation.get('kind') != 'call' or not mapped or mapped[0] not in ('plt', 'plt_tail_veneer'):
            continue
        instruction = image.disasm1(int(relocation['new_at'], 16))
        if mapped[0] == 'plt_tail_veneer':
            expected = int(report['plt_tail_veneers'][mapped[1]]['address'], 16)
        else:
            expected = image.plt_target(mapped[1], to_arm=instruction.mnemonic == 'blx')
        if instruction.operands[-1].imm != expected or (int(mapped[2], 16) & ~1) != expected:
            raise EmuError(f'PLT call skips/misidentifies {mapped[1]} entry at {instruction.address:#x}')
        calls += 1
    machine = Emu(path, {})
    arm_decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm_decoder.detail = True
    executed = 0
    for name in image.plt_labels:
        entry = image.plt_target(name, to_arm=True)
        instructions = list(arm_decoder.disasm(image.data[image.off(entry):image.off(entry) + 12], entry))
        if len(instructions) != 3 or [x.mnemonic for x in instructions] != ['add', 'add', 'ldr']:
            raise EmuError(f'unsupported PLT instruction shape: {name}')
        slot = entry + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm + instructions[2].operands[1].mem.disp
        machine.w32(slot, SENTINEL)
        machine.mu.reg_write(UC_ARM_REG_R12, 0xdead0000)
        machine.mu.emu_start(entry, SENTINEL, count=8)
        if machine.reg(UC_ARM_REG_PC) != SENTINEL or machine.reg(UC_ARM_REG_R12) != slot:
            raise EmuError(f'actual PLT instructions failed resolution: {name}')
        machine.mu.reg_write(UC_ARM_REG_R12, 0xdead0000)
        try:
            machine.mu.emu_start(entry + 4, SENTINEL, count=8)
        except UcError:
            pass
        else:
            raise EmuError(f'skipped-prefix PLT mutation was accepted: {name}')
        executed += 1
    for name, veneer in report.get('plt_tail_veneers', {}).items():
        address = int(veneer['address'], 16)
        arm = image.plt_target(name, to_arm=True)
        if bytes(machine.mu.mem_read(address, 8)) != b'\xdf\xf8\x00\xf0' + struct.pack('<I', arm):
            raise EmuError(f'invalid interworking tail veneer: {name}')
        machine.mu.reg_write(UC_ARM_REG_R12, 0xdead0000)
        machine.mu.reg_write(UC_ARM_REG_LR, 0x12345679)
        machine.mu.emu_start(address | 1, SENTINEL, count=8)
        if machine.reg(UC_ARM_REG_PC) != SENTINEL or machine.reg(UC_ARM_REG_LR) != 0x12345679:
            raise EmuError(f'PLT tail veneer lost return address: {name}')
    return {'entries_executed': executed, 'relocated_calls_checked': calls,
            'skipped_prefix_mutations_rejected': executed,
            'tail_veneers_executed': len(report.get('plt_tail_veneers', {})), 'hardware_access': False}


def imx586_lane_policy(path, *, remove_hook=False):
    """Actual getter execution with synthetic rows: software policy, not sensor proof."""
    import fextent as FE
    image = FE.Image(path)
    cases = []
    for board, kind, sensor in ((16, 2, b'imx586'), (17, 2, b'imx586'),
                                (18, 2, b'imx586'), (15, 2, b'imx586'),
                                (17, 1, b'imx586'), (17, 2, b'cv2004')):
        em = Emu(path, image.plt)
        if remove_hook:
            em.mu.mem_write(0x65a98, b'\xf8\xb5\x00\x20')
        combo = em.alloc(128)
        table = em.alloc(32)
        em.w32(table, 0x16)
        em.w32(table + 12, combo)
        state = 0x2709e4
        em.w32(state + 4, 0x16)
        em.w32(state + 20, table)
        em.w32(state + 24, 1)
        context = em.call(image.syms['get_uav_ctx'][0])
        em.w32(context, kind)
        em.w32(context + 4, board)
        em.mu.mem_write(context + 8, sensor + b'\0')
        expected = (0x10000, 0x30002) if board == 16 else (0x20000, 0x30001)
        if board < 16 or kind != 2 or sensor != b'imx586':
            expected = (0xabcdef01, 0x12345678)
        for invocation in range(2):
            em.w32(combo + 0x24, 0xabcdef01)
            em.w32(combo + 0x28, 0x12345678)
            returned = em.call(0x65a98)
            actual = (em.u32(combo + 0x24), em.u32(combo + 0x28))
            if returned != table or actual != expected:
                raise EmuError(f'IMX586 lane policy mismatch: board={board}, kind={kind}, sensor={sensor!r}, call={invocation}, actual={actual}, expected={expected}')
            cases.append({'board': board, 'kind': kind, 'sensor': sensor.decode(),
                          'invocation': invocation, 'lanes': actual})
    return {'cases': cases, 'hardware_access': False}


def actual_table_lane_policy(path, report):
    """Use the emitted table/attributes and ELF CPU permissions, not heap substitutes."""
    import fextent as FE
    image = FE.Image(path)
    init = report['sym'].get('z40_init', report['sym'].get('z8_init'))
    rows = []
    for board in (16, 17):
        em = Emu(path, image.plt)
        em.call(int(init, 16))
        em.call(image.syms['vi_register_sensor'][0])
        context = em.call(image.syms['get_uav_ctx'][0])
        em.w32(context, 2)
        em.w32(context + 4, board)
        em.mu.mem_write(context + 8, b'imx586\0')
        em.w32(0x2709e4 + 4, 0x16)
        sequence = [(b'imx586', 0x16)]
        if 'z40_init' in report['sym']:
            sequence += [(b'ps5280', 0x0b), (b'ps5280', 0x0c), (b'imx586', 0x16)]
        for iteration in range(2):
            for sensor, sensor_type in sequence:
                em.mu.mem_write(context + 8, sensor + b'\0')
                em.w32(0x2709e4 + 4, sensor_type)
                selected = em.call(0x65a98)
                combo = em.u32(selected + 12)
                if not any(segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 2
                           and segment['p_vaddr'] <= combo < segment['p_vaddr'] + segment['p_memsz']
                           for segment in image.elf.iter_segments()):
                    raise EmuError('real sensor combo attributes are not writable')
                lanes = (em.u32(combo + 0x24), em.u32(combo + 0x28))
                expected = (0x10000, 0x30002) if board == 16 else (0x20000, 0x30001)
                if lanes != expected:
                    raise EmuError(f'actual table lane mismatch: {board}, {sensor!r}, {lanes}')
                rows.append({'board': board, 'iteration': iteration, 'sensor': sensor.decode(), 'sensor_type': sensor_type, 'combo': hex(combo), 'lanes': lanes})
    return {'cases': rows, 'hardware_access': False, 'elf_permissions_enforced': True}


def scalar_sensor_data_preservation(hub_path, output_path, report):
    """Independently compare emitted scalar bytes; only callback records may change."""
    import fextent as FE
    hub, output = FE.Image(hub_path), FE.Image(output_path)
    scalar = report.get('scalar_tables_preserved', [])
    private = report.get('sensor_data_images', [])
    if not scalar or not private:
        raise EmuError('missing scalar/private sensor data provenance')
    compared = 0
    for item in scalar:
        source, destination, length = int(item['source'],16), int(item['destination'],16), item['bytes']
        original = hub.data[hub.off(source):hub.off(source)+length]
        actual = output.data[output.off(destination):output.off(destination)+length]
        if original != actual:
            raise EmuError(f'scalar ISP table was rewritten at {source:#x}')
        compared += length
    for item in private:
        source, destination, length = int(item['source'],16), int(item['destination'],16), item['bytes']
        original = hub.data[hub.off(source):hub.off(source)+length]
        # Private data is initialized at runtime, using the emitted init table.
        init = report['sym'].get('z40_init', report['sym'].get('z8_init',report['sym'].get('hub_init')))
        em = Emu(output_path, output.plt)
        em.call(int(init,16))
        actual = bytes(em.mu.mem_read(destination,length))
        callback_bytes = set()
        for name in ('g_sns_imx586_obj','g_sns_farsight_obj'):
            address,size,_ = hub.syms[name]
            if size != 48: raise EmuError('sensor object shape changed')
            callback_bytes.update(range(max(source,address),min(source+length,address+size)))
        for offset,(before,after) in enumerate(zip(original,actual)):
            if source+offset not in callback_bytes and before != after:
                raise EmuError(f'sensor scalar was rewritten at {source+offset:#x}')
        compared += length-len(callback_bytes)
    return {'scalar_bytes_compared':compared,'tables':len(scalar),'private_images':len(private),'hardware_access':False}


def sensor_isp_default_validation(path, object_address, init_entry):
    """Real callback/default/CAC validation with only registration backends modeled."""
    import fextent as FE
    class Defaults(Emu):
        def _libc(self,name):
            if name.startswith('pthread_mutex_'): return 0
            return super()._libc(name)
    image = FE.Image(path)
    em = Defaults(path,image.plt)
    em.call(init_entry)
    tables=[]
    def register(machine):
        pointer=machine.reg(UC_ARM_REG_R2)
        tables.append([machine.u32(pointer+4*k) for k in range(12)])
        return 0
    em.stubs[image.syms['isp_sensor_reg_callback'][0]&~1]=register
    for name in ('ot_mpi_ae_sensor_reg_callback','ot_mpi_awb_sensor_reg_callback'):
        em.stubs[image.syms[name][0]&~1]=lambda machine:0
    em.call(em.u32(object_address),0,em.alloc(64),em.alloc(64))
    if len(tables)!=1: raise EmuError('missing ISP callback table')
    em.call(tables[0][2],0)
    defaults=em.alloc(0x400)
    result=em.call(tables[0][5],0,defaults)
    if result: raise EmuError('sensor ISP defaults refused')
    cac=em.u32(defaults+0x44)
    checked=em.call(image.syms['isp_cac_comm_attr_check'][0],0,cac)
    sharpen=em.u32(defaults+0x14)
    gain_pair=(em.u32(sharpen+0x1528)&0xffff,em.u32(sharpen+0x1528)>>16)
    if checked or gain_pair!=(30,26):
        raise EmuError(f'sensor scalar defaults invalid: CAC={checked:#x}, sharpen={gain_pair}')
    return {'cac_validator':checked,'sharpen_gain_pair':gain_pair,'hardware_access':False,'registration_backend_modeled':True}
