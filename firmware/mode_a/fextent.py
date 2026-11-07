"""Recursive-descent extent and reference analysis for Thumb-2 functions in an ET_EXEC ARM ELF.

extent(entry) follows every branch that stays inside the function (a target that is a
known function start is a call/tail-call, not an internal edge), records PC-relative
literal loads as data, decodes TBB/TBH tables using the guarding `cmp rX, #n`, and
returns the exact byte ranges the function occupies plus every outgoing reference:

  calls      bl/blx/b.w/b to an address outside the function
  pic        ldr rX,[pc,#k] ... add rX,pc  -> absolute target (string / data / GOT base)
  gotloads   ldr rY,[rG, rL] where rG holds the GOT base and rL a literal -> GOT slot
  absw       movw/movt pairs forming an absolute address
  lits       every literal-pool word read (address, value), so the relocator can see all

It REFUSES (raises) on anything it cannot classify: an indirect branch it cannot bound,
a register-relative jump, a literal it cannot attribute. Silence is not an option here.
"""
from __future__ import annotations

import io
from pathlib import Path

import struct
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_LR,
                          ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12,
                          ARM_REG_SP, ARM_CC_AL)
from elftools.elf.elffile import ELFFile


class ExtentError(RuntimeError):
    pass


@dataclass
class Func:
    entry: int
    insns: dict = field(default_factory=dict)       # addr -> (size, mnemonic, op_str)
    lits: dict = field(default_factory=dict)        # lit addr -> (value, size, user insn)
    tables: dict = field(default_factory=dict)      # table addr -> (nbytes, entries)
    calls: list = field(default_factory=list)       # (insn addr, target, kind)
    pic: list = field(default_factory=list)         # (add insn addr, lit addr, target)
    gotloads: list = field(default_factory=list)    # (insn addr, lit addr, slot)
    absw: list = field(default_factory=list)        # (movw addr, movt addr, value)

    def ranges(self):
        spans = [(a, a + s[0]) for a, s in self.insns.items()]
        spans += [(a, a + v[1]) for a, v in self.lits.items()]
        spans += [(a, a + v[0]) for a, v in self.tables.items()]
        spans.sort()
        out = []
        for s, e in spans:
            if out and s <= out[-1][1]:
                out[-1] = (out[-1][0], max(out[-1][1], e))
            else:
                out.append((s, e))
        return out

    @property
    def lo(self):
        return self.ranges()[0][0]

    @property
    def hi(self):
        return self.ranges()[-1][1]


class Image:
    def __init__(self, path):
        self.path = path
        self.data = Path(path).read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.segs = [(s["p_offset"], s["p_vaddr"], s["p_filesz"]) for s in self.elf.iter_segments()
                     if s["p_type"] == "PT_LOAD"]
        self.sections = [(s.name, s["sh_addr"], s["sh_addr"] + s["sh_size"]) for s in self.elf.iter_sections()
                         if s["sh_addr"]]
        self.syms = {}
        for s in self.elf.get_section_by_name(".dynsym").iter_symbols():
            if s["st_value"] and s.name and s["st_shndx"] != "SHN_UNDEF":
                self.syms[s.name] = (s["st_value"], s["st_size"], s["st_info"]["type"])
        self.func_starts = {v[0] & ~1: k for k, v in self.syms.items() if v[2] == "STT_FUNC"}
        got = self.elf.get_section_by_name(".got")
        self.got = (got["sh_addr"], got["sh_addr"] + got["sh_size"])
        # _GLOBAL_OFFSET_TABLE_ base used by PIC code = the most common add-pc target into .got
        self.got_base = None
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.md.detail = True
        self.plt = self._plt()

    def _plt(self):
        import re, subprocess
        from arm_tools import tool as arm_tool
        od = subprocess.run([arm_tool("objdump"), "-d",
                             "-j", ".plt", self.path], capture_output=True, text=True).stdout
        out = {}
        self.plt_labels = {}
        for m in re.finditer(r"^([0-9a-f]+) <([^>@]+)@plt>:", od, re.M):
            a = int(m.group(1), 16)
            name = m.group(2)
            self.plt_labels[name] = a
            out[a] = name
            if self.data[self.off(a):self.off(a) + 4] == b'\x78\x47\xfd\xe7':
                out[a + 4] = name       # Only actual Thumb veneers have a second entry.
        return out

    def plt_target(self, name, *, to_arm):
        """Resolve an entry by its actual instruction prefix, never label+4 blindly."""
        label = self.plt_labels[name]
        prefix = self.data[self.off(label):self.off(label) + 4]
        thumb = prefix == b'\x78\x47\xfd\xe7'
        arm = label + 4 if thumb else label
        # GNU ARM PLT starts with ADD ip,pc,#imm; skipping it leaves ip undefined.
        if self.u32(arm) & 0xfffff000 != 0xe28fc000:
            raise ExtentError(f'unsupported ARM PLT entry for {name} at {arm:#x}')
        if not to_arm and not thumb:
            raise ExtentError(f'{name} has no Thumb PLT veneer')
        return arm if to_arm else label

    def off(self, va):
        for po, v, sz in self.segs:
            if v <= va < v + sz:
                return po + va - v
        return None

    def u32(self, va):
        return struct.unpack_from("<I", self.data, self.off(va))[0]

    def section_of(self, va):
        for n, a, b in self.sections:
            if a <= va < b:
                return n
        return None

    def name_of(self, va):
        if va in self.plt:
            return "plt:" + self.plt[va]
        return self.func_starts.get(va & ~1)

    def disasm1(self, addr):
        o = self.off(addr)
        for ins in self.md.disasm(self.data[o:o + 4], addr, count=1):
            return ins
        raise ExtentError(f"undecodable instruction at {addr:#x}")


def extent(img: Image, entry: int, *, internal_ok=lambda a: True, indirect_tails=None) -> Func:
    f = Func(entry & ~1)
    todo = [f.entry]
    regs_lit: dict = {}
    while todo:
        a = todo.pop()
        regs = {}          # per-path literal tracking (reset at each block start)
        pics = {}          # reg -> PIC-computed absolute address
        while True:
            if a in f.insns:
                break
            if a in f.lits or any(t <= a < t + v[0] for t, v in f.tables.items()):
                raise ExtentError(f"code/data overlap at {a:#x} in function {f.entry:#x}")
            ins = img.disasm1(a)
            f.insns[a] = (ins.size, ins.mnemonic, ins.op_str)
            m, ops = ins.mnemonic, ins.operands
            nxt = a + ins.size
            # got loads: ldr rY, [rG, rL] where rG holds a PIC-computed address and rL a literal
            if m.startswith("ldr") and len(ops) == 2 and ops[1].type == ARM_OP_MEM and ops[1].mem.index \
                    and ops[1].mem.index in regs and ops[1].mem.base in pics:
                lit, val = regs[ops[1].mem.index]
                f.gotloads.append((a, lit, val, pics[ops[1].mem.base]))
            # any register write invalidates tracked literal / PIC values in that register
            written = set()
            if ops and ops[0].type == ARM_OP_REG and not m.startswith(("str", "cmp", "cmn", "tst", "teq", "vstr",
                                                                        "cbz", "cbnz", "push", "stm", "b", "vcmp")):
                written.add(ops[0].reg)
            if m.startswith("ldrd") and len(ops) >= 2 and ops[1].type == ARM_OP_REG:
                written.add(ops[1].reg)
            if m in ("bl", "blx"):
                written |= {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12}
            for r in written:
                pics.pop(r, None)
            # literal loads
            if ops and len(ops) >= 2 and ops[-1].type == ARM_OP_MEM and ops[-1].mem.base == ARM_REG_PC \
                    and m.startswith(("ldr", "vldr")):
                lit = ((a + 4) & ~3) + ops[-1].mem.disp
                size = 8 if (m.startswith("ldrd") or (m == "vldr" and "d" in ins.op_str.split(",")[0])) else 4
                if m.startswith(("ldrb", "ldrsb")):
                    size = 1
                elif m.startswith(("ldrh", "ldrsh")):
                    size = 2
                f.lits[lit] = (img.u32(lit) if size >= 4 else None, size, a)
                if m in ("ldr", "ldr.w") and ops[0].type == ARM_OP_REG:
                    regs[ops[0].reg] = (lit, img.u32(lit))
                    written.discard(ops[0].reg)
            elif m.startswith("add") and len(ops) == 2 and ops[1].type == ARM_OP_REG and ops[1].reg == ARM_REG_PC:
                r = ops[0].reg
                if r not in regs:
                    raise ExtentError(f"add pc without tracked literal at {a:#x}")
                lit, val = regs.pop(r)
                f.pic.append((a, lit, (val + a + 4) & 0xFFFFFFFF))
                pics[r] = (val + a + 4) & 0xFFFFFFFF
                written.discard(r)
            elif m == "adr" or (m.startswith("add") and len(ops) == 3 and ops[1].type == ARM_OP_REG and ops[1].reg == ARM_REG_PC):
                raise ExtentError(f"adr/pc-relative add at {a:#x}: needs explicit handling")
            elif m in ("tbb", "tbh"):
                # bound from the most recent 'cmp rX, #n' + bhi in this block
                bound = None
                back = a - 2
                for _ in range(8):
                    pi = f.insns.get(back) or f.insns.get(back - 2)
                    if pi is None:
                        break
                    if pi[1].startswith("cmp") and "#" in pi[2]:
                        bound = int(pi[2].split("#")[-1], 0)
                        break
                    back -= pi[0]
                if bound is None:
                    raise ExtentError(f"{m} at {a:#x} without a recoverable bound")
                n = bound + 1
                tsize = n if m == "tbb" else 2 * n
                tbase = a + 4
                ents = []
                for i in range(n):
                    e = img.data[img.off(tbase) + i] if m == "tbb" else struct.unpack_from(
                        "<H", img.data, img.off(tbase) + 2 * i)[0]
                    ents.append(tbase + 2 * e)
                f.tables[tbase] = ((tsize + 1) & ~1, ents)
                todo.extend(ents)
                break
            elif m.startswith(("movw", "movt")) and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                regs.setdefault(("mov", ops[0].reg), {})[m[:4]] = (a, ops[1].imm)
                d = regs[("mov", ops[0].reg)]
                if "movw" in d and "movt" in d:
                    val = (d["movt"][1] << 16) | d["movw"][1]
                    if img.section_of(val):
                        f.absw.append((d["movw"][0], d["movt"][0], val))
                    regs.pop(("mov", ops[0].reg))
            for r in written:
                regs.pop(r, None)
            # control flow
            is_branch = m.split(".")[0] in ("b", "bl", "blx", "cbz", "cbnz") or \
                (m.startswith("b") and m[1:3] in ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls",
                                                   "ge", "lt", "gt", "le", "hs", "lo") and len(m.split(".")[0]) == 3)
            if is_branch:
                imm = [o.imm for o in ops if o.type == ARM_OP_IMM]
                if not imm:
                    if m in ("blx", "bx"):
                        pass
                    else:
                        raise ExtentError(f"branch without immediate at {a:#x}")
                else:
                    t = imm[-1]
                    base = m.split(".")[0]
                    if base in ("bl", "blx"):
                        f.calls.append((a, t, base))
                        a = nxt
                        continue
                    ext = (t & ~1) in img.func_starts and (t & ~1) != f.entry or t in img.plt or \
                        not internal_ok(t)
                    if ext:
                        f.calls.append((a, t, "tail" if base == "b" else "cond-ext"))
                        if base == "b":
                            break
                        a = nxt
                        continue
                    todo.append(t)
                    if base == "b":
                        break
                    a = nxt
                    continue
            # returns / indirect
            if m == "bx" and ops and ops[0].type == ARM_OP_REG:
                if ops[0].reg == ARM_REG_LR:
                    break
                # Only explicitly audited callback-tail sites may terminate an
                # extent this way. Unclassified register branches still refuse.
                if indirect_tails and indirect_tails.get(a) == ops[0].reg:
                    f.calls.append((a, None, "indirect-tail"))
                    break
                raise ExtentError(f"register branch bx at {a:#x}")
            if m in ("blx",) and ops and ops[0].type == ARM_OP_REG:
                f.calls.append((a, None, "blx-reg"))
                a = nxt
                continue
            if m.startswith(("pop", "ldm")) and "pc" in ins.op_str:
                break
            if m.startswith("ldr") and ops and ops[0].type == ARM_OP_REG and ops[0].reg == ARM_REG_PC:
                break
            if m == "udf":
                break
            a = nxt
    f.gotloads = _cfg_got_loads(img, f)
    return f

def _cfg_got_loads(img: Image, f: Func):
    """Resolve indexed GOT loads across branches using converged register provenance.

    The extent walk discovers code; it cannot discard a callee-saved GOT base at
    each basic-block boundary and then certify the remaining literal as scalar.
    Joins retain unknown alternatives and refuse ambiguous GOT references.
    """
    from collections import deque
    unknown = ("unknown", 0, 0)
    top = frozenset((unknown,))
    incoming = {f.entry: {}}
    pending = deque((f.entry,))
    decoded = {a: img.disasm1(a) for a in f.insns}

    def successors(a, ins):
        m = ins.mnemonic.split('.')[0]
        nxt = a + ins.size
        imm = [o.imm for o in ins.operands if o.type == ARM_OP_IMM]
        if m in ('tbb', 'tbh'):
            return f.tables[a + 4][1]
        if m in ('bl', 'blx'):
            name = img.plt.get(imm[-1]) if imm else None
            if name in ('__stack_chk_fail', 'exit', '_exit', 'abort'):
                return []
            return [nxt] if nxt in decoded else []
        if m == 'b':
            return [imm[-1]] if imm and imm[-1] in decoded else []
        conditional = m in ('cbz', 'cbnz') or (m.startswith('b') and imm)
        if conditional:
            return [x for x in (nxt, imm[-1]) if x in decoded]
        if (m == 'bx' or (m.startswith(('pop', 'ldm')) and 'pc' in ins.op_str)
                or (m.startswith('ldr') and ins.operands and ins.operands[0].type == ARM_OP_REG
                    and ins.operands[0].reg == ARM_REG_PC) or m == 'udf'):
            return []
        return [nxt] if nxt in decoded else []

    def transfer(a, state):
        ins = decoded[a]
        m, ops = ins.mnemonic, ins.operands
        out = dict(state)
        _, writes = ins.regs_access()
        for reg in writes:
            out.pop(reg, None)
        if m in ('bl', 'blx'):
            for reg in (ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12):
                out.pop(reg, None)
        if (m in ('ldr', 'ldr.w') and len(ops) == 2 and ops[0].type == ARM_OP_REG
                and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC):
            lit = ((a + 4) & ~3) + ops[1].mem.disp
            out[ops[0].reg] = frozenset((("literal", img.u32(lit), lit),))
        elif (m.startswith('add') and len(ops) == 2 and ops[0].type == ARM_OP_REG
              and ops[1].type == ARM_OP_REG and ops[1].reg == ARM_REG_PC):
            values = state.get(ops[0].reg, top)
            out[ops[0].reg] = frozenset(
                ("pic", (value + a + 4) & 0xffffffff, 0) if kind == 'literal' else unknown
                for kind, value, literal in values)
        elif (m in ('mov', 'mov.w') and len(ops) == 2 and
              ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_REG):
            out[ops[0].reg] = state.get(ops[1].reg, top)
        return out

    while pending:
        a = pending.popleft()
        after = transfer(a, incoming[a])
        for target in successors(a, decoded[a]):
            if target not in incoming:
                incoming[target] = dict(after)
                pending.append(target)
                continue
            before = incoming[target]
            merged = {reg: before.get(reg, top) | after.get(reg, top)
                      for reg in before.keys() | after.keys()}
            if merged != before:
                incoming[target] = merged
                pending.append(target)

    found = []
    for a, state in incoming.items():
        ins = decoded[a]
        ops = ins.operands
        if not (ins.mnemonic.startswith('ldr') and len(ops) == 2
                and ops[1].type == ARM_OP_MEM and ops[1].mem.index):
            continue
        bases = state.get(ops[1].mem.base, top)
        got = [v for v in bases if v[0] == 'pic' and img.got[0] <= v[1] < img.got[1]]
        if not got:
            continue
        indices = state.get(ops[1].mem.index, top)
        if len(bases) != 1 or any(value[0] != 'literal' for value in indices):
            raise ExtentError(f"ambiguous GOT reference at {a:#x}: bases={bases}, indices={indices}")
        for _, offset, lit in indices:
            found.append((a, lit, offset, got[0][1]))
    return sorted(found)
