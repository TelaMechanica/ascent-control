"""Offline execution gate for the actual Z40 MSP receive hook and vendor zoom parser.

Frames reproduce Betaflight 4.5.2 osdElementRcChannels (%5d, four consecutive
rows). SDK/hardware is never contacted. The existing zoom target is observed;
no substitute Python zoom controller stands in for the emitted ARM code.
"""
import re
import struct

import fextent as FE
from emu import Emu, EmuError, STACK_TOP
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R7, UC_ARM_REG_PC


def frame(row, value, *, column=12, attribute=0, text=None):
    text = f'{value:5d}'.encode() if text is None else text
    payload = bytes((3, row, column, attribute)) + text
    data = b'$M>' + bytes((len(payload), 182)) + payload
    checksum = 0
    for byte in data[3:]:
        checksum ^= byte
    return data + bytes((checksum,))


class RcEmu(Emu):
    def _libc(self, name):
        if name == 'strtol':
            address, end, radix = self._args(3)[:3]
            if radix != 10:
                raise EmuError('unexpected numeric radix in RC parser')
            text = self.cstr(address)
            match = re.match(rb'[ \t\r\n]*[+-]?[0-9]+', text)
            if end:
                self.w32(end, address + (match.end() if match else 0))
            return int(match.group()) if match else 0
        return super()._libc(name)


def validate_displayport_zoom(path, report):
    image = FE.Image(path)
    sym = {key: int(value, 16) for key, value in report['sym'].items()}
    if 'mspSerialParaOsdRcSlot' not in sym or 'displayport_zoom_frame' not in sym:
        raise EmuError('DisplayPort zoom receive path missing')
    target = int(report['layout']['glue_data']['0x294b28'], 16)
    cases = []

    def fresh():
        e = RcEmu(path, image.plt)
        e.call(sym['z40_init'])
        e.mu.mem_write(target, struct.pack('<f', 99.0))
        e.lock_calls = 0
        def locked(emu):
            emu.lock_calls += 1
            return 1
        e.stubs[image.syms['fpv_bb_is_locked'][0] & ~1] = locked
        return e

    def ratio(e):
        return struct.unpack('<f', e.mu.mem_read(target, 4))[0]

    def receive(e, data):
        # Execute the patched CALL at the real receive site, with the original
        # raw-frame stack location and length register. The next original
        # instruction is the stop boundary; the lock call must survive too.
        e.mu.mem_write(STACK_TOP-0x1000+0x514, data + b'\0'*32)
        e.mu.reg_write(UC_ARM_REG_R7, len(data))
        before = e.lock_calls
        e.call(0x6ccda, stop=[0x6ccde])
        if e.reg(UC_ARM_REG_PC) != 0x6ccde or e.lock_calls != before+1 or e.reg(UC_ARM_REG_R0) != 1:
            raise EmuError('DisplayPort receive hook changed original continuation/lock result')

    def group(e, zoom, reset=-1000):
        for index, value in enumerate((zoom, reset, 0, 0)):
            receive(e, frame(5+index, value))

    updates = 0
    for value, expected in ((-1000, 1.0), (-500, 4.0), (0, 16.0), (900, 32.0)):
        e = fresh()
        group(e, value)
        if ratio(e) != expected:
            raise EmuError(f'DisplayPort zoom target {value}: expected {expected}, got {ratio(e)}')
        updates += 1
        cases.append({'value': value, 'zoom_target': expected})

    e = fresh()
    group(e, 0)
    group(e, 900)
    if ratio(e) != 32.0:
        raise EmuError('DisplayPort parser cannot update repeatedly')
    group(e, 900, 500)
    if ratio(e) != 1.0:
        raise EmuError('DisplayPort reset did not return zoom target to 1x')
    cases.append({'repeated_groups': True, 'high_reset': 1.0})

    negatives = {}
    sequences = {
        'partial_three_rows': [frame(5, 900), frame(6, -1000), frame(7, 0)],
        'repeated_same_row': [frame(5, 900)]*4,
        'different_columns': [frame(5+i, v, column=12+i) for i, v in enumerate((900,-1000,0,0))],
        'invalid_numeric_text': [frame(5, 0, text=b'abcde')]+[frame(6+i,v) for i,v in enumerate((-1000,0,0))],
        'out_of_range': [frame(5, 1025)]+[frame(6+i,v) for i,v in enumerate((-1000,0,0))],
        'truncated': [frame(5+i,v)[:-1] for i,v in enumerate((900,-1000,0,0))],
        'bad_checksum': [frame(5+i,v)[:-1]+bytes((frame(5+i,v)[-1]^1,)) for i,v in enumerate((900,-1000,0,0))],
        'wrong_direction': [b'$M<'+frame(5+i,v)[3:] for i,v in enumerate((900,-1000,0,0))],
        'other_display_text': [frame(5+i,0,text=b'HELLO') for i in range(4)],
    }
    for name, sequence in sequences.items():
        e = fresh()
        for data in sequence:
            receive(e, data)
        if ratio(e) != 99.0:
            raise EmuError(f'DisplayPort refusal changed zoom target: {name}')
        negatives[name] = 'unchanged'
    return {'zoom_updates': updates, 'cases': cases, 'negative_cases': negatives,
            'consumer': 'actual patched MSP receive call and carried vendor parser/setter',
            'hardware_access': False, 'physical_effect': 'NOT TESTED'}
