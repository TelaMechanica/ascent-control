"""Bounded direct-Z40 hardware adaptation; retain the B051 callback ABI.

The 17.5.8 register program and PS5280 timing belong to the direct camera.
Its older ISP context offsets do not. Never transplant its whole driver.
"""
import hashlib
import struct

import fextent as FE


# (dedicated Z40 instruction, modern driver instruction). Only hardware timing
# immediates differ here; B051 context offsets and register-info sizes stay intact.
PS_TIMING = (
    (0xfb7ac, 0x104100), (0xfb6f8, 0x10404c),
    (0xfba26, 0x10437a), (0xfba3e, 0x104392),
    (0xfb874, 0x1041c8), (0xfb878, 0x1041cc), (0xfb87a, 0x1041ce),
)
EXPECTED_TIMING = (
    ("movw", "r3, #0x546", "r3, #0x51f"),
    ("movw", "r3, #0x546", "r3, #0x51f"),
    ("movw", "r2, #0x39de", "r2, #0x3b97"),
    ("movw", "r2, #0x83d6", "r2, #0x8007"),
    ("rsb.w", "r1, r4, #0x540", "r1, r4, #0x518"),
    ("adds", "r1, #6", "r1, #7"),
    ("movw", "r4, #0x545", "r4, #0x51e"),
)


def install_z40_hardware(owner):
    from z40_build import assemble, enc_bl, enc_bw, die
    original = FE.Image(owner.z40_path)
    modern = owner.H
    source = FE.extent(original, original.syms["farsight_init"][0])
    if (source.lo, source.hi) != (0xfc42c, 0xfd808) or source.absw or source.tables:
        die("dedicated Z40 register-program extent changed")
    new = owner.rx_alloc(bytes(source.hi-source.lo), align=4, mod=source.lo % 4)
    block = bytearray(original.data[original.off(source.lo):original.off(source.hi)])
    proof = {"source_sha256": hashlib.sha256(original.data).hexdigest(),
             "source_entry": hex(source.entry), "new_entry": hex(new),
             "references": [], "timing": [], "sdk_context": "B051 retained"}
    used = set()
    lane_address = modern.syms['g_farsight_ps5280_lane_cnt'][0]
    if (original.u32(original.syms['g_farsight_ps5280_lane_cnt'][0]) != 4
            or modern.u32(lane_address) != 4):
        die("direct PS5280 lane-count initialization changed")
    lane_cell = owner.rx_alloc(struct.pack('<I', owner.data_new+lane_address-0x299fa8), align=4)

    def put(address, data):
        offset = address-source.lo
        if offset < 0 or offset+len(data) > len(block):
            die("direct register-program patch outside its extent")
        block[offset:offset+len(data)] = data

    for address, target, kind in source.calls:
        if target is None:
            die("unclassified indirect call in direct register program")
        name = original.plt.get(target)
        at = new+address-source.lo
        if name:
            destination = owner.N.plt_target(name, to_arm=True)
            if kind == "tail":
                # Tail interworking uses the existing audited PLT veneer logic.
                mapped = owner.map_call(modern.plt_target(name, to_arm=True), kind)
                destination = mapped[2]
                encoded = enc_bw(at, destination)
            else:
                encoded = enc_bl(at, destination, to_arm=True)
        else:
            name = original.name_of(target)
            if name not in ("farsight_get_ctx", "farsight_set_sel_sensor", "farsight_write_register"):
                die(f"unexpected direct register-program dependency {target:#x}: {name}")
            destination = owner.map_text(modern.syms[name][0])
            encoded = enc_bw(at, destination) if kind == "tail" else enc_bl(at, destination)
        if source.insns[address][0] != len(encoded):
            die("direct register-program branch width changed")
        put(address, encoded)
        proof["references"].append([hex(address), name, hex(destination)])

    for address, literal, target in source.pic:
        if target == 0x27e6d8:
            destination = 0x263700
        elif target == 0x2bde8c:
            destination = owner.bss_new+0x2d44c0-0x2d3008
        elif original.section_of(target) == ".rodata":
            offset = original.off(target)
            data = original.data[offset:original.data.index(b'\0', offset)+1]
            if not data or any(c not in (0, 9, 10, 13) and not 32 <= c < 127 for c in data):
                die("direct register program references non-string legacy data")
            destination = owner.new_string(data)
        else:
            die(f"unmapped direct register-program data {target:#x}")
        put(literal, struct.pack('<I', (destination-(new+address-source.lo+4)) & 0xffffffff))
        used.add(literal)
        proof["references"].append([hex(address), "data", hex(destination)])
    for address, literal, slot, base in source.gotloads:
        if base != 0x27e6d8 or slot not in (0x4f4, 0x344):
            die("direct register-program GOT dependency changed")
        destination = 0x4f4 if slot == 0x4f4 else (lane_cell-0x263700) & 0xffffffff
        put(literal, struct.pack('<I', destination))
        used.add(literal)
    for literal, (value, size, _) in source.lits.items():
        if literal not in used and size == 4 and value and original.section_of(value):
            die(f"unclassified direct register-program literal {literal:#x}={value:#x}")
    owner.rx[new-0x2b0000:new-0x2b0000+len(block)] = block
    old_entry = owner.map_text(modern.syms['farsight_init'][0]) & ~1
    offset = old_entry-0x2b0000
    owner.rx[offset:offset+4] = enc_bw(old_entry, new | 1)
    owner.sym['direct_farsight_init'] = new | 1
    for (old_site, modern_site), (mnemonic, old_operands, modern_operands) in zip(PS_TIMING, EXPECTED_TIMING):
        old, current = original.disasm1(old_site), modern.disasm1(modern_site)
        if ((old.mnemonic, old.op_str) != (mnemonic, old_operands)
                or (current.mnemonic, current.op_str) != (mnemonic, modern_operands)):
            die(f"direct PS5280 timing evidence changed at {old_site:#x}/{modern_site:#x}")
        destination = owner.map_text(modern_site) & ~1
        code = assemble(f'{mnemonic} {old_operands}\n', destination, {})
        if len(code) != current.size:
            die("direct PS5280 timing instruction width changed")
        owner.rx[destination-0x2b0000:destination-0x2b0000+len(code)] = code
        proof['timing'].append({'source': hex(old_site), 'destination': hex(destination),
                                'instruction': f'{mnemonic} {old_operands}'})
    owner.report['direct_camera_hardware'] = proof


def validate_z40_hardware(source_path, emitted_path, report):
    """Execute both register programs and AE callbacks; model only I/O backends.

    This proves software/source fidelity, never camera operation. In particular,
    it catches accidentally binding the native lane-count GOT cell to zoom state.
    """
    from emu import Emu, EmuError

    class Sensor(Emu):
        def _libc(self, name):
            if name.startswith('pthread_mutex_') or name in ('usleep', 'sleep'):
                return 0
            return super()._libc(name)

    source, emitted = FE.Image(source_path), FE.Image(emitted_path)
    if hashlib.sha256(source.data).hexdigest() != report['direct_camera_hardware']['source_sha256']:
        raise EmuError('dedicated camera source identity does not match build evidence')
    modern_start = int(report['layout']['unit_new'], 16)
    source_modern_start = int(report['layout']['unit_hub'][0], 16)

    def run(image, path, transplanted):
        e = Sensor(path, image.plt)
        tables, writes = {}, []
        if transplanted:
            e.call(int(report['sym']['z40_init'], 16))
        def capture(kind, count):
            def callback(machine):
                pointer = machine._args(4)[2 if kind == 'isp' else 3]
                tables[kind] = [machine.u32(pointer+4*i) for i in range(count)]
                return 0
            return callback
        e.stubs[image.syms['isp_sensor_reg_callback'][0] & ~1] = capture('isp', 12)
        e.stubs[image.syms['ot_mpi_ae_sensor_reg_callback'][0] & ~1] = capture('ae', 9)
        e.stubs[image.syms['ot_mpi_awb_sensor_reg_callback'][0] & ~1] = lambda machine: 0
        addresses = ({name: image.syms[name][0] for name in
                      ('farsight_write_register', 'farsight_read_register', 'farsight_i2c_init')}
                     if not transplanted else
                     {name: modern_start+address-source_modern_start for name, address in
                      [('farsight_write_register', 0x104be5), ('farsight_read_register', 0x104b0d),
                       ('farsight_i2c_init', 0x104951)]})
        def write(machine):
            writes.append(tuple(machine._args(3)[:3]))
            return 0
        e.stubs[addresses['farsight_write_register'] & ~1] = write
        e.stubs[addresses['farsight_read_register'] & ~1] = lambda machine: 0
        e.stubs[addresses['farsight_i2c_init'] & ~1] = lambda machine: 0
        obj = (int(report['sym']['g_sns_farsight_obj'], 16) if transplanted
               else image.syms['g_sns_farsight_obj'][0])
        if e.call(e.u32(obj), 0, e.alloc(64), e.alloc(64)):
            raise EmuError('direct sensor registration refused')
        e.call(tables['isp'][2], 0)
        e.call(tables['isp'][0], 0)
        defaults, exposure_updates = [], []
        initial = e.alloc(0x400)
        if e.call(tables['ae'][0], 0, initial):
            raise EmuError('initial direct AE defaults refused')
        defaults.append(bytes(e.mu.mem_read(initial, 0x400)))
        for width, height in ((1920, 1080), (2000, 1500)):
            mode = e.alloc(12, struct.pack('<HHfI', width, height, 50.0, 0))
            e.call(tables['isp'][3], 0, mode)
            data = e.alloc(0x400)
            if e.call(tables['ae'][0], 0, data):
                raise EmuError('direct AE defaults refused')
            defaults.append(bytes(e.mu.mem_read(data, 0x400)))
            registers = e.alloc(0x800)
            e.call(tables['isp'][8], 0, registers)
            for exposure in (0, 1, 500, 1348, 1350, 2400):
                e.call(tables['ae'][3], 0, exposure)
                # Model the SDK's acknowledged register-layout state using its
                # actual B010/B051 offset; never copy the old context wholesale.
                e.w32(registers+(0x67c if transplanted else 0x42c), 1)
                e.call(tables['isp'][8], 0, registers)
                count = e.u32(registers+4)
                if not 0 < count <= 32:
                    raise EmuError('invalid direct sensor register count')
                exposure_updates.append([(e.u32(registers+0x1c+24*i+8),
                                           e.u32(registers+0x1c+24*i+16)) for i in range(count)])
        return writes, defaults, exposure_updates

    original_writes, original_defaults, original_exposure = run(source, source_path, False)
    current_writes, current_defaults, current_exposure = run(emitted, emitted_path, True)
    if original_writes != current_writes or len(current_writes) != 428:
        raise EmuError('direct sensor register stream differs from authentic dedicated Z40')
    if original_defaults != current_defaults:
        raise EmuError('direct PS5280/IMX586 AE defaults differ from authentic dedicated Z40')
    if original_exposure != current_exposure:
        raise EmuError('direct sensor exposure-register updates differ from authentic dedicated Z40')
    # B010 register-info context is smaller. Hardware adaptation must not import
    # those legacy offsets into the B051 ABI used by the donor SDK.
    for site, operands in ((0x104106, 'r3, [r0, #0xd18]'),
                           (0x10410c, 'r3, [r0, #0xd10]')):
        instruction = emitted.disasm1(modern_start+site-source_modern_start)
        if instruction.op_str != operands:
            raise EmuError('modern sensor context layout was replaced by legacy layout')
    return {'register_writes': len(current_writes), 'ae_defaults_equal': True,
            'sensor_modes': 2, 'exposure_cases': len(current_exposure),
            'modern_context_retained': True, 'hardware_access': False}


def validate_direct_handover(emitted_path, report):
    """Run the real restart consumer with explicitly modeled SDK/device backends."""
    from emu import Emu, EmuError

    class Route(Emu):
        def _libc(self, name):
            if name.startswith('pthread_') or name in ('usleep', 'sleep', 'close', 'ioctl'):
                return 0
            if name == 'open':
                return 3
            return super()._libc(name)

    image = FE.Image(emitted_path)
    if image.disasm1(0x66110).op_str != 'r0, #1':
        raise EmuError('direct-camera VI/VPSS mode differs from dedicated source')
    forbidden = {'ss_mpi_isp_exit', 'ss_mpi_isp_init', 'ss_mpi_isp_mem_init',
                 'ss_mpi_ae_unregister', 'ss_mpi_awb_unregister',
                 'ot_mpi_ae_sensor_unreg_callback', 'ot_mpi_awb_sensor_unreg_callback'}
    transitions = []
    for initial, target, width, height in (('imx586', 'ps5280', 1920, 1080),
                                            ('ps5280', 'imx586', 2000, 1500)):
        e = Route(emitted_path, image.plt)
        calls, writes = [], []
        def backend(name):
            def callback(machine):
                args = machine._args(4)
                if name == 'ss_mpi_sys_get_vi_vpss_mode':
                    machine.mu.mem_write(args[0], struct.pack('<4I', 1, 1, 1, 1))
                if name == 'ss_mpi_isp_query_inner_state_info':
                    machine.w32(args[1]+0xac, 1)  # Modeled SDK change-complete signal.
                calls.append(name)
                return 0
            return callback
        for name, (address, _, _) in image.syms.items():
            if name.startswith(('ss_mpi_', 'ot_mpi_')):
                e.stubs[address & ~1] = backend(name)
        e.stubs[image.syms['load_pq_bin'][0] & ~1] = backend('load_pq_bin')
        def write(machine):
            writes.append(tuple(machine._args(3)[:3]))
            return 0
        unit = int(report['layout']['unit_new'], 16)
        e.stubs[unit+0x104be4-0x1031f0] = write
        e.call(int(report['sym']['z40_init'], 16))
        context = e.call(image.syms['get_uav_ctx'][0])
        e.w32(context, 2); e.w32(context+4, 17)
        e.mu.mem_write(context+8, initial.encode()+b'\0')
        for offset, value in ((0x28, 4), (0x2c, 2000 if initial == 'imx586' else 1920),
                              (0x30, 1500 if initial == 'imx586' else 1080), (0x34, 50),
                              (0x38, 1920), (0x3c, 1080), (0x40, 50)):
            e.w32(context+offset, value)
        e.call(image.syms['vi_register_sensor'][0])
        e.call(image.syms['init_vi_vpss'][0])
        calls.clear(); writes.clear()
        e.call(int(report['sym']['restart_vin'], 16), e.alloc(16, target.encode()+b'\0'))
        if forbidden.intersection(calls):
            raise EmuError('direct sensor handover destroys/reinitializes its ISP session')
        required = ('ss_mpi_isp_set_pub_attr', 'ss_mpi_isp_query_inner_state_info',
                    'ss_mpi_vi_start_pipe', 'ss_mpi_vpss_create_grp')
        if any(name not in calls for name in required) or not writes:
            raise EmuError('direct sensor handover omitted route rebuild or sensor restart')
        geometry = tuple(e.u32(context+offset) for offset in (0x44, 0x48, 0x4c))
        if geometry != (width, height, 50):
            raise EmuError(f'direct handover selected wrong geometry: {geometry}')
        if target == 'ps5280' and writes[-3:] != [(0, 0xef, 5), (0, 0x25, 0), (0, 0xed, 1)]:
            raise EmuError('direct wide-sensor stream did not restart')
        if target == 'imx586' and writes[-1:] != [(0, 0x100, 1)]:
            raise EmuError('direct zoom-sensor stream did not restart')
        transitions.append({'target': target, 'geometry': geometry, 'sdk_calls': len(calls),
                            'isp_session_preserved': True})
    return {'transitions': transitions, 'hardware_access': False, 'backends_modeled': True}


def validate_z8_hardware(source_path, emitted_path, report):
    """The single-sensor program must match dedicated Z8, without Z40 routing."""
    from emu import Emu, EmuError

    class Sensor(Emu):
        def _libc(self, name):
            if name.startswith('pthread_mutex_') or name in ('usleep', 'sleep'):
                return 0
            return super()._libc(name)

    streams = []
    for path, transplanted in ((source_path, False), (emitted_path, True)):
        image = FE.Image(path)
        e = Sensor(path, image.plt)
        tables, writes = [], []
        if transplanted:
            e.call(int(report['sym']['z8_init'], 16))
        def register(machine):
            pointer = machine._args(3)[2]
            tables.append([machine.u32(pointer+4*i) for i in range(12)])
            return 0
        e.stubs[image.syms['isp_sensor_reg_callback'][0] & ~1] = register
        for name in ('ot_mpi_ae_sensor_reg_callback', 'ot_mpi_awb_sensor_reg_callback'):
            e.stubs[image.syms[name][0] & ~1] = lambda machine: 0
        def address(name):
            return int(report['sym'][name], 16) if transplanted else image.syms[name][0]
        def write(machine):
            writes.append(tuple(machine._args(3)[:3])); return 0
        e.stubs[address('imx586_write_register') & ~1] = write
        e.stubs[address('imx586_read_register') & ~1] = lambda machine: 0
        e.stubs[address('imx586_i2c_init') & ~1] = lambda machine: 0
        obj = address('g_sns_imx586_obj')
        if e.call(e.u32(obj), 0, e.alloc(64), e.alloc(64)):
            raise EmuError('Z8 sensor registration refused')
        e.call(tables[0][2], 0)
        e.call(tables[0][0], 0)
        streams.append(writes)
        if transplanted and image.disasm1(0x66110).op_str != 'r0, #1':
            raise EmuError('Z8 VI/VPSS mode differs from dedicated source')
    if streams[0] != streams[1] or len(streams[1]) != 197:
        raise EmuError('Z8 sensor register stream differs from authentic dedicated source')
    if any(name in report['sym'] for name in ('restart_vin', 'uninit_pre_route', 'init_next_route',
                                              'direct_sensor_object', 'direct_farsight_init')):
        raise EmuError('single-sensor Z8 inherited dual-camera routing')
    return {'register_writes': 197, 'native_source_equal': True,
            'direct_camera_mode': 1, 'hardware_access': False}


def validate_z40_tuning_loads(emitted_path, tuning_directory):
    """Execute the actual donor PQ loader across same-sized profile changes.

    Real staged vendor blobs are supplied through an in-memory stdio backend.
    The SDK import is the explicit modeled boundary; no device calls occur.
    """
    from pathlib import Path
    from emu import Emu, EmuError, FILEBASE
    image = FE.Image(emitted_path)
    blobs = {name: (Path(tuning_directory)/name).read_bytes() for name in
             ('cam_imx586_50fps_z40_xg1.bin', 'cam_ps5280_50fps_z40.bin')}

    class Loader(Emu):
        def __init__(self):
            super().__init__(emitted_path, image.plt)
            self.positions, self.opened = {}, []
        def _libc(self, name):
            args = self._args(4)
            if name == 'fopen':
                filename = self.cstr(args[0]).decode()
                basename = filename.rsplit('/', 1)[-1]
                if basename not in blobs:
                    raise EmuError(f'unexpected direct tuning profile: {filename}')
                handle = FILEBASE+16*(len(self.opened)+1)
                self.files[handle] = basename
                self.positions[handle] = 0
                self.opened.append(filename)
                return handle
            if name == 'fseek':
                handle, offset, origin = args[:3]
                if offset >= 0x80000000:
                    offset -= 1 << 32
                self.positions[handle] = offset+(len(blobs[self.files[handle]]) if origin == 2
                                                else self.positions[handle] if origin == 1 else 0)
                return 0
            if name == 'ftell':
                return self.positions[args[0]]
            if name == 'fread':
                destination, size, count, handle = args
                start = self.positions[handle]
                data = blobs[self.files[handle]][start:start+size*count]
                self.mu.mem_write(destination, data)
                self.positions[handle] += len(data)
                return len(data)//size if size else 0
            return super()._libc(name)

    e = Loader()
    for name, (address, _, _) in image.syms.items():
        if name.startswith(('ss_mpi_', 'ot_mpi_')):
            e.stubs[address & ~1] = lambda machine: 0
    imported = []
    def sdk_import(machine):
        pointer = machine._args(3)[1]
        imported.append((machine.u32(pointer+0x1c), machine.u32(pointer+0x20)))
        return 0
    e.stubs[image.syms['OT_PQ_BIN_ImportBinData'][0] & ~1] = sdk_import
    context = e.call(image.syms['get_uav_ctx'][0])
    e.w32(context, 2); e.w32(context+4, 17)
    for name, width, height, filename in (
            ('imx586', 2000, 1500, 'cam_imx586_50fps_z40_xg1.bin'),
            ('ps5280', 1920, 1080, 'cam_ps5280_50fps_z40.bin'),
            ('imx586', 2000, 1500, 'cam_imx586_50fps_z40_xg1.bin'),
            ('ps5280', 1920, 1080, 'cam_ps5280_50fps_z40.bin')):
        e.mu.mem_write(context+8, name.encode()+b'\0')
        for offset, value in ((0x28, 4), (0x2c, width), (0x30, height), (0x34, 50)):
            e.w32(context+offset, value)
        before = len(imported)
        result = e.call(image.syms['load_pq_bin'][0], 0)
        if result or len(imported) != before+1 or imported[-1] != (width, height):
            raise EmuError('ordinary PQ loader consumed tuning profile for the wrong sensor')
        if e.opened[-1] != '/usrdata/fpv/tunning/'+filename:
            raise EmuError('ordinary PQ loader selected wrong tuning profile path')
    return {'ordinary_loader_calls': len(imported), 'profile_headers': imported,
            'same_size_buffer_reuse_checked': len(set(map(len, blobs.values()))) == 1,
            'hardware_access': False, 'stdio_and_sdk_import_modeled': True}
