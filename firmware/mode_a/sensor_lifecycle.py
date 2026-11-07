"""Fixed Farsight re-entry repair for the physical Hub's full ISP lifecycle."""
import struct


def install_hub_farsight_reentry(owner):
    from z40_build import assemble, enc_bw, die
    source = owner.H
    if source.data[source.off(0x104db4):source.off(0x104db8)] != bytes.fromhex('03600848'):
        die('Farsight already-initialized branch changed')
    # Return through the plain epilogue, rather than the original tail-puts
    # epilogue: this thunk has already emitted the scoped outcome message.
    continuation = owner.map_text(0x104da0) | 1
    address = owner.rx_alloc(bytes(96), align=4)
    already = owner.new_string(b'farsight sensor has already init!')
    failed = owner.new_string(b'farsight I2C reopen failed; sensor context remains uninitialized')
    code = assemble(
        'mov r0,r4\nbl i2c_init\ncmp r0,#0\nbne 1f\n'
        'movs r3,#1\nstr r3,[r5]\nldr r0,=s_already\nb 2f\n'
        '1: movs r3,#0\nstr r3,[r5]\nldr r0,=s_failed\n'
        '2: ldr ip,=puts_arm\nblx ip\nb.w resume\n.ltorg\n',
        address, {'i2c_init': owner.map_text(source.syms['farsight_i2c_init'][0]),
                  'resume': continuation, 'puts_arm': owner.N.plt_target('puts', to_arm=True),
                  's_already': already, 's_failed': failed}, name='hub_farsight_reentry')
    if len(code) > 96:
        die('Farsight re-entry repair exceeded its fixed allocation')
    owner.rx[address-0x2b0000:address-0x2b0000+len(code)] = code
    site = owner.map_text(0x104db4)
    owner.rx[site-0x2b0000:site-0x2b0000+4] = enc_bw(site, address | 1)
    owner.report['farsight_reentry'] = {'site': hex(site), 'entry': hex(address),
                                       'bytes': len(code), 'continuation': hex(continuation),
                                       'unit_new': hex(owner.unit_new),
                                       'object': hex(owner.sdata_new+source.syms['g_sns_farsight_obj'][0]-0x2995e0)}
    owner.sym['hub_farsight_reentry'] = address | 1


def validate_farsight_reentry(path, report, *, fail_reopen=False):
    from emu import Emu, EmuError
    import fextent as FE
    image = FE.Image(path)

    class Sensor(Emu):
        def __init__(self):
            super().__init__(path, image.plt)
            self.fds, self.opens, self.closed, self.fail_open = set(), [], [], False
        def _libc(self, name):
            args = self._args(4)
            if name.startswith('pthread_mutex_') or name in ('usleep', 'sleep', 'ioctl'):
                return 0
            if name == 'open':
                if self.fail_open:
                    return 0xffffffff
                fd = len(self.opens)+3
                self.opens.append((self.cstr(args[0]), fd)); self.fds.add(fd)
                return fd
            if name == 'close':
                self.closed.append(args[0]); self.fds.discard(args[0])
                return 0
            if name in ('write', 'read'):
                if args[0] not in self.fds:
                    raise EmuError('sensor used a closed I2C handle')
                if name == 'read':
                    self.mu.mem_write(args[1], bytes(args[2]))
                return args[2]
            return super()._libc(name)

    e = Sensor()
    e.call(int(report['sym']['hub_init'], 16))
    tables = []
    def register(machine):
        pointer = machine._args(3)[2]
        tables.append([machine.u32(pointer+4*i) for i in range(12)])
        return 0
    e.stubs[image.syms['isp_sensor_reg_callback'][0] & ~1] = register
    for name in ('ot_mpi_ae_sensor_reg_callback', 'ot_mpi_awb_sensor_reg_callback'):
        e.stubs[image.syms[name][0] & ~1] = lambda machine: 0
    unit = int(report['farsight_reentry']['unit_new'], 16)
    base = 0x100b5c
    obj = int(report['farsight_reentry']['object'], 16)
    e.call(e.u32(obj), 0, e.alloc(64), e.alloc(64))
    e.call(tables[0][2], 0)
    e.call(tables[0][3], 0, e.alloc(12, struct.pack('<HHfI', 2000, 1500, 50.0, 0)))
    e.call(tables[0][0], 0)
    opened_before = len(e.opens)
    e.call(tables[0][1], 0)
    if not e.closed:
        raise EmuError('test did not exercise real sensor I2C teardown')
    e.call(tables[0][2], 0)
    e.fail_open = fail_reopen
    e.call(tables[0][0], 0)
    context = e.call(unit+0x103a34-base, 0)
    if fail_reopen:
        if e.u32(context):
            raise EmuError('failed I2C reopen marked sensor initialized')
        return {'failed_reopen_refused': True, 'hardware_access': False}
    if len(e.opens) != opened_before+1 or not e.u32(context):
        raise EmuError('full ISP re-entry skipped reopening the closed sensor I2C handle')
    # Exercise real register I/O after re-entry; an existing open handle is reused.
    e.call(unit+0x104be5-base, 0, 0x100, 1)
    e.call(tables[0][0], 0)
    if len(e.opens) != opened_before+1:
        raise EmuError('repeated initialized callbacks leak I2C handles')
    return {'closed_then_reopened': True, 'no_descriptor_leak': True,
            'hardware_access': False, 'device_io_modeled': True}
