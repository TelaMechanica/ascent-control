"""Offline diagnostic capture table; physical CSI/IQ profile is unqualified.

Uses the donor's four-lane transport defaults, not its sensor calibration.
Geometry comes from the recovered Avatar descriptor. Board lane order and odd
sensor-height acceptance must be qualified before this can be admitted in AC.
"""
import struct


def install(builder, bootstrap, sensor_object):
    import z40_build as Z
    donor=builder.N
    raw=bytes(donor.data[donor.off(0x265780):donor.off(0x265780)+0x2a0])
    rows=[struct.unpack_from('<8I',raw,32*i) for i in range(21)]
    assert not any(row[0] in [0x16,0x17] for row in rows)
    template=next(row for row in rows if row[0]==0xc)
    attrs={k:bytes(donor.data[donor.off(template[k]):donor.off(template[k])+size])
           for k,size in {4:44,5:120,6:32,7:32}.items()}
    pipe=bytearray(attrs[6]);struct.pack_into('<II',pipe,8,1952,1097);attrs[6]=bytes(pipe)
    shared={k:builder.rx_alloc(data,align=4) for k,data in attrs.items()}
    combo=bytearray(200)
    struct.pack_into('<9I4h',combo,0,0,0,0,0,0,1952,1097,1,0,0,1,2,3)
    combo_source=builder.rx_alloc(combo,align=4)
    combo_target=builder.rw_alloc(len(combo),align=4)
    addresses=[];table=bytearray(raw)
    for fps,route in [(60,0x16),(100,0x17)]:
        isp=bytearray(68)
        struct.pack_into('<6If2I',isp,0,16,8,1920,1080,1952,1097,float(fps),3,0)
        struct.pack_into('<4I',isp,52,0,0,1952,1097)
        pointer=builder.rx_alloc(isp,align=4)
        row=(route,sensor_object,pointer,combo_target,shared[4],shared[5],shared[6],shared[7])
        table.extend(struct.pack('<8I',*row));addresses.append({'fps':fps,'words':list(row)})
    table_pointer=builder.rx_alloc(table,align=8)
    for address,mnemonic,fragment,replacement in [
        (0x66b38,'sub','#0x2ac','subw sp,sp,#0x2ec'),
        (0x66b46,'mov','#0x2a0','mov.w r2,#0x2e0'),
        (0x66b56,'mov','#0x2a0','mov.w r0,#0x2e0'),
        (0x66b7c,'mov','#0x2a0','mov.w r2,#0x2e0'),
        (0x66b9c,'add','#0x2ac','addw sp,sp,#0x2ec'),
        (0x66b4c,'str','#0x2a4','str r3,[sp,#0x2e4]'),
        (0x66b8e,'ldr','#0x2a4','ldr r3,[sp,#0x2e4]'),
        (0x66b76,'movs','#0x15','movs r2,#0x17')]:
        instruction=builder.expect(address,mnemonic,fragment)
        code=Z.assemble(replacement+'\n',address,{},name='hdpro_table_'+hex(address))
        builder.patch(address,code,instruction.size,'HD Pro23row capture table allocation/count/stack guard')
    original,literal=builder.pic_target(0x66b3c,0x66b44);assert original==0x265780
    builder.patch(literal,struct.pack('<I',(table_pointer-0x66b48)&0xffffffff),4,'HD Pro23row table source;21stock rows unchanged')
    address=(Z.NEW_RX_VA+len(builder.rx)+3)&~3
    code=Z.assemble('push {r4,lr}\nbl previous_bootstrap\nldr r0,=s_target\nldr r1,=s_source\nmovs r2,#200\nldr ip,=memcpy_arm\nblx ip\npop {r4,pc}\n.ltorg\n',address,
                    {'previous_bootstrap':bootstrap,'s_target':combo_target,'s_source':combo_source,
                     'memcpy_arm':donor.plt_target('memcpy',to_arm=True)},name='hdpro_capture_bootstrap')
    assert builder.rx_alloc(code,align=4)==address
    return address|1,{'table':table_pointer,'rows':23,'added':addresses,
                      'combo_source':combo_source,'combo_target':combo_target,
                      'profile':'Diagnostic RAW10/BGGR,1952x1097,crop16,8 to1920x1080; candidate four-lane0,1,2,3 device0; not bench qualified',
                      'unqualified':['Connector/lane order','Sensor input timing and odd-height acceptance','RAW/Bayer interpretation on CV610','IQ/AWB/black-level calibration'],
                      'original_rows_preserved':21,'hardware_access':False}
