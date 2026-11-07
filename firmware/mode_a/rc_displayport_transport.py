"""Fixed MSP182 camera-text transport adapters for the existing vendor parser.

The donor UART receiver already accepts MSPv1, native MSPv2 and v2-in-v1.
Normalize only the nine-byte, flag-zero WRITE_STRING response; never rewrite
the receive buffer, forwarding state, menu policy or camera interpretation.
"""


def assembly_sources():
    return {
        'displayport_zoom_frame': (
            'cmp r1,#15\nbne 0f\nb.w displayport_zoom_v1\n0:\n'
            'cmp r1,#18\nbeq 1f\ncmp r1,#21\nbne 9f\n'
            '1: push {r4,r5,r6,r7,r8,lr}\nsub sp,#16\n'
            'mov r4,r0\nmov r5,r1\nldrb r0,[r4,#0]\ncmp r0,#36\nbne 8f\n'
            'ldrb r0,[r4,#2]\ncmp r0,#62\nbne 8f\n'
            'cmp r5,#18\nbne 2f\n'
            # Native $X>: flags, LE command, LE payload length, payload, CRC8.
            'ldrb r0,[r4,#1]\ncmp r0,#88\nbne 8f\n'
            'ldrb r0,[r4,#3]\ncmp r0,#0\nbne 8f\n'
            'ldrh r0,[r4,#4]\ncmp r0,#182\nbne 8f\n'
            'ldrh r0,[r4,#6]\ncmp r0,#9\nbne 8f\n'
            'add r0,r4,#3\nmovs r1,#14\nbl displayport_crc8\n'
            'ldrb r1,[r4,#17]\ncmp r0,r1\nbne 8f\n'
            'add r6,r4,#8\nb 3f\n'
            # $M> v2-in-v1: validate outer XOR and the inner DVB-S2 CRC.
            '2: ldrb r0,[r4,#1]\ncmp r0,#77\nbne 8f\n'
            'ldrb r0,[r4,#3]\ncmp r0,#15\nbne 8f\n'
            'ldrb r0,[r4,#4]\ncmp r0,#255\nbne 8f\n'
            'ldrb r0,[r4,#5]\ncmp r0,#0\nbne 8f\n'
            'ldrh r0,[r4,#6]\ncmp r0,#182\nbne 8f\n'
            'ldrh r0,[r4,#8]\ncmp r0,#9\nbne 8f\n'
            'add r0,r4,#3\nmovs r1,#18\nbl displayport_xor\n'
            'cmp r0,#0\nbne 8f\n'
            'add r0,r4,#5\nmovs r1,#14\nbl displayport_crc8\n'
            'ldrb r1,[r4,#19]\ncmp r0,r1\nbne 8f\n'
            'add r6,r4,#10\n'
            # Private stack packet; the original raw packet remains untouched.
            '3: ldrb r0,[r6]\ncmp r0,#3\nbne 8f\n'
            'ldr r0,=0x093e4d24\nstr r0,[sp]\n'
            'movs r0,#182\nstrb r0,[sp,#4]\n'
            'add r1,sp,#5\nmovs r2,#0\n'
            '4: ldrb r0,[r6,r2]\nstrb r0,[r1,r2]\nadds r2,#1\n'
            'cmp r2,#9\nbne 4b\n'
            'add r0,sp,#3\nmovs r1,#11\nbl displayport_xor\n'
            'strb r0,[sp,#14]\nmov r0,sp\nmovs r1,#15\n'
            'bl displayport_zoom_v1\n'
            '8: add sp,#16\npop {r4,r5,r6,r7,r8,pc}\n'
            '9: bx lr\n.ltorg\n'
        ),
        # Called only after exact five-character grammar/checksum validation.
        # Accept the observed BF +/-1024 domain; saturate only its small tails
        # into the carried camera parser's +/-1000 domain. Never scale midpoints.
        'displayport_rc_range': (
            'push {r4,r5,r6,lr}\nsub sp,#16\nmov r4,r0\n'
            'movs r5,#0\nmovs r6,#9\n'
            '1: ldrb r0,[r4,r6]\ncmp r0,#48\nblo 2f\n'
            'subs r0,#48\nmovs r1,#10\nmul r5,r5,r1\nadds r5,r0\n'
            '2: adds r6,#1\ncmp r6,#14\nbne 1b\n'
            'cmp.w r5,#1024\nbhi 9f\ncmp.w r5,#1000\nbhi 3f\n'
            'mov r0,r4\nmovs r1,#15\nbl msp_osd\nb 9f\n'
            '3: movs r2,#0\nmov r1,sp\n'
            '4: ldrb r0,[r4,r2]\nstrb r0,[r1,r2]\nadds r2,#1\n'
            'cmp r2,#15\nbne 4b\n'
            'ldrb r0,[r4,#9]\ncmp r0,#45\nbeq 5f\nmovs r0,#32\n'
            '5: strb r0,[r1,#9]\nmovs r0,#49\nstrb r0,[r1,#10]\n'
            'movs r0,#48\nstrb r0,[r1,#11]\nstrb r0,[r1,#12]\nstrb r0,[r1,#13]\n'
            'add r0,sp,#3\nmovs r1,#11\nbl displayport_xor\nstrb r0,[sp,#14]\n'
            'mov r0,sp\nmovs r1,#15\nbl msp_osd\n'
            '9: add sp,#16\npop {r4,r5,r6,pc}\n'
        ),
        'displayport_crc8': (
            'movs r2,#0\n'
            '1: ldrb r3,[r0],#1\neors r2,r3\nmovs r3,#8\n'
            '2: lsls r2,#1\ntst r2,#0x100\nbeq 3f\n'
            'eor r2,r2,#0xd5\n'
            '3: uxtb r2,r2\nsubs r3,#1\nbne 2b\n'
            'subs r1,#1\nbne 1b\nmov r0,r2\nbx lr\n'
        ),
        'displayport_xor': (
            'movs r2,#0\n'
            '1: ldrb r3,[r0],#1\neors r2,r3\nsubs r1,#1\nbne 1b\n'
            'mov r0,r2\nbx lr\n'
        ),
    }
