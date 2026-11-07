.syntax unified
.thumb
.arch armv7-a
.text
.thumb_set original, 0x2252c
.global identity_hook
.thumb_func
identity_hook:
push {r4-r8,lr}
sub sp, sp, #16
mov r4,r0
mov r5,r1
mov r6,r2
mov r7,r3
bl original
mov r0,r4
ldr r1,=base0
bl compare
cbnz r0,next0
mov r0,r4
ldr r1,=name0
mov r2,r5
bl copy
ldr r2,=hardware0
b hardware
next0:
mov r0,r4
ldr r1,=base1
bl compare
cbnz r0,next1
mov r0,r4
ldr r1,=name1
mov r2,r5
bl copy
ldr r2,=hardware1
b hardware
next1:
mov r0,r4
ldr r1,=base2
bl compare
cbnz r0,next2
mov r0,r4
ldr r1,=name2
mov r2,r5
bl copy
ldr r2,=hardware2
b hardware
next2:
b done
hardware:
add r0,sp,#804
movs r1,#32
ubfx r3,r6,#4,#4
and r6,r6,#15
str r6,[sp]
ubfx r6,r7,#4,#4
str r6,[sp,#4]
and r7,r7,#15
str r7,[sp,#8]
bl format
done:
movs r0,#0
add sp,sp,#16
pop {r4-r8,pc}
.ltorg
base0: .asciz "Ascent_GT_pro"
name0: .asciz "Ascent_GT_pro_Hub"
hardware0: .asciz "Ascent-GT-Pro-Hub-V%d.%d-%d.%d"
base1: .asciz "Ascent_GT_MAX_HF"
name1: .asciz "Ascent_GT_MAX_HF_Hub"
hardware1: .asciz "Ascent-GT-MAX-HF-Hub-V%d.%d-%d.%d"
base2: .asciz "Ascent_GT_MAX_WF"
name2: .asciz "Ascent_GT_MAX_WF_Hub"
hardware2: .asciz "Ascent-GT-MAX-WF-Hub-V%d.%d-%d.%d"
