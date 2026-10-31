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

die:
    la a0, msg_err
    li a1, 4
    call print
    li a0, 1
    li a7, 93
    ecall

_start:
    addi sp, sp, -128
    # mmap
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
    li t0, 0x1122334455667788
    sd t0, 0(s1)
    li t0, 0x5a
    sb t0, 16(s1)
    # open
    li a0, -100
    la a1, path_dev
    li a2, 2
    li a3, 0
    li a7, 56
    ecall
    bltz a0, die
    mv s2, a0
    # ioctl
    sd s1, 0(sp)
    sd zero, 8(sp)
    sd zero, 16(sp)
    mv a0, s2
    li a1, 0xc0184702
    mv a2, sp
    li a7, 29
    ecall
    bltz a0, die
    li t0, 0x9d37c4b1a62ef059
    ld t1, 8(sp)
    xor s3, t1, t0          # pte_pa
    ld t1, 16(sp)
    xor s4, t1, t0          # flag_pa
    la a0, msg_pte
    li a1, 4
    call print
    mv a0, s3
    call print_hex64

    li s8, 0                # test index
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
    # fork
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    bltz a0, die
    beqz a0, tchild
    mv s7, a0
    mv a0, s7
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
    li t0, 9
    blt s8, t0, test_loop
    la a0, msg_fin
    li a1, 4
    call print
    li a0, 0
    li a7, 93
    ecall

# ---- test child: dispatch on s8 ----
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
    li t0, 6
    beq s8, t0, c6
    li t0, 7
    beq s8, t0, c7
    j c8

alive:
    la a0, msg_alv
    li a1, 2
    call print
    addi t0, s8, 48
    sb t0, 40(sp)
    li t0, 10
    sb t0, 41(sp)
    addi a0, sp, 40
    li a1, 2
    call print
    li a0, 42
    li a7, 93
    ecall

# control: normal vse8 to scratch VA s1+16, then read back
c0:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0x33
    vmv.v.x v0, t1
    addi t0, s1, 16
    vse8.v v0, (t0)
    fence
    lbu t1, 16(s1)
    la a0, msg_val
    li a1, 2
    call print
    mv a0, t1
    call print_hex64
    j alive

# lane exact: a0=pte_pa+7 a1=0
c1:
    addi a0, s3, 7
    li a1, 0
    .word 0xcc00f057
    .word 0x00b5700b
    j alive

# vse256
c2:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x1002d027
    fence
    j alive

# vse512
c3:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x1002e027
    fence
    j alive

# vse1024
c4:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x1002f027
    fence
    j alive

# vse128 with vm=1
c5:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x12028027
    fence
    j alive

# width=100 variant, mop=0
c6:
    vsetivli zero, 1, e8, m1, ta, ma
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x0202c027
    fence
    j alive

# e128 config + normal vse8 (word 0x02028027)
c7:
    .word 0xcc40f057
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x02028027
    fence
    j alive

# e128 config + vse128 original
c8:
    .word 0xcc40f057
    li t1, 0
    vmv.v.x v0, t1
    addi t0, s3, 7
    .word 0x10028027
    fence
    j alive

    .section .rodata
msg_err: .ascii "ERR\n"
msg_pte: .ascii "PTE="
msg_tst: .ascii "T>"
msg_sta: .ascii "S="
msg_alv: .ascii "A<"
msg_val: .ascii "V="
msg_fin: .ascii "FIN\n"
path_dev: .asciz "/dev/ghostvector"
