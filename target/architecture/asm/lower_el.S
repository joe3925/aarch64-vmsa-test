.arch armv8.5-a
.section .text.vmsa_lower_el, "ax"
.balign 4
.equ HCR_RW, (1 << 31)
.equ HCR_TGE, (1 << 27)
.equ HCR_E2H, (1 << 34)
.equ CPTR_TFP, (1 << 10)
.equ CPACR_FPEN, (3 << 20)
.equ TCR_EPD1, (1 << 23)
.global vmsa_enter_lower_el_asm
.type vmsa_enter_lower_el_asm, %function
vmsa_enter_lower_el_asm:
    stp x29, x30, [sp, #-144]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    str x25, [sp, #64]
    str x26, [sp, #112]
    mrs x12, SP_EL0
    str x12, [sp, #128]
    str x5, [sp, #136]
    mov x29, sp
    mov x19, x2
    mov x20, x0
    mov x21, x1
    mov x22, x3
    mov x26, x4
    mrs x23, HCR_EL2
    mrs x24, CPTR_EL2
    mrs x25, CPACR_EL1
    adr x0, .Llower_recovery
    mrs x1, SPSel
    orr x1, x1, #8
    mrs x2, DAIF
    orr x1, x1, x2
    bl vmsa_lower_begin
    cbz x0, .Llower_busy
    mov x12, #0
    str x12, [sp, #120]
    tbz x23, #34, .Lnon_vhe
    cbnz x26, .Llower_configured
    mrs x12, TTBR0_EL12
    str x12, [sp, #72]
    mrs x12, TCR_EL12
    str x12, [sp, #80]
    mrs x12, MAIR_EL12
    str x12, [sp, #88]
    mrs x12, SCTLR_EL12
    str x12, [sp, #96]
    mrs x12, CPACR_EL12
    str x12, [sp, #104]
    mov x12, #1
    str x12, [sp, #120]
    mrs x12, TTBR0_EL2
    msr TTBR0_EL12, x12
    mrs x12, MAIR_EL2
    msr MAIR_EL12, x12
    mrs x12, TCR_EL2
    and x13, x12, #0xffff
    ubfx x14, x12, #16, #3
    bfi x13, x14, #32, #3
    orr x13, x13, #TCR_EPD1
    msr TCR_EL12, x13
    movz x12, #0x1805
    movk x12, #0x30d0, lsl #16
    msr SCTLR_EL12, x12
    mrs x12, CPACR_EL12
    orr x12, x12, #CPACR_FPEN
    msr CPACR_EL12, x12
    b .Llower_configured
.Lnon_vhe:
    bic x12, x24, #CPTR_TFP
    msr CPTR_EL2, x12
    orr x12, x25, #CPACR_FPEN
    msr CPACR_EL1, x12
.Llower_configured:
    orr x12, x23, #HCR_RW
    ldr x13, [sp, #136]
    cmp x13, #2
    b.eq .Llower_host_el0
    bic x12, x12, #HCR_TGE
    b .Llower_hcr_ready
.Llower_host_el0:
    tbnz x23, #34, .Llower_host_already_vhe
    mrs x14, TCR_EL2
    str x14, [sp, #72]
    and x15, x14, #0xffff
    ubfx x14, x14, #16, #3
    bfi x15, x14, #32, #3
    orr x15, x15, #TCR_EPD1
    msr TCR_EL2, x15
    mov x14, #2
    str x14, [sp, #120]
.Llower_host_already_vhe:
    orr x12, x12, #HCR_E2H
    orr x12, x12, #HCR_TGE
.Llower_hcr_ready:
    msr HCR_EL2, x12
    msr SP_EL1, x21
    ldr x12, [sp, #136]
    cbz x12, .Llower_stack_ready
    msr SP_EL0, x21
.Llower_stack_ready:
    msr ELR_EL2, x20
    msr SPSR_EL2, x22
    mov x0, x19
    isb
    eret
    dsb nsh
    isb
.Llower_recovery:
    ldr x12, [sp, #120]
    cmp x12, #2
    b.eq .Lrestore_host_el0
    cbz x12, .Lrestore_common
    ldr x12, [sp, #72]
    msr TTBR0_EL12, x12
    ldr x12, [sp, #80]
    msr TCR_EL12, x12
    ldr x12, [sp, #88]
    msr MAIR_EL12, x12
    ldr x12, [sp, #96]
    msr SCTLR_EL12, x12
    ldr x12, [sp, #104]
    msr CPACR_EL12, x12
    b .Lrestore_common
.Lrestore_host_el0:
    ldr x12, [sp, #72]
    msr HCR_EL2, x23
    msr TCR_EL2, x12
    isb
.Lrestore_common:
    ldr x12, [sp, #128]
    msr SP_EL0, x12
    msr HCR_EL2, x23
    msr CPTR_EL2, x24
    msr CPACR_EL1, x25
    isb
    bl vmsa_lower_complete
    mov x0, #0
    b .Llower_return
.Llower_busy:
    mov x0, #1
.Llower_return:
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldr x25, [sp, #64]
    ldr x26, [sp, #112]
    ldp x29, x30, [sp], #144
    ret
.size vmsa_enter_lower_el_asm, .-vmsa_enter_lower_el_asm

.global vmsa_lower_el1_return
.type vmsa_lower_el1_return, %function
vmsa_lower_el1_return:
    bl vmsa_lower_return_conduit
    cbnz x0, .Llower_return_smc
    hvc #0
    b .
.Llower_return_smc:
    smc #0
    b .
.size vmsa_lower_el1_return, .-vmsa_lower_el1_return
