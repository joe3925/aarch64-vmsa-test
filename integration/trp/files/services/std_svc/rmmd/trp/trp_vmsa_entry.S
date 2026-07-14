.section .bss.vmsa_realm_stack, "aw", %nobits
.balign 16
vmsa_realm_stack:
    .space 16384
vmsa_realm_stack_top:

.section .text.trp_vmsa_entry, "ax"
.balign 4
.global trp_vmsa_entry_on_stack
.type trp_vmsa_entry_on_stack, %function
trp_vmsa_entry_on_stack:
    stp x19, x20, [sp, #-32]!
    str x30, [sp, #16]
    mov x19, sp
    mrs x20, spsel
    msr spsel, #1
    isb
    adrp x1, vmsa_realm_stack_top
    add x1, x1, :lo12:vmsa_realm_stack_top
    mov sp, x1
    bl vmsa_test_realm_el2_entry
    cbnz x20, 1f
    msr spsel, #0
    isb
1:
    mov sp, x19
    ldr x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.size trp_vmsa_entry_on_stack, .-trp_vmsa_entry_on_stack
