.section .bss.vmsa_root_stack, "aw", %nobits
.balign 16
vmsa_root_stack:
    .space 16384
vmsa_root_stack_top:

.section .text.fvp_vmsa_root_entry, "ax"
.balign 4
.global fvp_vmsa_root_entry_on_stack
.type fvp_vmsa_root_entry_on_stack, %function
fvp_vmsa_root_entry_on_stack:
    stp x19, x20, [sp, #-32]!
    str x30, [sp, #16]
    mov x19, sp
    mrs x20, spsel
    msr spsel, #1
    isb
    adrp x1, vmsa_root_stack_top
    add x1, x1, :lo12:vmsa_root_stack_top
    mov sp, x1
    bl vmsa_test_root_el3_entry
    cbnz x20, 1f
    msr spsel, #0
    isb
1:
    mov sp, x19
    ldr x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.size fvp_vmsa_root_entry_on_stack, .-fvp_vmsa_root_entry_on_stack
