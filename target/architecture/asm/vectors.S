.section .text.vmsa_vectors, "ax"
.balign 2048
.global vmsa_exception_vectors
.type vmsa_exception_vectors, %object
vmsa_exception_vectors:
.macro VECTOR target
    b \target
    .space 124
.endm
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
.size vmsa_exception_vectors, .-vmsa_exception_vectors

.section .text.vmsa_recovery_vectors, "ax"
.balign 2048
.global vmsa_recovery_vectors
.type vmsa_recovery_vectors, %object
vmsa_recovery_vectors:
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_sync_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
    VECTOR vmsa_unexpected_vector
.size vmsa_recovery_vectors, .-vmsa_recovery_vectors

.type vmsa_sync_vector, %function
vmsa_sync_vector:
    sub sp, sp, #256
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    ldr x0, [sp, #144]
    bl vmsa_arch_handle_sync
    cbz x0, vmsa_unexpected_saved
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #256
    eret
    dsb nsh
    isb

vmsa_unexpected_saved:
    add sp, sp, #256
vmsa_unexpected_vector:
    bl vmsa_arch_unexpected_exception
    b .
