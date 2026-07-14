.section .text.vmsa_access, "ax"
.balign 4

.global vmsa_guarded_read
.type vmsa_guarded_read, %function
vmsa_guarded_read:
    stp x29, x30, [sp, #-64]!
    stp x18, x19, [sp, #16]
    stp x20, x21, [sp, #32]
    mov x29, sp
    mov x18, x2
    mov x19, x0
    mov x20, x1
    adr x0, .Lread_recovery
    mov x1, x18
    bl vmsa_guard_begin
    cbz x0, .Lbusy
    cmp x20, #0
    b.eq .Lread8
    cmp x20, #1
    b.eq .Lread16
    cmp x20, #2
    b.eq .Lread32
    ldr x21, [x19]
    b .Lread_done
.Lread8:
    ldrb w21, [x19]
    b .Lread_done
.Lread16:
    ldrh w21, [x19]
    b .Lread_done
.Lread32:
    ldr w21, [x19]
.Lread_done:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #0
    mov x1, x21
    b .Lread_return
.Lread_recovery:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #1
    mov x1, #0
    b .Lread_return
.Lbusy:
    mov x0, #2
    mov x1, #0
.Lread_return:
    ldp x18, x19, [sp, #16]
    ldp x20, x21, [sp, #32]
    ldp x29, x30, [sp], #64
    ret
.size vmsa_guarded_read, .-vmsa_guarded_read

.global vmsa_guarded_write
.type vmsa_guarded_write, %function
vmsa_guarded_write:
    stp x29, x30, [sp, #-64]!
    stp x18, x19, [sp, #16]
    stp x20, x21, [sp, #32]
    mov x29, sp
    mov x18, x3
    mov x19, x0
    mov x20, x1
    mov x21, x2
    adr x0, .Lwrite_recovery
    mov x1, x18
    bl vmsa_guard_begin
    cbz x0, .Lwrite_busy
    cmp x20, #0
    b.eq .Lwrite8
    cmp x20, #1
    b.eq .Lwrite16
    cmp x20, #2
    b.eq .Lwrite32
    str x21, [x19]
    b .Lwrite_done
.Lwrite8:
    strb w21, [x19]
    b .Lwrite_done
.Lwrite16:
    strh w21, [x19]
    b .Lwrite_done
.Lwrite32:
    str w21, [x19]
.Lwrite_done:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #0
    mov x1, #0
    b .Lwrite_return
.Lwrite_recovery:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #1
    mov x1, #0
    b .Lwrite_return
.Lwrite_busy:
    mov x0, #2
    mov x1, #0
.Lwrite_return:
    ldp x18, x19, [sp, #16]
    ldp x20, x21, [sp, #32]
    ldp x29, x30, [sp], #64
    ret
.size vmsa_guarded_write, .-vmsa_guarded_write

.global vmsa_guarded_execute
.type vmsa_guarded_execute, %function
vmsa_guarded_execute:
    stp x29, x30, [sp, #-48]!
    stp x18, x19, [sp, #16]
    str x20, [sp, #32]
    mov x29, sp
    mov x18, x1
    mov x19, x0
    adr x0, .Lexecute_recovery
    mov x1, x18
    bl vmsa_guard_begin
    cbz x0, .Lexecute_busy
    blr x19
    mov x20, x0
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #0
    mov x1, x20
    b .Lexecute_return
.Lexecute_recovery:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #1
    mov x1, #0
    b .Lexecute_return
.Lexecute_busy:
    mov x0, #2
    mov x1, #0
.Lexecute_return:
    ldp x18, x19, [sp, #16]
    ldr x20, [sp, #32]
    ldp x29, x30, [sp], #48
    ret
.size vmsa_guarded_execute, .-vmsa_guarded_execute

.arch armv8.1-a+lse
.global vmsa_guarded_ordered
.type vmsa_guarded_ordered, %function
vmsa_guarded_ordered:
    stp x29, x30, [sp, #-80]!
    stp x18, x19, [sp, #16]
    stp x20, x21, [sp, #32]
    str x22, [sp, #48]
    mov x29, sp
    mov x18, x3
    mov x19, x0
    mov x20, x1
    mov x21, x2
    adr x0, .Lordered_recovery
    mov x1, x18
    bl vmsa_guard_begin
    cbz x0, .Lordered_busy
    cmp x21, #0
    b.eq .Lordered_acquire
    cmp x21, #1
    b.eq .Lordered_release
    cmp x21, #2
    b.eq .Lordered_swap
.Lordered_exclusive:
    ldxr x22, [x19]
    add x9, x22, x20
    stxr w10, x9, [x19]
    cbnz w10, .Lordered_exclusive
    b .Lordered_done
.Lordered_acquire:
    ldar x22, [x19]
    b .Lordered_done
.Lordered_release:
    stlr x20, [x19]
    mov x22, #0
    b .Lordered_done
.Lordered_swap:
    swp x20, x22, [x19]
.Lordered_done:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #0
    mov x1, x22
    b .Lordered_return
.Lordered_recovery:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #1
    mov x1, #0
    b .Lordered_return
.Lordered_busy:
    mov x0, #2
    mov x1, #0
.Lordered_return:
    ldp x18, x19, [sp, #16]
    ldp x20, x21, [sp, #32]
    ldr x22, [sp, #48]
    ldp x29, x30, [sp], #80
    ret
.size vmsa_guarded_ordered, .-vmsa_guarded_ordered

.global vmsa_guarded_pair
.type vmsa_guarded_pair, %function
vmsa_guarded_pair:
    stp x29, x30, [sp, #-64]!
    stp x18, x19, [sp, #16]
    stp x20, x21, [sp, #32]
    stp x22, x23, [sp, #48]
    mov x29, sp
    mov x18, x5
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x23, x4
    adr x0, .Lpair_recovery
    mov x1, x18
    bl vmsa_guard_begin
    cbz x0, .Lpair_busy
    cbnz x22, .Lpair_write
    ldp x20, x21, [x19]
    b .Lpair_done
.Lpair_write:
    stp x20, x21, [x19]
.Lpair_done:
    mov x0, x18
    bl vmsa_guard_complete
    stp x20, x21, [x23]
    mov x0, #0
    b .Lpair_return
.Lpair_recovery:
    mov x0, x18
    bl vmsa_guard_complete
    mov x0, #1
    b .Lpair_return
.Lpair_busy:
    mov x0, #2
.Lpair_return:
    ldp x18, x19, [sp, #16]
    ldp x20, x21, [sp, #32]
    ldp x22, x23, [sp, #48]
    ldp x29, x30, [sp], #64
    ret
.size vmsa_guarded_pair, .-vmsa_guarded_pair
