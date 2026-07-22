.section .text.fvp_vmsa_root_secondary_on_stack, "ax", %progbits
.balign 16
.global fvp_vmsa_root_secondary_on_stack
.type fvp_vmsa_root_secondary_on_stack, %function
fvp_vmsa_root_secondary_on_stack:
	stp	x19, x20, [sp, #-80]!
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	str	x30, [sp, #64]
	mov	x19, sp
	mrs	x20, spsel
	cbnz	x20, 3f
	mov	x21, x19
	msr	spsel, #1
	isb
	mov	x22, sp
	b	4f
3:
	mov	x22, x19
	msr	spsel, #0
	isb
	mov	x21, sp
4:
	mov	x23, x0
	mov	x24, x1
	and	x25, x2, #0xfffffffffffffff0
	and	x26, x3, #0xfffffffffffffff0
	msr	spsel, #1
	isb
	mov	sp, x26
	msr	spsel, #0
	isb
	mov	sp, x25
	mov	x0, x24
	blr	x23
	msr	spsel, #0
	isb
	mov	sp, x21
	msr	spsel, #1
	isb
	mov	sp, x22
	msr	spsel, x20
	isb
	ldr	x30, [sp, #64]
	ldp	x25, x26, [sp, #48]
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]
	ldp	x19, x20, [sp], #80
	ret
.size fvp_vmsa_root_secondary_on_stack, . - fvp_vmsa_root_secondary_on_stack

.section .text.fvp_vmsa_root_entry_on_stack, "ax", %progbits
.balign 16
.global fvp_vmsa_root_entry_on_stack
.type fvp_vmsa_root_entry_on_stack, %function
fvp_vmsa_root_entry_on_stack:
	stp	x19, x20, [sp, #-80]!
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	str	x30, [sp, #64]
	mov	x19, sp
	mrs	x20, spsel
	cbnz	x20, 1f
	mov	x21, x19
	msr	spsel, #1
	isb
	mov	x22, sp
	b	2f
1:
	mov	x22, x19
	msr	spsel, #0
	isb
	mov	x21, sp
2:
	mov	x23, x0
	mov	x24, x1
	mov	x25, x2
	ldr	x9, [x23, #8]
	ldr	x10, [x23, #24]
	add	x9, x9, x10
	and	x9, x9, #0xfffffffffffffff0
	and	x25, x25, #0xfffffffffffffff0
	msr	spsel, #1
	isb
	mov	sp, x25
	msr	spsel, #0
	isb
	mov	sp, x9
	blr	x24
	mov	x26, x0
	msr	spsel, #0
	isb
	mov	sp, x21
	msr	spsel, #1
	isb
	mov	sp, x22
	msr	spsel, x20
	isb
	mov	x0, x26
	ldr	x30, [sp, #64]
	ldp	x25, x26, [sp, #48]
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]
	ldp	x19, x20, [sp], #80
	ret
.size fvp_vmsa_root_entry_on_stack, . - fvp_vmsa_root_entry_on_stack
