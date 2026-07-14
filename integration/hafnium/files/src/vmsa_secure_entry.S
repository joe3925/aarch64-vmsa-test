.section .bss.vmsa_entry_stack, "aw", %nobits
.balign 16
vmsa_entry_stack:
	.space 32768
vmsa_entry_stack_end:

.section .text.vmsa_entry, "ax"
.balign 4
.global vmsa_test_secure_el2_run
.type vmsa_test_secure_el2_run, %function
vmsa_test_secure_el2_run:
	stp	x19, x20, [sp, #-32]!
	stp	x21, x30, [sp, #16]
	mov	x19, sp
	mov	x20, x0
	mrs	x21, cptr_el2
	bic	x1, x21, #(1 << 10)
	orr	x1, x1, #(3 << 20)
	msr	cptr_el2, x1
	isb
	adrp	x1, vmsa_entry_stack_end
	add	x1, x1, :lo12:vmsa_entry_stack_end
	mov	sp, x1
	mov	x0, x20
	bl	vmsa_test_secure_el2_entry
	mov	sp, x19
	msr	cptr_el2, x21
	isb
	ldp	x21, x30, [sp, #16]
	ldp	x19, x20, [sp], #32
	ret
.size vmsa_test_secure_el2_run, . - vmsa_test_secure_el2_run
