#include <stdint.h>

#include <arch_helpers.h>
#include <drivers/console.h>

#include "vmsa_filter.h"
#include "vmsa_test_abi.h"

#define VMSA_ARENA_BYTES (128U * 1024U)

static uint8_t vmsa_arena[VMSA_ARENA_BYTES] __attribute__((aligned(4096)));

extern uint32_t vmsa_test_root_el3_entry(const vmsa_boot_context_t *context);
extern uint32_t fvp_vmsa_root_entry_on_stack(const vmsa_boot_context_t *context);

static void vmsa_uart_write(uint8_t byte)
{
	(void)console_putc((int)byte);
}

static void vmsa_write_message(const char *message)
{
	for (size_t index = 0U; message[index] != '\0'; ++index) {
		vmsa_uart_write((uint8_t)message[index]);
	}
}

void fvp_vmsa_root_test(void)
{
	uint32_t result;
	uint64_t saved_cptr_el3;
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_arena,
		.memory_physical = (uintptr_t)vmsa_arena,
		.memory_bytes = sizeof(vmsa_arena),
		.uart_write = vmsa_uart_write,
		.lower_el_entry = 0U,
		.lower_el_stack = 0U,
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
	};

	saved_cptr_el3 = read_cptr_el3();
	write_cptr_el3(saved_cptr_el3 & ~TFP_BIT);
	isb();
	result = fvp_vmsa_root_entry_on_stack(&context);
	write_cptr_el3(saved_cptr_el3);
	isb();
	if (result == 22U) {
		vmsa_write_message("VMSA-INFRA CAPABILITY\n");
	} else if (result == 23U) {
		vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-entry\n");
	}
}
