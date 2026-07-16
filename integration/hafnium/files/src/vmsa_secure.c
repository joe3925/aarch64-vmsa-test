#include <stdint.h>

#include "hf/addr.h"
#include "hf/plat/console.h"

#include "../vmsa_filter.h"
#include "vmsa_test_abi.h"

#define VMSA_ARENA_BYTES (1024U * 1024U)
#define VMSA_LOWER_STACK_BYTES (64U * 1024U)

static uint8_t vmsa_arena[VMSA_ARENA_BYTES] __attribute__((aligned(4096)));
static uint8_t vmsa_lower_stack[VMSA_LOWER_STACK_BYTES] __attribute__((aligned(16)));

extern uint32_t vmsa_test_secure_el2_run(const vmsa_boot_context_t *context);
extern void vmsa_lower_el_entry(void);

static void vmsa_uart_write(uint8_t byte)
{
	plat_console_putchar((char)byte);
}

void hafnium_vmsa_secure_test(void)
{
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_arena,
		/* This image is identity mapped. Hafnium's pa_from_va() returns the
		 * partition allocation base for this static object, not the object's
		 * offset within the image, which would overlap the harness arena with
		 * executable text in candidate translation tables. */
		.memory_physical = (uint64_t)(uintptr_t)vmsa_arena,
		.memory_bytes = sizeof(vmsa_arena),
		.uart_write = vmsa_uart_write,
		.lower_el_entry = (uintptr_t)vmsa_lower_el_entry,
		.lower_el_stack = (uintptr_t)(vmsa_lower_stack + sizeof(vmsa_lower_stack)),
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
	};
	if (vmsa_test_secure_el2_run(&context) == 22U) {
		const char message[] = "VMSA-INFRA CAPABILITY\n";
		for (size_t index = 0U; index < sizeof(message) - 1U; ++index) {
			vmsa_uart_write((uint8_t)message[index]);
		}
	}
}
