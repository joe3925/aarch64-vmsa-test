#include <stdint.h>

#include <drivers/console.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <platform_def.h>

#include "vmsa_filter.h"
#include "vmsa_test_abi.h"

#define VMSA_ARENA_BYTES (2U * 1024U * 1024U)
#define VMSA_LOWER_STACK_BYTES (64U * 1024U)
/* In the R-EL2 stage-1 regime, descriptor PAS bits 00 select Realm PAS. */
#define VMSA_R_EL2_PAS MT_SECURE

static uint8_t vmsa_arena[VMSA_ARENA_BYTES] __attribute__((aligned(4096)));
static uint8_t vmsa_lower_stack[VMSA_LOWER_STACK_BYTES]
	__attribute__((aligned(16)));
extern char __VMSA_RW_START__[];
extern uint32_t vmsa_test_realm_el2_entry(const vmsa_boot_context_t *context);
extern void vmsa_lower_el_entry(void);
extern uint32_t trp_vmsa_entry_on_stack(const vmsa_boot_context_t *context);

static void vmsa_uart_write(uint8_t byte)
{
	(void)console_putc((int)byte);
}

void trp_vmsa_test(void)
{
	const uintptr_t rw_start =
		(uintptr_t)__VMSA_RW_START__ & ~(uintptr_t)0xfffU;
	const uintptr_t rmm_end = (RMM_END + 0xfffU) & ~(uintptr_t)0xfffU;
	const uintptr_t uart_page = PLAT_ARM_TRP_UART_BASE & ~(uintptr_t)0xfffU;
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_arena,
		.memory_physical = (uintptr_t)vmsa_arena,
		.memory_bytes = sizeof(vmsa_arena),
		.uart_write = vmsa_uart_write,
		.lower_el_entry = (uintptr_t)vmsa_lower_el_entry,
		.lower_el_stack =
			(uintptr_t)(vmsa_lower_stack + sizeof(vmsa_lower_stack)),
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
	};

	mmap_add_region(RMM_BASE, RMM_BASE, rw_start - RMM_BASE,
			MT_CODE | VMSA_R_EL2_PAS);
	mmap_add_region(rw_start, rw_start, rmm_end - rw_start,
			MT_RW_DATA | VMSA_R_EL2_PAS);
	mmap_add_region(uart_page, uart_page, 0x1000U,
			MT_DEVICE | MT_RW | VMSA_R_EL2_PAS);
	init_xlat_tables();
	enable_mmu_el2(0U);
	if (trp_vmsa_entry_on_stack(&context) == 22U) {
		const char message[] = "VMSA-INFRA CAPABILITY\n";
		for (size_t index = 0U; index < sizeof(message) - 1U; ++index) {
			vmsa_uart_write((uint8_t)message[index]);
		}
	}
}
