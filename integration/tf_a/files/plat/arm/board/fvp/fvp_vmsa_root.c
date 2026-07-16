#include <stdbool.h>
#include <stdint.h>

#include <arch_helpers.h>
#include <drivers/console.h>
#include <lib/gpt_rme/gpt_rme.h>
#include <lib/smccc.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <platform_def.h>

#include "vmsa_filter.h"
#include "vmsa_test_abi.h"

#define VMSA_ARENA_BYTES (1024U * 1024U)
#define VMSA_ARENA_PHYSICAL (PLAT_ARM_TRUSTED_DRAM_BASE + UINT64_C(0x01000000))
#define VMSA_ARENA_VIRTUAL UINT64_C(0x61000000)
#define VMSA_PAS_PAGE UINT64_C(0x87ff0000)
#define VMSA_PAS_VIRTUAL UINT64_C(0x60000000)
#define VMSA_PAS_NON_SECURE UINT32_C(0)
#define VMSA_PAS_DELEGATED_REALM UINT32_C(5)

static bool vmsa_pas_page_owned;
static uint32_t vmsa_pas_page_kind;

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

static int32_t vmsa_pas_page_acquire(uint32_t pas, uint64_t *virtual_address,
				     uint64_t *physical)
{
	volatile uint64_t *page = (volatile uint64_t *)(uintptr_t)VMSA_PAS_VIRTUAL;

	if (vmsa_pas_page_owned || virtual_address == NULL || physical == NULL ||
	    (pas != VMSA_PAS_NON_SECURE && pas != VMSA_PAS_DELEGATED_REALM)) {
		return -1;
	}
	if (mmap_add_dynamic_region(VMSA_PAS_PAGE, VMSA_PAS_VIRTUAL, 4096U,
				    MT_MEMORY | MT_RW | MT_NS) != 0) {
		return -1;
	}
	for (size_t index = 0U; index < 4096U / sizeof(*page); ++index) {
		page[index] = 0U;
	}
	if (pas == VMSA_PAS_DELEGATED_REALM) {
		if (mmap_remove_dynamic_region(VMSA_PAS_VIRTUAL, 4096U) != 0 ||
		    gpt_delegate_pas(VMSA_PAS_PAGE, 4096U, SMC_FROM_REALM) != 0) {
			return -1;
		}
		if (mmap_add_dynamic_region(VMSA_PAS_PAGE, VMSA_PAS_VIRTUAL,
					    4096U, MT_MEMORY | MT_RW | MT_REALM) != 0) {
			(void)gpt_undelegate_pas(VMSA_PAS_PAGE, 4096U,
						 SMC_FROM_REALM);
			return -1;
		}
	}
	vmsa_pas_page_owned = true;
	vmsa_pas_page_kind = pas;
	*virtual_address = VMSA_PAS_VIRTUAL;
	*physical = VMSA_PAS_PAGE;
	return 0;
}

static int32_t vmsa_pas_page_release(uint32_t pas, uint64_t physical)
{
	if (!vmsa_pas_page_owned || pas != vmsa_pas_page_kind ||
	    physical != VMSA_PAS_PAGE) {
		return -1;
	}
	if (mmap_remove_dynamic_region(VMSA_PAS_VIRTUAL, 4096U) != 0) {
		return -1;
	}
	if (pas == VMSA_PAS_DELEGATED_REALM &&
	    gpt_undelegate_pas(VMSA_PAS_PAGE, 4096U, SMC_FROM_REALM) != 0) {
		return -1;
	}
	vmsa_pas_page_owned = false;
	return 0;
}

void fvp_vmsa_root_test(void)
{
	uint32_t result;
	uint64_t saved_cptr_el3;
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = (void *)(uintptr_t)VMSA_ARENA_VIRTUAL,
		.memory_physical = VMSA_ARENA_PHYSICAL,
		.memory_bytes = VMSA_ARENA_BYTES,
		.uart_write = vmsa_uart_write,
		.lower_el_entry = 0U,
		.lower_el_stack = 0U,
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
		.pas_page_acquire = vmsa_pas_page_acquire,
		.pas_page_release = vmsa_pas_page_release,
	};

	if (mmap_add_dynamic_region(VMSA_ARENA_PHYSICAL, VMSA_ARENA_VIRTUAL,
				    VMSA_ARENA_BYTES,
				    MT_MEMORY | MT_RW | MT_ROOT) != 0) {
		vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-arena-map\n");
		return;
	}

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
