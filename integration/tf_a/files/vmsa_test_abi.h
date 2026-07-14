#ifndef VMSA_TEST_ABI_H
#define VMSA_TEST_ABI_H

#include <stddef.h>
#include <stdint.h>

typedef void (*vmsa_uart_write_t)(uint8_t byte);
typedef void (*vmsa_secondary_entry_t)(void *argument);
typedef int32_t (*vmsa_run_on_secondary_t)(vmsa_secondary_entry_t entry, void *argument);
#define VMSA_BOOT_CONTEXT_ABI_VERSION UINT32_C(3)
typedef struct vmsa_boot_context {
	uint32_t abi_version;
	uint32_t abi_size;
	uint8_t *memory_virtual;
	uint64_t memory_physical;
	size_t memory_bytes;
	vmsa_uart_write_t uart_write;
	uint64_t lower_el_entry;
	uint64_t lower_el_stack;
	const uint8_t *filter;
	size_t filter_bytes;
	vmsa_run_on_secondary_t run_on_secondary;
	uint64_t reserved[2];
} vmsa_boot_context_t;

_Static_assert(sizeof(vmsa_boot_context_t) == 96U, "vmsa boot ABI size");
_Static_assert(_Alignof(vmsa_boot_context_t) == 8U, "vmsa boot ABI alignment");

#endif
