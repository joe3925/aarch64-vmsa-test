#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <host_shared_data.h>
#include <lib/aarch64/arch_helpers.h>
#include <realm_helpers.h>
#include <realm_rsi.h>

#include <vmsa_realm_rec_abi.h>

#include "../vmsa_filter.h"

#define VMSA_BOOT_CONTEXT_ABI_VERSION UINT32_C(4)
#define VMSA_ARENA_BYTES (256U * 1024U)

typedef void (*vmsa_uart_write_t)(uint8_t byte);
typedef int32_t (*vmsa_pas_page_acquire_t)(uint32_t pas, uint64_t *virtual_address,
		uint64_t *physical);
typedef int32_t (*vmsa_pas_page_release_t)(uint32_t pas, uint64_t physical);

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
	void *run_on_secondary;
	vmsa_pas_page_acquire_t pas_page_acquire;
	vmsa_pas_page_release_t pas_page_release;
	uint64_t reserved[2];
} vmsa_boot_context_t;

_Static_assert(sizeof(vmsa_boot_context_t) == 112U, "vmsa boot ABI size");
_Static_assert(_Alignof(vmsa_boot_context_t) == 8U, "vmsa boot ABI alignment");

static uint8_t vmsa_arena[VMSA_ARENA_BYTES] __attribute__((aligned(4096)));
static uint8_t *vmsa_report_buffer;
static size_t vmsa_report_length;
static bool vmsa_report_overflow;
static vmsa_realm_rec_record_t *vmsa_rec_record;

extern uint32_t vmsa_test_realm_stage2_entry(const vmsa_boot_context_t *context,
		vmsa_realm_rec_record_t *record);

static void vmsa_report_byte(uint8_t byte)
{
	if (vmsa_report_length == MAX_BUF_SIZE - 1U) {
		vmsa_report_overflow = true;
		return;
	}
	vmsa_report_buffer[vmsa_report_length++] = byte;
	vmsa_report_buffer[vmsa_report_length] = 0U;
}

uint32_t vmsa_test_realm_stage2_mutate(uint64_t operation)
{
	if (vmsa_rec_record == NULL ||
			(operation != VMSA_REALM_REC_MUTATION_MAP_UNPROTECTED &&
			 operation != VMSA_REALM_REC_MUTATION_UNMAP_UNPROTECTED &&
			 operation != VMSA_REALM_REC_MUTATION_PROTECT_READ_ONLY &&
			 operation != VMSA_REALM_REC_MUTATION_PROTECT_READ_WRITE) ||
			vmsa_rec_record->mutation_status != VMSA_REALM_REC_MUTATION_IDLE) {
		return 1U;
	}
	vmsa_rec_record->mutation_operation = operation;
	vmsa_rec_record->mutation_status = VMSA_REALM_REC_MUTATION_REQUEST;
	flush_dcache_range((uintptr_t)vmsa_rec_record, sizeof(*vmsa_rec_record));
	if (rsi_exit_to_host((enum host_call_cmd)
			VMSA_REALM_REC_MUTATION_HOST_CALL) != RSI_SUCCESS) {
		return 2U;
	}
	inv_dcache_range((uintptr_t)vmsa_rec_record, sizeof(*vmsa_rec_record));
	if (vmsa_rec_record->mutation_operation != operation ||
			vmsa_rec_record->mutation_status !=
			VMSA_REALM_REC_MUTATION_COMPLETE) {
		return 3U;
	}
	vmsa_rec_record->mutation_operation = VMSA_REALM_REC_MUTATION_NONE;
	vmsa_rec_record->mutation_status = VMSA_REALM_REC_MUTATION_IDLE;
	return 0U;
}

bool vmsa_test_realm_rec_run(void)
{
	host_shared_data_t *shared = realm_get_my_shared_structure();
	vmsa_realm_rec_record_t *record = (vmsa_realm_rec_record_t *)
		shared->realm_cmd_output_buffer;
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_arena,
		.memory_physical = (uint64_t)(uintptr_t)vmsa_arena,
		.memory_bytes = sizeof(vmsa_arena),
		.uart_write = vmsa_report_byte,
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
	};
	uint32_t result;

	vmsa_report_buffer = shared->log_buffer;
	vmsa_report_length = 0U;
	vmsa_report_overflow = false;
	vmsa_report_buffer[0] = 0U;
	if ((((uintptr_t)record & (_Alignof(vmsa_realm_rec_record_t) - 1U)) != 0U) ||
			record->abi_version != VMSA_REALM_REC_ABI_VERSION ||
			record->abi_size != sizeof(*record) ||
			record->operation != VMSA_REALM_REC_RUN_CATALOG ||
			record->status != VMSA_REALM_REC_STATUS_REQUEST) {
		return false;
	}
	if (record->mutation_operation != VMSA_REALM_REC_MUTATION_NONE ||
			record->mutation_status != VMSA_REALM_REC_MUTATION_IDLE ||
			record->mutation_ipa == 0U ||
			!IS_ALIGNED(record->mutation_ipa, PAGE_SIZE) ||
			record->mutation_physical == 0U ||
			!IS_ALIGNED(record->mutation_physical, PAGE_SIZE)) {
		return false;
	}
	record->status = VMSA_REALM_REC_STATUS_RUNNING;
	vmsa_rec_record = record;
	result = vmsa_test_realm_stage2_entry(&context, record);
	vmsa_rec_record = NULL;
	return result == 0U && !vmsa_report_overflow;
}
