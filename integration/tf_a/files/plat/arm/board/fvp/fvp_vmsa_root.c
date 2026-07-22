#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <arch_helpers.h>
#include <common/debug.h>
#include <drivers/console.h>
#include <lib/gpt_rme/gpt_rme.h>
#include <lib/psci/psci.h>
#include <lib/smccc.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <plat/common/platform.h>
#include <platform_def.h>

#include "vmsa_filter.h"
#include "vmsa_root_payload.h"
#include "vmsa_test_abi.h"

#define VMSA_ROOT_ARENA_BYTES (1088U * 1024U)
#define VMSA_ROOT_CONTROL_BYTES (4U * 1024U)
#define VMSA_ROOT_EXCEPTION_STACK_BYTES (60U * 1024U)
#define VMSA_ROOT_SECONDARY_STACK_BYTES (32U * 1024U)
#define VMSA_ROOT_SECONDARY_EXCEPTION_STACK_BYTES (32U * 1024U)
#define VMSA_ROOT_ALLOCATOR_BYTES \
	(VMSA_ROOT_ARENA_BYTES - VMSA_ROOT_CONTROL_BYTES - \
	 VMSA_ROOT_EXCEPTION_STACK_BYTES - VMSA_ROOT_SECONDARY_STACK_BYTES - \
	 VMSA_ROOT_SECONDARY_EXCEPTION_STACK_BYTES)
#define VMSA_ROOT_CONTROL_OFFSET VMSA_ROOT_ALLOCATOR_BYTES
#define VMSA_ROOT_EXCEPTION_STACK_TOP \
	(VMSA_ROOT_CONTROL_OFFSET + VMSA_ROOT_CONTROL_BYTES + \
	 VMSA_ROOT_EXCEPTION_STACK_BYTES)
#define VMSA_ROOT_SECONDARY_STACK_TOP \
	(VMSA_ROOT_EXCEPTION_STACK_TOP + VMSA_ROOT_SECONDARY_STACK_BYTES)
#define VMSA_ROOT_SECONDARY_EXCEPTION_STACK_TOP VMSA_ROOT_ARENA_BYTES
#define VMSA_PAS_PAGE UINT64_C(0x87ff0000)
#define VMSA_PAS_VIRTUAL UINT64_C(0x60000000)
#define VMSA_PAS_NON_SECURE UINT32_C(0)
#define VMSA_PAS_SECURE UINT32_C(1)
#define VMSA_PAS_REALM UINT32_C(2)
#define VMSA_PAS_DELEGATED_REALM UINT32_C(5)

static uint8_t vmsa_root_arena[VMSA_ROOT_ARENA_BYTES]
	__attribute__((aligned(4096), section(".arm_el3_tzc_dram"), used));
static uint8_t vmsa_root_payload_data[VMSA_ROOT_PAYLOAD_DATA_BYTES]
	__attribute__((aligned(4096), section(".vmsa_root_payload_data"), used));
static uint8_t vmsa_root_payload_code[VMSA_ROOT_PAYLOAD_CODE_BYTES]
	__attribute__((aligned(4096), section(".vmsa_root_payload_code"), used));

static bool vmsa_pas_page_owned;
static uint32_t vmsa_pas_page_kind;
static bool vmsa_root_runtime_ready;
static bool vmsa_root_test_started;

#define VMSA_SECONDARY_IDLE U(0)
#define VMSA_SECONDARY_BOOTING U(1)
#define VMSA_SECONDARY_READY U(2)
#define VMSA_SECONDARY_REQUESTED U(3)
#define VMSA_SECONDARY_RUNNING U(4)
#define VMSA_SECONDARY_COMPLETE U(5)
#define VMSA_SECONDARY_FAILED U(6)
#define VMSA_SECONDARY_STOP U(7)
#define VMSA_SECONDARY_TIMEOUT_SECONDS U(5)

typedef struct vmsa_secondary_control {
	vmsa_secondary_entry_t entry;
	void *argument;
	u_register_t target;
	unsigned int state;
} vmsa_secondary_control_t;

_Static_assert(sizeof(vmsa_secondary_control_t) <= VMSA_ROOT_CONTROL_BYTES,
	       "Root secondary control page is too small");
_Static_assert((VMSA_ROOT_CONTROL_OFFSET & 4095U) == 0U,
	       "Root secondary control page must be page aligned");
_Static_assert(VMSA_ROOT_SECONDARY_EXCEPTION_STACK_TOP == VMSA_ROOT_ARENA_BYTES,
	       "Root secondary layout must fill the arena exactly");

extern uint32_t fvp_vmsa_root_entry_on_stack(const vmsa_boot_context_t *context,
					      uintptr_t entry,
					      uintptr_t exception_stack_top);
extern void fvp_vmsa_root_secondary_on_stack(vmsa_secondary_entry_t entry,
					     void *argument,
					     uintptr_t stack_top,
					     uintptr_t exception_stack_top);

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

static vmsa_secondary_control_t *vmsa_secondary_control(void)
{
	return (vmsa_secondary_control_t *)(void *)&vmsa_root_arena[
		VMSA_ROOT_CONTROL_OFFSET];
}

static uint64_t vmsa_secondary_deadline(void)
{
	return read_cntpct_el0() +
	       read_cntfrq_el0() * VMSA_SECONDARY_TIMEOUT_SECONDS;
}

static void vmsa_secondary_wait_timeout(void)
{
	vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-secondary-timeout\n");
	panic();
}

static u_register_t vmsa_find_secondary_target(void)
{
	static const unsigned int affinity_shifts[] = { 0U, 8U, 16U };
	u_register_t lead = read_mpidr_el1() & MPIDR_AFFINITY_MASK;

	for (size_t shift_index = 0U;
	     shift_index < sizeof(affinity_shifts) / sizeof(affinity_shifts[0]);
	     ++shift_index) {
		unsigned int shift = affinity_shifts[shift_index];
		u_register_t mask = (u_register_t)UINT64_C(0xff) << shift;

		for (u_register_t affinity = 0U; affinity <= UINT64_C(0xff);
		     ++affinity) {
			u_register_t target = (lead & ~mask) | (affinity << shift);

			if (target != lead && plat_core_pos_by_mpidr(target) >= 0 &&
			    psci_affinity_info(target, PSCI_CPU_PWR_LVL) ==
				    AFF_STATE_OFF) {
				return target;
			}
		}
	}
	return PSCI_INVALID_MPIDR;
}

static void vmsa_reset_secondary_control(void)
{
	vmsa_secondary_control_t *control = vmsa_secondary_control();

	control->entry = NULL;
	control->argument = NULL;
	control->target = PSCI_INVALID_MPIDR;
	__atomic_store_n(&control->state, VMSA_SECONDARY_IDLE, __ATOMIC_RELEASE);
}

static bool vmsa_start_secondary_worker(void)
{
	vmsa_secondary_control_t *control = vmsa_secondary_control();
	u_register_t target = vmsa_find_secondary_target();
	uint64_t deadline;

	if (target == PSCI_INVALID_MPIDR) {
		return false;
	}
	control->entry = NULL;
	control->argument = NULL;
	control->target = target;
	__atomic_store_n(&control->state, VMSA_SECONDARY_BOOTING,
			 __ATOMIC_RELEASE);
	if (psci_cpu_on(target, plat_get_ns_image_entrypoint(), 0U) !=
	    PSCI_E_SUCCESS) {
		vmsa_reset_secondary_control();
		return false;
	}

	deadline = vmsa_secondary_deadline();
	while (__atomic_load_n(&control->state, __ATOMIC_ACQUIRE) !=
	       VMSA_SECONDARY_READY) {
		if (read_cntpct_el0() >= deadline) {
			vmsa_secondary_wait_timeout();
		}
		__asm__ volatile ("yield");
	}
	return true;
}

static bool vmsa_stop_secondary_worker(void)
{
	vmsa_secondary_control_t *control = vmsa_secondary_control();
	u_register_t target = control->target;
	uint64_t deadline;

	if (__atomic_load_n(&control->state, __ATOMIC_ACQUIRE) !=
	    VMSA_SECONDARY_READY) {
		return false;
	}
	__atomic_store_n(&control->state, VMSA_SECONDARY_STOP, __ATOMIC_RELEASE);
	deadline = vmsa_secondary_deadline();
	while (psci_affinity_info(target, PSCI_CPU_PWR_LVL) != AFF_STATE_OFF) {
		if (read_cntpct_el0() >= deadline) {
			vmsa_secondary_wait_timeout();
		}
		__asm__ volatile ("yield");
	}
	vmsa_reset_secondary_control();
	return true;
}

static int32_t vmsa_run_on_secondary(vmsa_secondary_entry_t entry,
				     void *argument)
{
	vmsa_secondary_control_t *control = vmsa_secondary_control();
	uint64_t deadline;
	unsigned int state;

	if (entry == NULL ||
	    __atomic_load_n(&control->state, __ATOMIC_ACQUIRE) !=
		    VMSA_SECONDARY_READY) {
		return -1;
	}
	control->entry = entry;
	control->argument = argument;
	__atomic_store_n(&control->state, VMSA_SECONDARY_REQUESTED,
			 __ATOMIC_RELEASE);

	deadline = vmsa_secondary_deadline();
	do {
		state = __atomic_load_n(&control->state, __ATOMIC_ACQUIRE);
		if (state == VMSA_SECONDARY_COMPLETE ||
		    state == VMSA_SECONDARY_FAILED) {
			break;
		}
		if (read_cntpct_el0() >= deadline) {
			vmsa_secondary_wait_timeout();
		}
		__asm__ volatile ("yield");
	} while (true);

	control->entry = NULL;
	control->argument = NULL;
	__atomic_store_n(&control->state, VMSA_SECONDARY_READY,
			 __ATOMIC_RELEASE);
	return state == VMSA_SECONDARY_COMPLETE ? 0 : -1;
}

static void vmsa_secondary_worker(void *argument)
{
	vmsa_secondary_control_t *control = argument;

	__atomic_store_n(&control->state, VMSA_SECONDARY_READY,
			 __ATOMIC_RELEASE);
	for (;;) {
		unsigned int expected = VMSA_SECONDARY_REQUESTED;
		unsigned int state =
			__atomic_load_n(&control->state, __ATOMIC_ACQUIRE);

		if (state == VMSA_SECONDARY_STOP) {
			return;
		}
		if (state != VMSA_SECONDARY_REQUESTED) {
			__asm__ volatile ("yield");
			continue;
		}
		if (!__atomic_compare_exchange_n(&control->state, &expected,
					 VMSA_SECONDARY_RUNNING, false,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE)) {
			continue;
		}
		if (control->entry == NULL) {
			__atomic_store_n(&control->state, VMSA_SECONDARY_FAILED,
					 __ATOMIC_RELEASE);
			continue;
		}
		control->entry(control->argument);
		__atomic_store_n(&control->state, VMSA_SECONDARY_COMPLETE,
				 __ATOMIC_RELEASE);
	}
}

int fvp_vmsa_root_secondary_try_run(void)
{
	vmsa_secondary_control_t *control = vmsa_secondary_control();
	uint64_t saved_cptr_el3;

	if (__atomic_load_n(&control->state, __ATOMIC_ACQUIRE) !=
	    VMSA_SECONDARY_BOOTING ||
	    (read_mpidr_el1() & MPIDR_AFFINITY_MASK) != control->target) {
		return 0;
	}
	saved_cptr_el3 = read_cptr_el3();
	write_cptr_el3(saved_cptr_el3 & ~TFP_BIT);
	isb();
	fvp_vmsa_root_secondary_on_stack(
		vmsa_secondary_worker, control,
		(uintptr_t)&vmsa_root_arena[VMSA_ROOT_SECONDARY_STACK_TOP],
		(uintptr_t)&vmsa_root_arena[
			VMSA_ROOT_SECONDARY_EXCEPTION_STACK_TOP]);
	write_cptr_el3(saved_cptr_el3);
	isb();
	return 1;
}

static bool vmsa_root_layout_valid(void)
{
	return (uintptr_t)vmsa_root_payload_code ==
		(uintptr_t)VMSA_ROOT_PAYLOAD_CODE_VIRTUAL &&
	       (uintptr_t)vmsa_root_payload_data ==
		(uintptr_t)VMSA_ROOT_PAYLOAD_DATA_VIRTUAL;
}

static bool vmsa_map_payload_source(void)
{
	return mmap_add_dynamic_region(VMSA_ROOT_PAYLOAD_SOURCE_PHYSICAL,
				       VMSA_ROOT_PAYLOAD_SOURCE_VIRTUAL,
				       (size_t)VMSA_ROOT_PAYLOAD_SOURCE_BYTES,
				       MT_RO_DATA | MT_NS) == 0;
}

static bool vmsa_unmap_payload_source(void)
{
	return mmap_remove_dynamic_region(VMSA_ROOT_PAYLOAD_SOURCE_VIRTUAL,
					  (size_t)VMSA_ROOT_PAYLOAD_SOURCE_BYTES) == 0;
}

static bool vmsa_prepare_root_payload(void)
{
	if (!vmsa_root_layout_valid() || !vmsa_map_payload_source()) {
		return false;
	}
	memcpy(vmsa_root_payload_code,
	       (const void *)(uintptr_t)VMSA_ROOT_PAYLOAD_CODE_SOURCE_VIRTUAL,
	       (size_t)VMSA_ROOT_PAYLOAD_CODE_BYTES);
	memcpy(vmsa_root_payload_data,
	       (const void *)(uintptr_t)VMSA_ROOT_PAYLOAD_DATA_SOURCE_VIRTUAL,
	       (size_t)VMSA_ROOT_PAYLOAD_DATA_BYTES);
	clean_dcache_range((uintptr_t)vmsa_root_payload_code,
			   (size_t)VMSA_ROOT_PAYLOAD_CODE_BYTES);
	clean_dcache_range((uintptr_t)vmsa_root_payload_data,
			   (size_t)VMSA_ROOT_PAYLOAD_DATA_BYTES);
	if (!vmsa_unmap_payload_source()) {
		return false;
	}
	if (xlat_change_mem_attributes((uintptr_t)vmsa_root_payload_code,
				       (size_t)VMSA_ROOT_PAYLOAD_CODE_BYTES,
				       MT_CODE | EL3_PAS) != 0) {
		return false;
	}
	__asm__ volatile ("ic iallu" : : : "memory");
	dsbsy();
	isb();
	return true;
}

static bool vmsa_restore_root_payload(void)
{
	return xlat_change_mem_attributes((uintptr_t)vmsa_root_payload_code,
					  (size_t)VMSA_ROOT_PAYLOAD_CODE_BYTES,
					  MT_RW_DATA | EL3_PAS) == 0;
}

static int32_t vmsa_pas_page_acquire(uint32_t pas, uint64_t *virtual_address,
				     uint64_t *physical)
{
	volatile uint64_t *page = (volatile uint64_t *)(uintptr_t)VMSA_PAS_VIRTUAL;

	if (vmsa_pas_page_owned || virtual_address == NULL || physical == NULL ||
	    (pas != VMSA_PAS_NON_SECURE && pas != VMSA_PAS_SECURE &&
	     pas != VMSA_PAS_REALM && pas != VMSA_PAS_DELEGATED_REALM)) {
		return -1;
	}
	if (mmap_add_dynamic_region(VMSA_PAS_PAGE, VMSA_PAS_VIRTUAL, 4096U,
				    MT_MEMORY | MT_RW | MT_NS) != 0) {
		return -1;
	}
	for (size_t index = 0U; index < 4096U / sizeof(*page); ++index) {
		page[index] = 0U;
	}
	if (pas != VMSA_PAS_NON_SECURE) {
		unsigned int source = pas == VMSA_PAS_SECURE ? SMC_FROM_SECURE :
							       SMC_FROM_REALM;
		unsigned int attributes = pas == VMSA_PAS_SECURE ? MT_SECURE :
								      MT_REALM;

		if (mmap_remove_dynamic_region(VMSA_PAS_VIRTUAL, 4096U) != 0 ||
		    gpt_delegate_pas(VMSA_PAS_PAGE, 4096U, source) != 0) {
			return -1;
		}
		if (mmap_add_dynamic_region(VMSA_PAS_PAGE, VMSA_PAS_VIRTUAL,
					    4096U, MT_MEMORY | MT_RW | attributes) != 0) {
			(void)gpt_undelegate_pas(VMSA_PAS_PAGE, 4096U,
						 source);
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
	if (pas != VMSA_PAS_NON_SECURE) {
		unsigned int source = pas == VMSA_PAS_SECURE ? SMC_FROM_SECURE :
							       SMC_FROM_REALM;

		if (gpt_undelegate_pas(VMSA_PAS_PAGE, 4096U, source) != 0) {
			return -1;
		}
	}
	vmsa_pas_page_owned = false;
	return 0;
}

void fvp_vmsa_root_test(void);

void fvp_vmsa_root_test_runtime(void)
{
	vmsa_root_runtime_ready = true;
	fvp_vmsa_root_test();
}

void fvp_vmsa_root_test(void)
{
	uint32_t result;
	uint64_t saved_cptr_el3;
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_root_arena,
		.memory_physical = (uintptr_t)vmsa_root_arena,
		.memory_bytes = VMSA_ROOT_ALLOCATOR_BYTES,
		.uart_write = vmsa_uart_write,
		.lower_el_entry = 0U,
		.lower_el_stack = 0U,
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
		.run_on_secondary = vmsa_run_on_secondary,
		.pas_page_acquire = vmsa_pas_page_acquire,
		.pas_page_release = vmsa_pas_page_release,
	};

	if (!vmsa_root_runtime_ready || vmsa_root_test_started) {
		return;
	}
	vmsa_root_test_started = true;
	if (!vmsa_prepare_root_payload()) {
		vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-payload-map\n");
		return;
	}
	if (!vmsa_start_secondary_worker()) {
		vmsa_write_message(
			"VMSA-INFRA HARNESS_FAILURE result=root-secondary-start\n");
		(void)vmsa_restore_root_payload();
		return;
	}
	saved_cptr_el3 = read_cptr_el3();
	write_cptr_el3(saved_cptr_el3 & ~TFP_BIT);
	isb();
	result = fvp_vmsa_root_entry_on_stack(
		&context, (uintptr_t)VMSA_ROOT_PAYLOAD_ENTRY,
		(uintptr_t)&vmsa_root_arena[VMSA_ROOT_EXCEPTION_STACK_TOP]);
	write_cptr_el3(saved_cptr_el3);
	isb();
	if (!vmsa_stop_secondary_worker()) {
		vmsa_write_message(
			"VMSA-INFRA HARNESS_FAILURE result=root-secondary-stop\n");
	}
	if (!vmsa_restore_root_payload()) {
		vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-payload-unmap\n");
	}
	if (result == 22U) {
		vmsa_write_message("VMSA-INFRA CAPABILITY\n");
	} else if (result == 23U) {
		vmsa_write_message("VMSA-INFRA HARNESS_FAILURE result=root-entry\n");
	}
}
