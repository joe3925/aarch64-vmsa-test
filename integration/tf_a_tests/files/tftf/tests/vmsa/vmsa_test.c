#include <stdint.h>

#include <lib/libc/stdio.h>
#include <power_management.h>
#include <test_helpers.h>
#include <tftf_lib.h>

#include "vmsa_filter.h"
#include "vmsa_test_abi.h"

#define VMSA_ARENA_BYTES (1024U * 1024U)
#define VMSA_LOWER_STACK_BYTES (64U * 1024U)

static uint8_t vmsa_arena[VMSA_ARENA_BYTES] __attribute__((aligned(4096)));
static uint8_t vmsa_lower_stack[VMSA_LOWER_STACK_BYTES] __attribute__((aligned(16)));

extern uint32_t vmsa_test_ns_el2_entry(const vmsa_boot_context_t *context);
extern void vmsa_lower_el_entry(void);

static vmsa_secondary_entry_t vmsa_secondary_entry;
static void *vmsa_secondary_argument;

static void vmsa_clear_secondary_request(void)
{
	__atomic_store_n(&vmsa_secondary_entry, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&vmsa_secondary_argument, NULL, __ATOMIC_RELEASE);
}

static test_result_t vmsa_secondary_trampoline(void)
{
	vmsa_secondary_entry_t entry = __atomic_load_n(&vmsa_secondary_entry, __ATOMIC_ACQUIRE);
	void *argument = __atomic_load_n(&vmsa_secondary_argument, __ATOMIC_ACQUIRE);

	if (entry == NULL) {
		return TEST_RESULT_FAIL;
	}
	entry(argument);
	return TEST_RESULT_SUCCESS;
}

static int32_t vmsa_run_on_secondary(vmsa_secondary_entry_t entry, void *argument)
{
	u_register_t lead = read_mpidr_el1() & MPID_MASK;
	uint64_t deadline;
	int cpu_node;

	if (entry == NULL) {
		return -1;
	}
	__atomic_store_n(&vmsa_secondary_argument, argument, __ATOMIC_RELEASE);
	__atomic_store_n(&vmsa_secondary_entry, entry, __ATOMIC_RELEASE);
	for_each_cpu(cpu_node) {
		u_register_t target = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;
		if (target == lead) {
			continue;
		}
		if (tftf_cpu_on(target, (uintptr_t)vmsa_secondary_trampoline, 0U) != PSCI_E_SUCCESS) {
			vmsa_clear_secondary_request();
			return -1;
		}
		deadline = read_cntpct_el0() + (read_cntfrq_el0() * 5U);
		while (tftf_psci_affinity_info(target, MPIDR_AFFLVL0) != PSCI_STATE_OFF) {
			if (read_cntpct_el0() >= deadline) {
				(void)printf("VMSA-INFRA HARNESS_FAILURE secondary-timeout\n");
				/* The secondary still owns the shared request. Continuing this
				 * boot could cause memory corruption, so recovery is a system
				 * reset rather than a false local cleanup. */
				psci_system_reset();
				vmsa_clear_secondary_request();
				return -1;
			}
			__asm__ volatile("yield");
		}
		vmsa_clear_secondary_request();
		return 0;
	}
	vmsa_clear_secondary_request();
	return -1;
}

static void vmsa_uart_write(uint8_t byte)
{
	(void)putchar((int)byte);
}

test_result_t test_vmsa_harness(void)
{
	vmsa_boot_context_t context = {
		.abi_version = VMSA_BOOT_CONTEXT_ABI_VERSION,
		.abi_size = (uint32_t)sizeof(vmsa_boot_context_t),
		.memory_virtual = vmsa_arena,
		.memory_physical = (uintptr_t)vmsa_arena,
		.memory_bytes = sizeof(vmsa_arena),
		.uart_write = vmsa_uart_write,
		.lower_el_entry = (uintptr_t)vmsa_lower_el_entry,
		.lower_el_stack = (uintptr_t)(vmsa_lower_stack + sizeof(vmsa_lower_stack)),
		.filter = (const uint8_t *)VMSA_FILTER,
		.filter_bytes = VMSA_FILTER_LENGTH,
		.run_on_secondary = vmsa_run_on_secondary,
	};

	if (vmsa_test_ns_el2_entry(&context) == 22U) {
		(void)printf("VMSA-INFRA CAPABILITY\n");
	}
	return TEST_RESULT_SUCCESS;
}
