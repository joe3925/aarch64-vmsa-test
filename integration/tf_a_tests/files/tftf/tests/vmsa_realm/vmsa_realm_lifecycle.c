#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <arch_features.h>
#include <heap/page_alloc.h>
#include <host_realm_helper.h>
#include <host_realm_mem_layout.h>
#include <host_shared_data.h>
#include <lib/xlat_tables/xlat_tables_defs.h>
#include <realm_def.h>
#include <test_helpers.h>
#include <tftf_lib.h>
#include <vmsa_realm_rec_abi.h>

static char vmsa_protocol_output[MAX_BUF_SIZE];

extern uint64_t vmsa_test_realm_stage2_plan(void);
extern u_register_t host_rmi_rtt_mapunprotected(u_register_t rd,
		u_register_t map_addr, long level, u_register_t descriptor);

static u_register_t map_existing_unprotected(struct realm *realm,
		const vmsa_realm_rec_record_t *record, bool writable)
{
	u_register_t descriptor;

	if (realm->rtt_s2ap_enc_indirect) {
		return REALM_ERROR;
	}
	descriptor = record->mutation_physical | S2TTE_MEMATTR_FWB_NORMAL_WB |
			(writable ? S2TTE_AP_RW : (1UL << S2TTE_AP_SHIFT));
	return host_rmi_rtt_mapunprotected(realm->rd, record->mutation_ipa,
			3L, descriptor);
}

static bool handle_stage2_mutation(struct realm *realm,
		vmsa_realm_rec_record_t *record, bool *mapped, bool *writable)
{
	u_register_t result = REALM_ERROR;
	u_register_t top = 0U;

	inv_dcache_range((uintptr_t)record, sizeof(*record));
	if (record->mutation_status != VMSA_REALM_REC_MUTATION_REQUEST) {
		return false;
	}
	if (record->mutation_operation ==
			VMSA_REALM_REC_MUTATION_MAP_UNPROTECTED && !*mapped) {
		result = host_realm_map_unprotected(realm,
			record->mutation_physical, PAGE_SIZE);
		*mapped = result == REALM_SUCCESS;
		*writable = *mapped;
	} else if (record->mutation_operation ==
			VMSA_REALM_REC_MUTATION_UNMAP_UNPROTECTED && *mapped) {
		result = host_rmi_rtt_unmap_unprotected(realm->rd,
			record->mutation_ipa, 3L, &top);
		if (result == RMI_SUCCESS) {
			*mapped = false;
			*writable = false;
		}
	} else if ((record->mutation_operation ==
			VMSA_REALM_REC_MUTATION_PROTECT_READ_ONLY ||
			record->mutation_operation ==
			VMSA_REALM_REC_MUTATION_PROTECT_READ_WRITE) && *mapped) {
		bool requested_writable = record->mutation_operation ==
			VMSA_REALM_REC_MUTATION_PROTECT_READ_WRITE;
		bool previous_writable = *writable;

		result = host_rmi_rtt_unmap_unprotected(realm->rd,
			record->mutation_ipa, 3L, &top);
		if (result == RMI_SUCCESS) {
			result = map_existing_unprotected(realm, record,
					requested_writable);
			if (result == RMI_SUCCESS) {
				*writable = requested_writable;
			} else if (map_existing_unprotected(realm, record,
					previous_writable) != RMI_SUCCESS) {
				*mapped = false;
			}
		}
	}
	record->mutation_status = result == RMI_SUCCESS ||
			result == REALM_SUCCESS ? VMSA_REALM_REC_MUTATION_COMPLETE :
			VMSA_REALM_REC_MUTATION_FAILED;
	flush_dcache_range((uintptr_t)record, sizeof(*record));
	return true;
}

static void print_realm_failure_log(const uint8_t *buffer)
{
	char line[256];
	size_t length = 0U;

	for (size_t index = 0U; index < MAX_BUF_SIZE && buffer[index] != 0U; ++index) {
		if (buffer[index] == '\n' || length == sizeof(line) - 1U) {
			line[length] = '\0';
			(void)printf("VMSA-INFRA REALM_LOG %s\n", line);
			length = 0U;
		} else {
			line[length++] = (char)buffer[index];
		}
	}
	if (length != 0U) {
		line[length] = '\0';
		(void)printf("VMSA-INFRA REALM_LOG %s\n", line);
	}
}

static bool run_realm_lifecycle(uint8_t command, bool valid_abi,
		bool expect_entry_success)
{
	struct realm realm;
	u_register_t rec_flag[] = {RMI_RUNNABLE};
	u_register_t feature_flag = 0U;
	long start_level = RTT_MIN_LEVEL;
	bool entered;
	bool destroyed;
	bool created;
	u_register_t exit_reason;
	u_register_t enter_result;
	unsigned int host_call_result;
	struct rmi_rec_run *run;
	u_register_t source = 0U;
	u_register_t target = 0U;
	u_register_t unprotected = 0U;
	bool unprotected_mapped = false;
	bool unprotected_writable = false;
	uint64_t plan;
	vmsa_realm_rec_record_t *record;

	if (is_feat_52b_on_4k_2_supported()) {
		feature_flag = RMI_FEATURE_REGISTER_0_LPA2;
		start_level = RTT_MIN_LEVEL_LPA2;
	}
	if (command == REALM_VMSA_TEST_CMD && valid_abi) {
		created = host_create_realm_payload(&realm,
				(u_register_t)REALM_IMAGE_BASE, feature_flag, 0U,
				start_level, rec_flag, 1U, 0U, get_test_mecid());
	} else {
		created = host_create_activate_realm_payload(&realm,
				(u_register_t)REALM_IMAGE_BASE, feature_flag, 0U,
				start_level, rec_flag, 1U, 0U, get_test_mecid());
	}
	if (!created) {
		return false;
	}
	record = (vmsa_realm_rec_record_t *)host_get_shared_structure(
			&realm, PRIMARY_PLANE_ID, 0U)->realm_cmd_output_buffer;
	(void)memset(record, 0, sizeof(*record));
	record->abi_version = valid_abi ? VMSA_REALM_REC_ABI_VERSION :
			VMSA_REALM_REC_ABI_VERSION + 1U;
	record->abi_size = sizeof(*record);
	record->operation = VMSA_REALM_REC_RUN_CATALOG;
	record->status = VMSA_REALM_REC_STATUS_REQUEST;
	record->request_id = 1U;
	if (command == REALM_VMSA_TEST_CMD && valid_abi) {
		plan = vmsa_test_realm_stage2_plan();
		(void)printf("VMSA-INFRA REALM_PLAN checks=0x%llx\n",
			(unsigned long long)plan);
		if (plan != UINT64_C(0x3f)) {
			(void)host_destroy_realm(&realm);
			return false;
		}
		record->attributes = VMSA_REALM_REC_ATTR_READ_WRITE;
		source = (u_register_t)page_alloc(PAGE_SIZE);
		target = (u_register_t)page_alloc(PAGE_SIZE);
		if (source == 0U || target == 0U) {
			if (source != 0U) {
				page_free(source);
			}
			if (target != 0U) {
				page_free(target);
			}
			(void)host_destroy_realm(&realm);
			return false;
		}
		*(uint64_t *)source = UINT64_C(0x5245432d53322d4d);
		if (host_realm_delegate_map_protected_data(false, &realm,
				target, PAGE_SIZE, source) != REALM_SUCCESS) {
			page_free(source);
			if (host_rmi_granule_undelegate(target) == RMI_SUCCESS) {
				page_free(target);
			}
			(void)host_destroy_realm(&realm);
			return false;
		}
		page_free(source);
		record->ipa = target;
		record->physical = target;
		record->bytes = PAGE_SIZE;
		record->result = realm.ipa_ns_buffer + realm.ns_buffer_size;
		unprotected = (u_register_t)page_alloc(PAGE_SIZE);
		if (unprotected == 0U) {
			(void)host_destroy_realm(&realm);
			return false;
		}
		*(uint64_t *)unprotected = UINT64_C(0x5245432d554e5052);
		record->mutation_ipa = unprotected |
			(1UL << (EXTRACT(RMI_FEATURE_REGISTER_0_S2SZ,
				realm.rmm_feat_reg0) - 1UL));
		record->mutation_physical = unprotected;
		if (host_realm_activate(&realm) != REALM_SUCCESS) {
			page_free(unprotected);
			(void)host_destroy_realm(&realm);
			return false;
		}
	}
	host_shared_data_set_realm_cmd(&realm, command, PRIMARY_PLANE_ID, 0U);
	host_call_result = TEST_RESULT_FAIL;
	exit_reason = RMI_EXIT_INVALID;
	enter_result = host_realm_rec_enter(&realm, &exit_reason,
			&host_call_result, 0U);
	entered = enter_result == RMI_SUCCESS && exit_reason == RMI_EXIT_HOST_CALL &&
			host_call_result == TEST_RESULT_SUCCESS;
	while (!entered && enter_result == RMI_SUCCESS &&
			command == REALM_VMSA_TEST_CMD && valid_abi) {
		run = (struct rmi_rec_run *)realm.run[0U];
		if (run->exit.exit_reason == RMI_EXIT_HOST_CALL &&
				run->exit.imm == VMSA_REALM_REC_MUTATION_HOST_CALL) {
			/* SEA injection is one-shot. Do not replay its entry flag when the
			 * recovered REC subsequently requests another host mutation. */
			run->entry.flags = 0U;
			if (!handle_stage2_mutation(&realm, record,
					&unprotected_mapped, &unprotected_writable)) {
				break;
			}
		} else if (run->exit.exit_reason == RMI_EXIT_SYNC &&
				EC_BITS(run->exit.esr) == EC_DABORT_LOWER_EL) {
			record->esr = run->exit.esr;
			record->far = run->exit.far;
			record->hpfar = run->exit.hpfar;
			record->hpfar_valid = 1U;
			record->status = VMSA_REALM_REC_STATUS_FAULT_PENDING;
			flush_dcache_range((uintptr_t)record, sizeof(*record));
			run->entry.flags = REC_ENTRY_FLAG_INJECT_SEA;
		} else {
			break;
		}
		host_call_result = TEST_RESULT_FAIL;
		exit_reason = RMI_EXIT_INVALID;
		enter_result = host_realm_rec_enter(&realm, &exit_reason,
				&host_call_result, 0U);
		entered = enter_result == RMI_SUCCESS &&
			exit_reason == RMI_EXIT_HOST_CALL &&
			host_call_result == TEST_RESULT_SUCCESS;
	}
	if (command == REALM_VMSA_TEST_CMD && valid_abi) {
		(void)printf("VMSA-INFRA REC_RESULT status=%u result=0x%llx\n",
			record->status, (unsigned long long)record->result);
		if (record->status == VMSA_REALM_REC_STATUS_FAILED) {
			print_realm_failure_log(host_get_shared_structure(
				&realm, PRIMARY_PLANE_ID, 0U)->log_buffer);
		}
		entered = entered &&
			record->status == VMSA_REALM_REC_STATUS_COMPLETE &&
			record->request_id == 1U;
		(void)memcpy(vmsa_protocol_output,
			host_get_shared_structure(&realm, PRIMARY_PLANE_ID, 0U)->log_buffer,
			sizeof(vmsa_protocol_output));
		vmsa_protocol_output[sizeof(vmsa_protocol_output) - 1U] = '\0';
	}
	if (unprotected_mapped) {
		u_register_t top;

		if (host_rmi_rtt_unmap_unprotected(realm.rd,
				record->mutation_ipa, 3L, &top) != RMI_SUCCESS) {
			entered = false;
		}
	}
	destroyed = host_destroy_realm(&realm);
	if (unprotected != 0U) {
		page_free(unprotected);
	}
	return entered == expect_entry_success && destroyed;
}

test_result_t test_vmsa_realm_stage2_lifecycle(void)
{
	vmsa_protocol_output[0] = '\0';
	if (!run_realm_lifecycle(REALM_VMSA_TEST_CMD, true, true) ||
			!run_realm_lifecycle(REALM_VMSA_TEST_CMD, false, false) ||
			!run_realm_lifecycle(REALM_GET_RSI_VERSION, true, true)) {
		(void)printf("VMSA-INFRA HARNESS_FAILURE realm-lifecycle\n");
		return TEST_RESULT_FAIL;
	}
	(void)printf("%s", vmsa_protocol_output);
	return TEST_RESULT_SUCCESS;
}
