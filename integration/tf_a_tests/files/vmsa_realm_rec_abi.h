#ifndef VMSA_REALM_REC_ABI_H
#define VMSA_REALM_REC_ABI_H

#include <stdint.h>

#define VMSA_REALM_REC_ABI_VERSION UINT32_C(2)
#define VMSA_REALM_REC_RUN_CATALOG UINT32_C(1)
#define VMSA_REALM_REC_ATTR_READ_WRITE UINT64_C(1)

#define VMSA_REALM_REC_STATUS_REQUEST UINT32_C(0)
#define VMSA_REALM_REC_STATUS_RUNNING UINT32_C(1)
#define VMSA_REALM_REC_STATUS_COMPLETE UINT32_C(2)
#define VMSA_REALM_REC_STATUS_FAILED UINT32_C(3)
#define VMSA_REALM_REC_STATUS_FAULT_PENDING UINT32_C(4)

#define VMSA_REALM_REC_MUTATION_NONE UINT64_C(0)
#define VMSA_REALM_REC_MUTATION_MAP_UNPROTECTED UINT64_C(1)
#define VMSA_REALM_REC_MUTATION_UNMAP_UNPROTECTED UINT64_C(2)
#define VMSA_REALM_REC_MUTATION_PROTECT_READ_ONLY UINT64_C(3)
#define VMSA_REALM_REC_MUTATION_PROTECT_READ_WRITE UINT64_C(4)
#define VMSA_REALM_REC_MUTATION_IDLE UINT64_C(0)
#define VMSA_REALM_REC_MUTATION_REQUEST UINT64_C(1)
#define VMSA_REALM_REC_MUTATION_COMPLETE UINT64_C(2)
#define VMSA_REALM_REC_MUTATION_FAILED UINT64_C(3)
#define VMSA_REALM_REC_MUTATION_HOST_CALL UINT16_C(0x5653)

typedef struct vmsa_realm_rec_record {
	uint32_t abi_version;
	uint32_t abi_size;
	uint32_t operation;
	uint32_t status;
	uint64_t request_id;
	uint64_t ipa;
	uint64_t physical;
	uint64_t bytes;
	uint64_t attributes;
	uint64_t result;
	uint64_t esr;
	uint64_t far;
	uint64_t hpfar;
	uint64_t hpfar_valid;
	uint64_t mutation_operation;
	uint64_t mutation_status;
	uint64_t mutation_ipa;
	uint64_t mutation_physical;
} vmsa_realm_rec_record_t;

_Static_assert(sizeof(vmsa_realm_rec_record_t) == 128U,
		"Realm REC ABI size mismatch");
_Static_assert(_Alignof(vmsa_realm_rec_record_t) == 8U,
		"Realm REC ABI alignment mismatch");

#endif
