#![no_std]

pub const LOWER_EL_MAILBOX_ABI_VERSION: u64 = 2;
pub const REALM_REC_ABI_VERSION: u32 = 2;
pub const REALM_REC_RUN_CATALOG: u32 = 1;
pub const REALM_REC_ATTR_READ_WRITE: u64 = 1;
pub const REALM_REC_STATUS_REQUEST: u32 = 0;
pub const REALM_REC_STATUS_RUNNING: u32 = 1;
pub const REALM_REC_STATUS_COMPLETE: u32 = 2;
pub const REALM_REC_STATUS_FAILED: u32 = 3;
pub const REALM_REC_STATUS_FAULT_PENDING: u32 = 4;
pub const REALM_REC_MUTATION_NONE: u64 = 0;
pub const REALM_REC_MUTATION_MAP_UNPROTECTED: u64 = 1;
pub const REALM_REC_MUTATION_UNMAP_UNPROTECTED: u64 = 2;
pub const REALM_REC_MUTATION_PROTECT_READ_ONLY: u64 = 3;
pub const REALM_REC_MUTATION_PROTECT_READ_WRITE: u64 = 4;
pub const REALM_REC_MUTATION_IDLE: u64 = 0;
pub const REALM_REC_MUTATION_REQUEST: u64 = 1;
pub const REALM_REC_MUTATION_COMPLETE: u64 = 2;
pub const REALM_REC_MUTATION_FAILED: u64 = 3;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RealmRecRecord {
    pub abi_version: u32,
    pub abi_size: u32,
    pub operation: u32,
    pub status: u32,
    pub request_id: u64,
    pub ipa: u64,
    pub physical: u64,
    pub bytes: u64,
    pub attributes: u64,
    pub result: u64,
    pub esr: u64,
    pub far: u64,
    pub hpfar: u64,
    pub hpfar_valid: u64,
    pub mutation_operation: u64,
    pub mutation_status: u64,
    pub mutation_ipa: u64,
    pub mutation_physical: u64,
}

const _: () = {
    assert!(core::mem::size_of::<RealmRecRecord>() == 128);
    assert!(core::mem::align_of::<RealmRecRecord>() == 8);
};

impl RealmRecRecord {
    pub fn fields_valid(&self) -> bool {
        self.abi_version == REALM_REC_ABI_VERSION
            && self.abi_size as usize == core::mem::size_of::<Self>()
            && self.operation == REALM_REC_RUN_CATALOG
            && self.status == REALM_REC_STATUS_RUNNING
            && self.request_id != 0
            && self.ipa != 0
            && self.ipa.is_multiple_of(4096)
            && self.physical != 0
            && self.physical.is_multiple_of(4096)
            && self.bytes == 4096
            && self.attributes == REALM_REC_ATTR_READ_WRITE
            && self.mutation_operation == REALM_REC_MUTATION_NONE
            && self.mutation_status == REALM_REC_MUTATION_IDLE
            && self.mutation_ipa != 0
            && self.mutation_ipa.is_multiple_of(4096)
            && self.mutation_physical != 0
            && self.mutation_physical.is_multiple_of(4096)
    }

    /// Validates the host-owned Realm/REC request before payload execution.
    ///
    /// # Safety
    ///
    /// `pointer` must identify writable host/Realm shared memory for the
    /// duration of the payload entry.
    pub unsafe fn from_abi<'a>(pointer: *mut Self) -> Option<&'a mut Self> {
        if pointer.is_null() || !pointer.addr().is_multiple_of(core::mem::align_of::<Self>()) {
            return None;
        }
        // SAFETY: The caller supplies writable shared storage and the checks
        // below are performed before any optional request field is consumed.
        let record = unsafe { &mut *pointer };
        if !record.fields_valid() {
            return None;
        }
        Some(record)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LowerElMailbox {
    pub abi_version: u64,
    pub abi_size: u64,
    pub reserved: [u64; 2],
    pub operation: u64,
    pub return_conduit: u64,
    pub exception_state: u64,
    pub target: u64,
    pub address: u64,
    pub width: u64,
    pub value: u64,
    pub second_value: u64,
    pub status: u64,
    pub result: u64,
    pub second_result: u64,
    pub esr: u64,
    pub far: u64,
    pub hpfar_valid: u64,
    pub hpfar: u64,
    pub elr: u64,
    pub spsr: u64,
}

impl LowerElMailbox {
    pub fn fields_valid(&self) -> bool {
        self.abi_version == LOWER_EL_MAILBOX_ABI_VERSION
            && self.abi_size as usize == core::mem::size_of::<Self>()
            && self.reserved == [0; 2]
            && self.operation <= 10
            && self.target <= 2
            && self.width <= 3
            && (self.operation <= 1 || self.width == 3)
            && self.exception_state != 0
            && self.exception_state & 0x7 == 0
            && self.hpfar_valid <= 1
    }
}

const _: () = {
    assert!(core::mem::size_of::<LowerElMailbox>() == 168);
    assert!(core::mem::align_of::<LowerElMailbox>() == 8);
};
