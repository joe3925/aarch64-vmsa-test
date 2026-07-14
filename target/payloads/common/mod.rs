use core::sync::atomic::{AtomicUsize, Ordering};

use vmsa_test_abi::{
    LOWER_EL_MAILBOX_ABI_VERSION, LowerElMailbox, REALM_REC_ABI_VERSION, REALM_REC_ATTR_READ_WRITE,
    REALM_REC_MUTATION_IDLE, REALM_REC_MUTATION_NONE, REALM_REC_RUN_CATALOG,
    REALM_REC_STATUS_RUNNING, RealmRecRecord,
};
use vmsa_test_architecture::exception::{FatalExceptionGuard, RawFault, VectorGuard};
use vmsa_test_architecture::registers::{
    self, D128Stage1State, D128Stage2State, GeometryStage1State, Stage1State, Stage2State,
};
use vmsa_test_architecture::transition::{LowerElReturnConduit, LowerElStage1Mode};
use vmsa_test_architecture::{GuardedResult, guarded_execute, guarded_read, guarded_write};
use vmsa_test_harness::adapter::{
    AccessRequest, ByteSink, InstalledTranslation, LowerElCommand, LowerElRequest, ProtocolWriter,
    ReportEvent, RunnerOutcome, TestMemory, normalize_fault, prepare_lower_runtime,
    prepare_lower_runtime_d128, read_capabilities,
};
use vmsa_test_harness::{
    AccessKind, AccessOperation, AccessResult, AddressBits, Capabilities, HarnessError,
    LookupLevel, ObservedFault, TranslationSetup, TranslationStage,
};

unsafe extern "C" {
    static __DATA_START__: u8;
}

pub const REGIME_NORMAL: u8 = 0;
pub const REGIME_SECURE: u8 = 1;
pub const REGIME_REALM: u8 = 2;
pub const REGIME_ROOT: u8 = 3;
pub const BOOT_CONTEXT_ABI_VERSION: u32 = 3;

pub fn panic_callback_address() -> u64 {
    core::ptr::addr_of!(PANIC_CALLBACK) as u64
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BootContext {
    pub abi_version: u32,
    pub abi_size: u32,
    pub memory_virtual: *mut u8,
    pub memory_physical: u64,
    pub memory_bytes: usize,
    pub uart_write: Option<unsafe extern "C" fn(byte: u8)>,
    pub lower_el_entry: u64,
    pub lower_el_stack: u64,
    pub filter: *const u8,
    pub filter_bytes: usize,
    pub run_on_secondary: Option<
        unsafe extern "C" fn(
            entry: unsafe extern "C" fn(argument: *mut u8),
            argument: *mut u8,
        ) -> i32,
    >,
    pub reserved: [u64; 2],
}

const _: () = {
    assert!(core::mem::size_of::<BootContext>() == 96);
    assert!(core::mem::align_of::<BootContext>() == 8);
};

impl SecondaryAccess {
    fn fields_valid(&self) -> bool {
        self.abi_version == SECONDARY_ACCESS_ABI_VERSION
            && self.abi_size as usize == core::mem::size_of::<Self>()
            && self.reserved == [0; 2]
            && self.access_request().is_some()
    }

    fn access_request(&self) -> Option<AccessRequest> {
        let width = match self.width {
            0 => vmsa_test_architecture::AccessWidth::Byte,
            1 => vmsa_test_architecture::AccessWidth::Half,
            2 => vmsa_test_architecture::AccessWidth::Word,
            3 => vmsa_test_architecture::AccessWidth::Double,
            _ => return None,
        };
        let mut request = match (self.kind, self.operation) {
            (0, 0) => AccessRequest::read(self.address, width),
            (1, 0) => AccessRequest::write(self.address, width, self.value),
            (2, 0) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::execute(self.address)
            }
            (0, 1) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::read_acquire(self.address)
            }
            (1, 2) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::write_release(self.address, self.value)
            }
            (1, 3) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::atomic_swap(self.address, self.value)
            }
            (1, 4) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::exclusive_add(self.address, self.value)
            }
            (0, 5) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::read_pair(self.address)
            }
            (1, 6) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::write_pair(self.address, self.value, self.second_value)
            }
            (0 | 1, 7) if width == vmsa_test_architecture::AccessWidth::Double => {
                AccessRequest::translate(self.address, self.kind == 1)
            }
            _ => return None,
        };
        request.second_value = self.second_value;
        Some(request)
    }

    fn observed_fault(&self) -> Option<ObservedFault> {
        let class = match self.fault_class {
            0 => vmsa_test_harness::FaultClass::DataAbort,
            1 => vmsa_test_harness::FaultClass::InstructionAbort,
            value if (0x100..=0x1ff).contains(&value) => {
                vmsa_test_harness::FaultClass::Other(value as u8)
            }
            _ => return None,
        };
        let status = match self.fault_status {
            1 => vmsa_test_harness::FaultStatus::AddressSize,
            2 => vmsa_test_harness::FaultStatus::Translation,
            3 => vmsa_test_harness::FaultStatus::AccessFlag,
            4 => vmsa_test_harness::FaultStatus::Permission,
            5 => vmsa_test_harness::FaultStatus::Alignment,
            6 => vmsa_test_harness::FaultStatus::External,
            7 => vmsa_test_harness::FaultStatus::GranuleProtection,
            8 => vmsa_test_harness::FaultStatus::TagCheck,
            9 => vmsa_test_harness::FaultStatus::TlbConflict,
            10 => vmsa_test_harness::FaultStatus::UnsupportedAtomicUpdate,
            value if (0x100..=0x1ff).contains(&value) => {
                vmsa_test_harness::FaultStatus::Other(value as u8)
            }
            _ => return None,
        };
        let level = if self.fault_level == u64::MAX {
            None
        } else {
            let value = self.fault_level as i64;
            Some(vmsa_test_harness::LookupLevel::new(
                i8::try_from(value).ok()?,
            )?)
        };
        let access = match self.fault_access {
            0 => AccessKind::Read,
            1 => AccessKind::Write,
            2 => AccessKind::Execute,
            _ => return None,
        };
        let stage = match self.fault_stage {
            0 => vmsa_test_harness::FaultStage::Stage1,
            1 => vmsa_test_harness::FaultStage::Stage2,
            2 => vmsa_test_harness::FaultStage::Unknown,
            _ => return None,
        };
        if self.fault_ipa_valid > 1 {
            return None;
        }
        Some(ObservedFault {
            class,
            status,
            level,
            address: self.fault_address,
            ipa: (self.fault_ipa_valid == 1).then_some(self.fault_ipa),
            access,
            stage,
        })
    }
}

fn perform_arch_access(request: AccessRequest) -> AccessResult {
    let result = match (request.kind, request.operation) {
        (AccessKind::Read, AccessOperation::Plain) => guarded_read(request.address, request.width),
        (AccessKind::Write, AccessOperation::Plain) => {
            guarded_write(request.address, request.width, request.value)
        }
        (AccessKind::Execute, AccessOperation::Plain) => guarded_execute(request.address),
        (AccessKind::Read, AccessOperation::Acquire) => {
            vmsa_test_architecture::guarded_read_acquire(request.address)
        }
        (AccessKind::Write, AccessOperation::Release) => {
            vmsa_test_architecture::guarded_write_release(request.address, request.value)
        }
        (AccessKind::Write, AccessOperation::AtomicSwap) => {
            vmsa_test_architecture::guarded_atomic_swap(request.address, request.value)
        }
        (AccessKind::Write, AccessOperation::ExclusiveAdd) => {
            vmsa_test_architecture::guarded_exclusive_add(request.address, request.value)
        }
        (AccessKind::Read, AccessOperation::PairRead) => {
            return match vmsa_test_architecture::guarded_read_pair(request.address) {
                Ok(vmsa_test_architecture::GuardedPairResult::Completed { first, second }) => {
                    AccessResult::CompletedPair { first, second }
                }
                Ok(vmsa_test_architecture::GuardedPairResult::Fault(raw)) => {
                    AccessResult::Fault(normalize_fault(raw, AccessKind::Read))
                }
                Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
            };
        }
        (AccessKind::Write, AccessOperation::PairWrite) => {
            return match vmsa_test_architecture::guarded_write_pair(
                request.address,
                request.value,
                request.second_value,
            ) {
                Ok(vmsa_test_architecture::GuardedPairResult::Completed { first, second }) => {
                    AccessResult::CompletedPair { first, second }
                }
                Ok(vmsa_test_architecture::GuardedPairResult::Fault(raw)) => {
                    AccessResult::Fault(normalize_fault(raw, AccessKind::Write))
                }
                Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
            };
        }
        _ => return AccessResult::HarnessFailure(HarnessError::InvalidState),
    };
    match result {
        Ok(GuardedResult::Completed(value)) => AccessResult::Completed { value },
        Ok(GuardedResult::Fault(raw)) => AccessResult::Fault(normalize_fault(raw, request.kind)),
        Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
    }
}

impl BootContext {
    fn header_valid(&self) -> bool {
        self.abi_version == BOOT_CONTEXT_ABI_VERSION
            && self.abi_size as usize == core::mem::size_of::<Self>()
            && self.reserved == [0; 2]
    }

    fn fields_valid(&self, regime: u8) -> bool {
        let virtual_start = self.memory_virtual as usize;
        let lower_pair_valid = (self.lower_el_entry == 0 && self.lower_el_stack == 0)
            || (self.lower_el_entry != 0
                && self.lower_el_entry & 0x3 == 0
                && self.lower_el_stack != 0
                && self.lower_el_stack & 0xf == 0);
        regime <= REGIME_ROOT
            && self.uart_write.is_some()
            && lower_pair_valid
            && virtual_start.checked_add(self.memory_bytes).is_some()
            && self
                .memory_physical
                .checked_add(self.memory_bytes as u64)
                .is_some()
            && (self.filter_bytes == 0
                || (!self.filter.is_null()
                    && self.filter_bytes <= 4096
                    && self.filter.addr().checked_add(self.filter_bytes).is_some()))
    }

    /// Validates the common firmware ABI header before an adapter dereferences
    /// any optional field or installs architecture state.
    ///
    /// # Safety
    ///
    /// `pointer` must either be null or identify readable firmware-owned
    /// storage large enough for the ABI header.
    pub unsafe fn from_abi<'a>(pointer: *const Self) -> Result<&'a Self, AdapterError> {
        if pointer.is_null() || !pointer.addr().is_multiple_of(core::mem::align_of::<Self>()) {
            return Err(AdapterError::InvalidContext);
        }
        // SAFETY: Alignment and nullness were checked above; readability is
        // the firmware entry contract stated by every exported entry point.
        let context = unsafe { &*pointer };
        if !context.header_valid() {
            return Err(AdapterError::InvalidContext);
        }
        Ok(context)
    }
}

pub struct CallbackSink {
    callback: unsafe extern "C" fn(u8),
}

impl ByteSink for CallbackSink {
    fn write_byte(&mut self, byte: u8) {
        // SAFETY: Firmware guarantees the callback remains valid for payload entry.
        unsafe { (self.callback)(byte) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    InvalidContext,
    TranslationAlreadyInstalled,
    TranslationTokenMismatch,
    UnsupportedStage,
    ArchitecturalState,
    RestorationFailed,
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterState {
    Uninitialized,
    Ready,
    TestScoped,
    TranslationInstalled,
    LowerElActive,
    SecondaryActive,
    RealmActive,
    Restoring,
    Corrupted,
    Finished,
}

enum SavedTranslation {
    Stage1(Stage1State),
    Stage1Geometry(GeometryStage1State),
    Stage1D128(D128Stage1State),
    LowerStage1(Stage1State),
    LowerStage1D128(D128Stage1State),
    Stage2(Stage2State),
    Stage2D128(D128Stage2State),
}

struct ActiveTranslation {
    token: InstalledTranslation,
    saved: SavedTranslation,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SecondaryAccess {
    abi_version: u32,
    abi_size: u32,
    reserved: [u64; 2],
    ttbr: u64,
    tcr: u64,
    mair: u64,
    kind: u64,
    operation: u64,
    width: u64,
    address: u64,
    value: u64,
    second_value: u64,
    status: u64,
    result: u64,
    second_result: u64,
    fault_class: u64,
    fault_status: u64,
    fault_level: u64,
    fault_address: u64,
    fault_ipa_valid: u64,
    fault_ipa: u64,
    fault_access: u64,
    fault_stage: u64,
}

const SECONDARY_ACCESS_ABI_VERSION: u32 = 2;
const _: () = {
    assert!(core::mem::size_of::<SecondaryAccess>() == 184);
    assert!(core::mem::align_of::<SecondaryAccess>() == 8);
};

unsafe extern "C" fn secondary_access_entry(argument: *mut u8) {
    let pointer = argument.cast::<SecondaryAccess>();
    if pointer.is_null()
        || !pointer
            .addr()
            .is_multiple_of(core::mem::align_of::<SecondaryAccess>())
    {
        return;
    }
    // SAFETY: The synchronous firmware callback preserves the primary-owned
    // command block until this entry returns.
    let request = unsafe { &mut *pointer };
    if !request.fields_valid() {
        request.status = 4;
        return;
    }
    let vectors = VectorGuard::install();
    // SAFETY: The primary adapter supplies a live shared root and the firmware
    // callback gives this PE exclusive execution until this function returns.
    let Some(saved) =
        (unsafe { registers::install_stage1(request.ttbr, request.tcr, request.mair) })
    else {
        request.status = 1;
        return;
    };
    let Some(access) = request.access_request() else {
        request.status = 4;
        return;
    };
    let access_result = if access.operation == AccessOperation::Translate {
        let translation_access = if access.kind == AccessKind::Write {
            vmsa_test_architecture::translation::TranslationAccess::Write
        } else {
            vmsa_test_architecture::translation::TranslationAccess::Read
        };
        vmsa_test_architecture::translation::current_stage1(access.address, translation_access)
            .map_or(
                AccessResult::HarnessFailure(HarnessError::InvalidState),
                |value| AccessResult::Completed { value },
            )
    } else {
        perform_arch_access(access)
    };
    match access_result {
        AccessResult::Completed { value } => {
            request.result = value;
            request.status = 0;
        }
        AccessResult::CompletedPair { first, second } => {
            request.result = first;
            request.second_result = second;
            request.status = 1;
        }
        AccessResult::Fault(fault) => {
            request.fault_class = match fault.class {
                vmsa_test_harness::FaultClass::DataAbort => 0,
                vmsa_test_harness::FaultClass::InstructionAbort => 1,
                vmsa_test_harness::FaultClass::Other(value) => 0x100 | u64::from(value),
            };
            request.fault_status = fault.status_code();
            request.fault_level = fault
                .level
                .map_or(u64::MAX, |level| level.get() as i64 as u64);
            request.fault_address = fault.address;
            request.fault_ipa_valid = fault.ipa.is_some() as u64;
            request.fault_ipa = fault.ipa.unwrap_or(0);
            request.fault_access = access_kind_code(fault.access);
            request.fault_stage = match fault.stage {
                vmsa_test_harness::FaultStage::Stage1 => 0,
                vmsa_test_harness::FaultStage::Stage2 => 1,
                vmsa_test_harness::FaultStage::Unknown => 2,
            };
            request.status = 2;
        }
        AccessResult::HarnessFailure(_) => request.status = 3,
    }
    // SAFETY: `saved` was captured on this PE immediately above.
    if !unsafe { registers::restore_stage1(saved) } {
        request.status = 5;
    }
    drop(vectors);
}

pub struct AdapterCore {
    state: AdapterState,
    capabilities: Capabilities,
    memory: TestMemory,
    reporter: ProtocolWriter<CallbackSink>,
    vectors: Option<VectorGuard>,
    fatal_exceptions: Option<FatalExceptionGuard>,
    installed_current_stage1: Option<ActiveTranslation>,
    installed_lower_stage1: Option<ActiveTranslation>,
    installed_stage2: Option<ActiveTranslation>,
    generation: u64,
    lower_el_entry: u64,
    lower_el_stack: u64,
    installed_lower_stack: Option<u64>,
    lower_el_stage1: LowerElStage1Mode,
    lower_el_return: LowerElReturnConduit,
    regime: u8,
    arena_physical: u64,
    arena_bytes: usize,
    arena_offset: u64,
    run_on_secondary: Option<
        unsafe extern "C" fn(
            entry: unsafe extern "C" fn(argument: *mut u8),
            argument: *mut u8,
        ) -> i32,
    >,
    secondary_previous: Option<AdapterState>,
    external_fault_source: Option<fn() -> Option<RawFault>>,
    realm_stage2_region: Option<vmsa_test_harness::RealmStage2Region>,
    realm_stage2_mutation: Option<unsafe extern "C" fn(u64) -> u32>,
    realm_stage2_mapped: bool,
}

impl AdapterCore {
    pub fn from_boot(
        context: &BootContext,
        regime: u8,
        lower_el_stage1: LowerElStage1Mode,
        lower_el_return: LowerElReturnConduit,
    ) -> Result<(Self, Option<&str>), AdapterError> {
        if !context.fields_valid(regime) {
            return Err(AdapterError::InvalidContext);
        }
        let callback = context.uart_write.ok_or(AdapterError::InvalidContext)?;
        // SAFETY: Firmware reserves this aligned region exclusively for the harness.
        let memory = unsafe {
            TestMemory::new(
                context.memory_virtual,
                context.memory_physical,
                context.memory_bytes,
            )
        }
        .map_err(|_| AdapterError::InvalidContext)?;
        let filter = if context.filter_bytes == 0 {
            None
        } else {
            // SAFETY: Firmware supplies immutable UTF-8 filter storage for the call.
            let bytes =
                unsafe { core::slice::from_raw_parts(context.filter, context.filter_bytes) };
            Some(core::str::from_utf8(bytes).map_err(|_| AdapterError::InvalidContext)?)
        };
        PANIC_CALLBACK.store(callback as usize, Ordering::Release);
        let capabilities = read_capabilities();
        let fatal_exceptions = FatalExceptionGuard::install(fatal_exception);
        let vectors = VectorGuard::install();
        let mut core = Self {
            state: AdapterState::Uninitialized,
            capabilities,
            memory,
            reporter: ProtocolWriter::new(CallbackSink { callback }),
            vectors: Some(vectors),
            fatal_exceptions: Some(fatal_exceptions),
            installed_current_stage1: None,
            installed_lower_stage1: None,
            installed_stage2: None,
            generation: 0,
            lower_el_entry: context.lower_el_entry,
            lower_el_stack: context.lower_el_stack,
            installed_lower_stack: None,
            lower_el_stage1,
            lower_el_return,
            regime,
            arena_physical: context.memory_physical,
            arena_bytes: context.memory_bytes,
            arena_offset: (context.memory_virtual as u64).wrapping_sub(context.memory_physical),
            run_on_secondary: context.run_on_secondary,
            secondary_previous: None,
            external_fault_source: None,
            realm_stage2_region: None,
            realm_stage2_mutation: None,
            realm_stage2_mapped: false,
        };
        core.initialize()?;
        Ok((core, filter))
    }

    fn initialize(&mut self) -> Result<(), AdapterError> {
        if self.state != AdapterState::Uninitialized {
            return Err(AdapterError::InvalidTransition);
        }
        self.state = AdapterState::Ready;
        Ok(())
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub fn memory_pas(&self) -> vmsa_test_harness::PhysicalAddressSpace {
        match self.regime {
            REGIME_NORMAL => vmsa_test_harness::PhysicalAddressSpace::NonSecure,
            REGIME_SECURE => vmsa_test_harness::PhysicalAddressSpace::Secure,
            REGIME_REALM => vmsa_test_harness::PhysicalAddressSpace::Realm,
            REGIME_ROOT => vmsa_test_harness::PhysicalAddressSpace::Root,
            _ => unreachable!(),
        }
    }
    pub fn transition_runtime_data(&self) -> [u64; 2] {
        [
            core::ptr::addr_of!(__DATA_START__) as u64,
            panic_callback_address(),
        ]
    }
    pub fn realm_rec_is_current(&self) -> bool {
        self.regime == REGIME_REALM && registers::current_el() == 1
    }
    pub fn set_external_fault_source(&mut self, source: Option<fn() -> Option<RawFault>>) {
        self.external_fault_source = source;
    }
    pub fn set_realm_stage2_service(
        &mut self,
        service: Option<(
            vmsa_test_harness::RealmStage2Region,
            unsafe extern "C" fn(u64) -> u32,
        )>,
    ) {
        let (region, mutation) = service.map_or((None, None), |(region, mutation)| {
            (Some(region), Some(mutation))
        });
        self.realm_stage2_region = region;
        self.realm_stage2_mutation = mutation;
    }
    pub fn begin_realm_stage2_session(
        &mut self,
    ) -> Result<vmsa_test_harness::RealmStage2Region, vmsa_test_harness::HarnessError> {
        if self.state != AdapterState::TestScoped
            || !self.realm_rec_is_current()
            || self.realm_stage2_mapped
        {
            return Err(vmsa_test_harness::HarnessError::InvalidState);
        }
        let region = self
            .realm_stage2_region
            .ok_or(vmsa_test_harness::HarnessError::Environment)?;
        if self.realm_stage2_mutation.is_none() {
            return Err(vmsa_test_harness::HarnessError::Environment);
        }
        self.state = AdapterState::RealmActive;
        Ok(region)
    }
    pub fn mutate_realm_stage2(
        &mut self,
        mutation: vmsa_test_harness::RealmStage2Mutation,
    ) -> Result<(), vmsa_test_harness::HarnessError> {
        if self.state != AdapterState::RealmActive {
            return Err(vmsa_test_harness::HarnessError::InvalidState);
        }
        let requires_mapping = !matches!(
            mutation,
            vmsa_test_harness::RealmStage2Mutation::MapUnprotected
        );
        if self.realm_stage2_mapped != requires_mapping {
            return Err(vmsa_test_harness::HarnessError::InvalidState);
        }
        let operation = match mutation {
            vmsa_test_harness::RealmStage2Mutation::MapUnprotected => 1,
            vmsa_test_harness::RealmStage2Mutation::UnmapUnprotected => 2,
            vmsa_test_harness::RealmStage2Mutation::ProtectReadOnly => 3,
            vmsa_test_harness::RealmStage2Mutation::ProtectReadWrite => 4,
        };
        let callback = self
            .realm_stage2_mutation
            .ok_or(vmsa_test_harness::HarnessError::Environment)?;
        // SAFETY: Realm payload construction installs its synchronous RSI-backed
        // callback and the shared record remains live until payload return.
        if unsafe { callback(operation) } != 0 {
            return Err(vmsa_test_harness::HarnessError::Environment);
        }
        self.realm_stage2_mapped = !matches!(
            mutation,
            vmsa_test_harness::RealmStage2Mutation::UnmapUnprotected
        );
        Ok(())
    }
    pub fn end_realm_stage2_session(&mut self) -> Result<(), vmsa_test_harness::HarnessError> {
        if self.state != AdapterState::RealmActive || self.realm_stage2_mapped {
            return Err(vmsa_test_harness::HarnessError::InvalidState);
        }
        self.state = AdapterState::TestScoped;
        Ok(())
    }
    pub fn begin_test_scope(&mut self) -> Result<(), AdapterError> {
        if self.state != AdapterState::Ready {
            return Err(AdapterError::InvalidTransition);
        }
        self.state = AdapterState::TestScoped;
        Ok(())
    }
    pub fn verify_invalid_transition_rejected(&mut self) -> bool {
        if self.state != AdapterState::TestScoped {
            return false;
        }
        let rejected = matches!(
            self.begin_test_scope(),
            Err(AdapterError::InvalidTransition)
        );
        let state_preserved = self.state == AdapterState::TestScoped;
        rejected && state_preserved
    }
    pub fn verify_common_abi_rejection(&self) -> bool {
        unsafe extern "C" fn ignored_callback(_: u8) {}
        let valid = BootContext {
            abi_version: BOOT_CONTEXT_ABI_VERSION,
            abi_size: core::mem::size_of::<BootContext>() as u32,
            memory_virtual: self.arena_physical.wrapping_add(self.arena_offset) as *mut u8,
            memory_physical: self.arena_physical,
            memory_bytes: self.arena_bytes,
            uart_write: Some(ignored_callback),
            lower_el_entry: self.lower_el_entry,
            lower_el_stack: self.lower_el_stack,
            filter: core::ptr::null(),
            filter_bytes: 0,
            run_on_secondary: self.run_on_secondary,
            reserved: [0; 2],
        };
        if !valid.header_valid() || !valid.fields_valid(self.regime) {
            return false;
        }
        // SAFETY: Null and deliberately misaligned pointers are rejected before
        // dereference by the firmware-entry ABI parser.
        if unsafe { BootContext::from_abi(core::ptr::null()) }.is_ok()
            || unsafe { BootContext::from_abi(core::ptr::dangling::<u8>().cast()) }.is_ok()
        {
            return false;
        }
        let mut candidate = valid;
        candidate.abi_version = candidate.abi_version.wrapping_add(1);
        if candidate.header_valid() {
            return false;
        }
        candidate = valid;
        candidate.abi_size = candidate.abi_size.wrapping_sub(1);
        if candidate.header_valid() {
            return false;
        }
        candidate = valid;
        candidate.reserved[1] = 1;
        if candidate.header_valid() {
            return false;
        }
        candidate = valid;
        candidate.uart_write = None;
        if candidate.fields_valid(self.regime) {
            return false;
        }
        candidate = valid;
        candidate.lower_el_entry = 4;
        candidate.lower_el_stack = 0;
        if candidate.fields_valid(self.regime) {
            return false;
        }
        candidate = valid;
        candidate.filter_bytes = 1;
        if candidate.fields_valid(self.regime) {
            return false;
        }
        candidate = valid;
        candidate.memory_bytes = usize::MAX;
        if candidate.fields_valid(self.regime) || valid.fields_valid(REGIME_ROOT + 1) {
            return false;
        }
        let secondary = SecondaryAccess {
            abi_version: SECONDARY_ACCESS_ABI_VERSION,
            abi_size: core::mem::size_of::<SecondaryAccess>() as u32,
            reserved: [0; 2],
            ttbr: 0,
            tcr: 0,
            mair: 0,
            kind: 0,
            operation: 0,
            width: 3,
            address: 0,
            value: 0,
            second_value: 0,
            status: 0,
            result: 0,
            second_result: 0,
            fault_class: 0,
            fault_status: 0,
            fault_level: u64::MAX,
            fault_address: 0,
            fault_ipa_valid: 0,
            fault_ipa: 0,
            fault_access: 0,
            fault_stage: 0,
        };
        let mut invalid_secondary = secondary;
        invalid_secondary.abi_size = 0;
        if !secondary.fields_valid() || invalid_secondary.fields_valid() {
            return false;
        }
        invalid_secondary = secondary;
        invalid_secondary.abi_version = 0;
        if invalid_secondary.fields_valid() {
            return false;
        }
        invalid_secondary = secondary;
        invalid_secondary.reserved[0] = 1;
        if invalid_secondary.fields_valid() {
            return false;
        }
        let lower = lower_el_mailbox(
            LowerElRequest::exit(),
            self.lower_el_return,
            vmsa_test_architecture::exception::runtime_state_address(),
        );
        let mut invalid_lower = lower;
        invalid_lower.operation = u64::MAX;
        if !lower.fields_valid() || invalid_lower.fields_valid() {
            return false;
        }
        for invalid in [
            LowerElMailbox {
                abi_version: 0,
                ..lower
            },
            LowerElMailbox {
                abi_size: 0,
                ..lower
            },
            LowerElMailbox {
                reserved: [1, 0],
                ..lower
            },
            LowerElMailbox { target: 3, ..lower },
            LowerElMailbox { width: 4, ..lower },
            LowerElMailbox {
                exception_state: 1,
                ..lower
            },
            LowerElMailbox {
                hpfar_valid: 2,
                ..lower
            },
        ] {
            if invalid.fields_valid() {
                return false;
            }
        }
        self.verify_realm_rec_abi_rejection()
    }

    fn verify_realm_rec_abi_rejection(&self) -> bool {
        let valid = RealmRecRecord {
            abi_version: REALM_REC_ABI_VERSION,
            abi_size: core::mem::size_of::<RealmRecRecord>() as u32,
            operation: REALM_REC_RUN_CATALOG,
            status: REALM_REC_STATUS_RUNNING,
            request_id: 1,
            ipa: 0x1000,
            physical: 0x2000,
            bytes: 4096,
            attributes: REALM_REC_ATTR_READ_WRITE,
            result: 0,
            esr: 0,
            far: 0,
            hpfar: 0,
            hpfar_valid: 0,
            mutation_operation: REALM_REC_MUTATION_NONE,
            mutation_status: REALM_REC_MUTATION_IDLE,
            mutation_ipa: 0x3000,
            mutation_physical: 0x4000,
        };
        if !valid.fields_valid() {
            return false;
        }
        let invalid = [
            RealmRecRecord {
                abi_version: 0,
                ..valid
            },
            RealmRecRecord {
                abi_size: 0,
                ..valid
            },
            RealmRecRecord {
                operation: 0,
                ..valid
            },
            RealmRecRecord { status: 0, ..valid },
            RealmRecRecord {
                request_id: 0,
                ..valid
            },
            RealmRecRecord {
                ipa: valid.ipa + 1,
                ..valid
            },
            RealmRecRecord {
                physical: valid.physical + 1,
                ..valid
            },
            RealmRecRecord { bytes: 0, ..valid },
            RealmRecRecord {
                attributes: 0,
                ..valid
            },
            RealmRecRecord {
                mutation_operation: 1,
                ..valid
            },
            RealmRecRecord {
                mutation_status: 1,
                ..valid
            },
            RealmRecRecord {
                mutation_ipa: valid.mutation_ipa + 1,
                ..valid
            },
            RealmRecRecord {
                mutation_physical: valid.mutation_physical + 1,
                ..valid
            },
        ];
        !invalid.iter().any(RealmRecRecord::fields_valid)
    }
    pub fn end_test_scope(&mut self) -> Result<(), AdapterError> {
        if self.state != AdapterState::TestScoped
            || self.installed_current_stage1.is_some()
            || self.installed_lower_stage1.is_some()
            || self.installed_stage2.is_some()
        {
            return Err(AdapterError::InvalidTransition);
        }
        self.state = AdapterState::Ready;
        Ok(())
    }
    pub fn mark_corrupted(&mut self) {
        self.state = AdapterState::Corrupted;
    }
    pub fn finish(&mut self) -> Result<(), AdapterError> {
        if self.state != AdapterState::Ready {
            return Err(AdapterError::InvalidTransition);
        }
        self.state = AdapterState::Finished;
        Ok(())
    }
    pub fn memory(&mut self) -> &mut TestMemory {
        &mut self.memory
    }
    pub fn report(&mut self, event: ReportEvent) {
        self.reporter.emit(event);
    }

    pub fn install_translation(
        &mut self,
        mut setup: TranslationSetup,
        transition_stack: Option<vmsa_test_harness::adapter::TransitionStack>,
    ) -> Result<InstalledTranslation, AdapterError> {
        if !matches!(
            self.state,
            AdapterState::TestScoped | AdapterState::TranslationInstalled
        ) {
            return Err(AdapterError::InvalidTransition);
        }
        let occupied = match setup.stage {
            TranslationStage::Stage1 => self.installed_current_stage1.is_some(),
            TranslationStage::Stage2 => self.installed_stage2.is_some(),
        };
        if occupied {
            return Err(AdapterError::TranslationAlreadyInstalled);
        }
        if regime_code(setup.regime) != self.regime {
            return Err(AdapterError::ArchitecturalState);
        }
        if setup.stage == TranslationStage::Stage1
            && setup.asid.is_some()
            && !registers::current_stage1_uses_asid()
        {
            return Err(AdapterError::ArchitecturalState);
        }
        if transition_stack.is_some_and(|stack| {
            setup.stage != TranslationStage::Stage1
                || stack.granule() != setup.granule
                || stack.physical_top() & 0xf != 0
                || stack.virtual_top() & 0xf != 0
                || stack.physical_top() == 0
                || stack.virtual_top() == 0
        }) {
            return Err(AdapterError::ArchitecturalState);
        }
        self.validate_setup(setup)?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AdapterError::ArchitecturalState)?;
        let saved = match setup.stage {
            TranslationStage::Stage1 => {
                let asid = match (setup.asid, setup.vmid) {
                    (Some(asid), None) => asid.0,
                    (None, None) => 0,
                    _ => return Err(AdapterError::ArchitecturalState),
                };
                let (configured_mair, configured_mair2) =
                    vmsa_test_harness::adapter::stage1_memory_registers(setup.stage1_memory);
                let (tcr, mair, mair2) = if setup.controls.preserves_current() {
                    let current = registers::current_stage1_state()
                        .ok_or(AdapterError::ArchitecturalState)?;
                    let (input_bits, start_level, output_bits, format) =
                        self.merge_current_root(setup.root.get(), current.ttbr0, current.tcr, 16)?;
                    setup.input_bits =
                        AddressBits::new(input_bits).ok_or(AdapterError::ArchitecturalState)?;
                    setup.output_bits =
                        AddressBits::new(output_bits).ok_or(AdapterError::ArchitecturalState)?;
                    setup.start_level = LookupLevel::new(start_level);
                    setup.format = format;
                    (current.tcr, current.mair, configured_mair2)
                } else {
                    (setup.controls.bits(), configured_mair, configured_mair2)
                };
                setup.controls =
                    vmsa_test_harness::adapter::translation_controls_from_register(tcr);
                if setup.format == vmsa_test_harness::TranslationFormat::Vmsa128 {
                    let (ttbr_low, ttbr_high) = encode_d128_table_base(
                        setup.root.get(),
                        asid,
                        setup.start_level.ok_or(AdapterError::ArchitecturalState)?,
                        setup.input_bits,
                    )?;
                    // SAFETY: The transition sandbox mappings supplied by the
                    // payload cover the MMU-off interval and this adapter owns
                    // TTBR0_EL2, TCR/TCR2, MAIR, PIR, and PIRE0 until restore.
                    let state = unsafe {
                        registers::install_el2_stage1_d128(
                            ttbr_low,
                            ttbr_high,
                            tcr,
                            registers::Stage1MemoryRegisters { mair, mair2 },
                            0xcccc_cccc_cccc_ccca,
                            0xcccc_cccc_cccc_ccca,
                            transition_stack.map(|stack| registers::TransitionStack {
                                physical_top: stack.physical_top(),
                                virtual_top: stack.virtual_top(),
                                recovery_root: stack.recovery_root(),
                                recovery_tcr: stack.recovery_tcr(),
                                recovery_mair: stack.recovery_mair(),
                                recovery_vector: stack.recovery_vector(),
                            }),
                        )
                    }
                    .ok_or(AdapterError::UnsupportedStage)?;
                    SavedTranslation::Stage1D128(state)
                } else if setup.format == vmsa_test_harness::TranslationFormat::Vmsa64
                    && setup.granule == vmsa_test_harness::Granule::Size4KiB
                    && transition_stack.is_none()
                {
                    let ttbr = encode_table_base(setup.root.get(), asid, setup.output_bits.get())?;
                    // SAFETY: Adapter owns current-EL translation state until restoration.
                    let state = unsafe { registers::install_stage1(ttbr, tcr, mair) }
                        .ok_or(AdapterError::UnsupportedStage)?;
                    SavedTranslation::Stage1(state)
                } else {
                    let ttbr = encode_table_base(setup.root.get(), asid, setup.output_bits.get())?;
                    // SAFETY: Firmware-integrated EL2 payloads are linked and
                    // stacked in their identity-mapped low physical region.
                    let stack = transition_stack.map(|stack| registers::TransitionStack {
                        physical_top: stack.physical_top(),
                        virtual_top: stack.virtual_top(),
                        recovery_root: stack.recovery_root(),
                        recovery_tcr: stack.recovery_tcr(),
                        recovery_mair: stack.recovery_mair(),
                        recovery_vector: stack.recovery_vector(),
                    });
                    let state =
                        unsafe { registers::install_el2_stage1_geometry(ttbr, tcr, mair, stack) }
                            .ok_or(AdapterError::UnsupportedStage)?;
                    SavedTranslation::Stage1Geometry(state)
                }
            }
            TranslationStage::Stage2 => {
                let vmid = match setup.vmid {
                    Some(vmid) if setup.asid.is_none() => vmid.0,
                    _ => return Err(AdapterError::ArchitecturalState),
                };
                if setup.controls.preserves_current() {
                    return Err(AdapterError::ArchitecturalState);
                }
                if setup.format == vmsa_test_harness::TranslationFormat::Vmsa128 {
                    let (vttbr_low, vttbr_high) = encode_d128_table_base(
                        setup.root.get(),
                        vmid,
                        setup.start_level.ok_or(AdapterError::ArchitecturalState)?,
                        setup.input_bits,
                    )?;
                    // Entries 0..3 match the typed D128 stage-2 mapper's
                    // RW, RO, RO+execute, and RW+execute permission indices.
                    const S2PIR: u64 = 0x0000_0000_0000_fb8c;
                    // SAFETY: This EL2 adapter exclusively owns the complete
                    // stage-2 register set until transactional restoration.
                    let state = unsafe {
                        registers::install_stage2_d128(
                            vttbr_low,
                            vttbr_high,
                            setup.controls.bits(),
                            S2PIR,
                        )
                    }
                    .ok_or(AdapterError::UnsupportedStage)?;
                    let active = registers::current_stage2_d128_state()
                        .ok_or(AdapterError::ArchitecturalState)?;
                    if active.vttbr_low != vttbr_low
                        || active.vttbr_high != vttbr_high
                        || active.vtcr != setup.controls.bits()
                        || active.hcr & 1 == 0
                        || active.s2pir != S2PIR
                    {
                        // SAFETY: State came from the immediately preceding
                        // install and no candidate access has occurred.
                        if !unsafe { registers::restore_stage2_d128(state) } {
                            return Err(AdapterError::RestorationFailed);
                        }
                        return Err(AdapterError::ArchitecturalState);
                    }
                    SavedTranslation::Stage2D128(state)
                } else {
                    let vttbr = encode_table_base(setup.root.get(), vmid, setup.output_bits.get())?;
                    // SAFETY: Stage-2 installation is accepted only by an EL2 adapter.
                    let state = unsafe { registers::install_stage2(vttbr, setup.controls.bits()) }
                        .ok_or(AdapterError::UnsupportedStage)?;
                    let active = registers::current_stage2_state()
                        .ok_or(AdapterError::ArchitecturalState)?;
                    if active.vttbr != vttbr
                        || active.vtcr != setup.controls.bits()
                        || active.hcr & 1 == 0
                    {
                        // SAFETY: `state` was captured by the immediately preceding
                        // installation and no other owner has observed the regime.
                        if !unsafe { registers::restore_stage2(state) } {
                            return Err(AdapterError::RestorationFailed);
                        }
                        return Err(AdapterError::ArchitecturalState);
                    }
                    SavedTranslation::Stage2(state)
                }
            }
        };
        let token = InstalledTranslation::new(
            setup,
            self.generation,
            [
                setup.root.get(),
                setup.controls.bits(),
                setup.input_bits.get() as u64,
                setup.output_bits.get() as u64,
                setup
                    .start_level
                    .map_or(u64::MAX, |level| level.get() as u64),
                match setup.stage {
                    TranslationStage::Stage1 => setup.asid.map_or(0, |asid| asid.0 as u64),
                    TranslationStage::Stage2 => setup.vmid.map_or(0, |vmid| vmid.0 as u64),
                },
            ],
        );
        match setup.stage {
            TranslationStage::Stage1 => {
                self.installed_current_stage1 = Some(ActiveTranslation { token, saved });
            }
            TranslationStage::Stage2 => {
                self.installed_stage2 = Some(ActiveTranslation { token, saved });
            }
        }
        self.state = AdapterState::TranslationInstalled;
        Ok(token)
    }

    pub fn install_lower_translation<R>(
        &mut self,
        mut setup: TranslationSetup,
    ) -> Result<InstalledTranslation, AdapterError>
    where
        R: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>
            + vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule16KiB>
            + vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule64KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy + PartialEq,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule16KiB,
            > + aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule64KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule16KiB,
        >: Copy + PartialEq,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule64KiB,
        >: Copy + PartialEq,
        aarch64_vmsa::descriptor::Vmsa64Lpa2: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            > + aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule16KiB,
            > + aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule64KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa64Lpa2,
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule4KiB,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule4KiB,
                >,
            >,
        <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule16KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa64Lpa2,
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule16KiB,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule16KiB,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule16KiB,
                >,
            >,
        <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule64KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa64Lpa2,
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule64KiB,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule64KiB,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    aarch64_vmsa::address::Granule64KiB,
                >,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
    {
        if !matches!(
            self.state,
            AdapterState::TestScoped | AdapterState::TranslationInstalled
        ) {
            return Err(AdapterError::InvalidTransition);
        }
        if self.installed_lower_stage1.is_some() {
            return Err(AdapterError::TranslationAlreadyInstalled);
        }
        if regime_code(setup.regime) != self.regime || setup.stage != TranslationStage::Stage1 {
            return Err(AdapterError::ArchitecturalState);
        }
        self.validate_setup(setup)?;
        let asid = match (setup.asid, setup.vmid) {
            (Some(asid), None) => asid.0,
            (None, None) => 0,
            _ => return Err(AdapterError::ArchitecturalState),
        };
        let lower_stack = if setup.granule == vmsa_test_harness::Granule::Size4KiB {
            self.lower_el_stack
        } else {
            let bytes = setup.granule.bytes() as usize;
            let page = self
                .memory
                .allocate_aligned_pages(bytes / 4096, bytes)
                .map_err(|_| AdapterError::ArchitecturalState)?;
            page.phys_addr()
                .checked_add(bytes as u64)
                .ok_or(AdapterError::ArchitecturalState)?
        };
        let (configured_mair, configured_mair2) =
            vmsa_test_harness::adapter::stage1_memory_registers(setup.stage1_memory);
        let (tcr, mair, mair2) = if setup.controls.preserves_current() {
            let current =
                registers::current_el1_stage1_state().ok_or(AdapterError::ArchitecturalState)?;
            if current.sctlr & 1 != 0 && current.tcr != 0 {
                let (input_bits, start_level, output_bits, format) =
                    self.merge_current_root(setup.root.get(), current.ttbr0, current.tcr, 32)?;
                setup.input_bits =
                    AddressBits::new(input_bits).ok_or(AdapterError::ArchitecturalState)?;
                setup.output_bits =
                    AddressBits::new(output_bits).ok_or(AdapterError::ArchitecturalState)?;
                setup.start_level = LookupLevel::new(start_level);
                setup.format = format;
                (current.tcr, current.mair, configured_mair2)
            } else {
                setup.input_bits = AddressBits::new(self.capabilities.va_bits.min(48))
                    .ok_or(AdapterError::ArchitecturalState)?;
                setup.output_bits = AddressBits::new(self.capabilities.pa_bits.min(48))
                    .ok_or(AdapterError::ArchitecturalState)?;
                setup.start_level = LookupLevel::new(0);
                setup.format = vmsa_test_harness::TranslationFormat::Vmsa64;
                let controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(
                    setup.input_bits,
                    setup.output_bits,
                )
                .ok_or(AdapterError::ArchitecturalState)?;
                prepare_lower_runtime::<R>(
                    &mut self.memory,
                    setup,
                    self.lower_el_entry,
                    lower_stack,
                )
                .map_err(|_| AdapterError::ArchitecturalState)?;
                (controls.bits(), 0x0000_44ff, configured_mair2)
            }
        } else {
            if setup.format == vmsa_test_harness::TranslationFormat::Vmsa128 {
                let lower_runtime_state =
                    vmsa_test_architecture::exception::runtime_state_address();
                prepare_lower_runtime_d128::<R>(
                    &mut self.memory,
                    setup,
                    self.lower_el_entry,
                    lower_stack,
                    lower_runtime_state,
                )
                .map_err(|_| AdapterError::ArchitecturalState)?;
            } else {
                prepare_lower_runtime::<R>(
                    &mut self.memory,
                    setup,
                    self.lower_el_entry,
                    lower_stack,
                )
                .map_err(|_| AdapterError::ArchitecturalState)?;
            }
            (setup.controls.bits(), configured_mair, configured_mair2)
        };
        setup.controls = vmsa_test_harness::adapter::translation_controls_from_register(tcr);
        let saved = if setup.format == vmsa_test_harness::TranslationFormat::Vmsa128 {
            let (ttbr_low, ttbr_high) = encode_d128_table_base(
                setup.root.get(),
                asid,
                setup.start_level.ok_or(AdapterError::ArchitecturalState)?,
                setup.input_bits,
            )?;
            // SAFETY: The inactive EL1 context and D128 register bank are
            // exclusively owned by this guard until restoration.
            let state = unsafe {
                registers::install_el1_stage1_d128(
                    ttbr_low,
                    ttbr_high,
                    tcr,
                    registers::Stage1MemoryRegisters { mair, mair2 },
                    0xcccc_cccc_cccc_ccca,
                    0xcccc_cccc_cccc_ccca,
                )
            }
            .ok_or(AdapterError::UnsupportedStage)?;
            SavedTranslation::LowerStage1D128(state)
        } else {
            let ttbr = encode_table_base(setup.root.get(), asid, setup.output_bits.get())?;
            // SAFETY: The inactive EL1 context is exclusively owned by this guard.
            let state = unsafe { registers::install_el1_stage1(ttbr, tcr, mair) }
                .ok_or(AdapterError::UnsupportedStage)?;
            SavedTranslation::LowerStage1(state)
        };
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AdapterError::ArchitecturalState)?;
        let token = InstalledTranslation::new(
            setup,
            self.generation,
            [
                setup.root.get(),
                setup.controls.bits(),
                setup.input_bits.get() as u64,
                setup.output_bits.get() as u64,
                setup
                    .start_level
                    .map_or(u64::MAX, |level| level.get() as u64),
                u64::from(asid),
            ],
        );
        self.installed_lower_stage1 = Some(ActiveTranslation { token, saved });
        self.installed_lower_stack = Some(lower_stack);
        self.state = AdapterState::TranslationInstalled;
        Ok(token)
    }

    pub fn restore_translation(&mut self, token: InstalledTranslation) -> Result<(), AdapterError> {
        if self.state != AdapterState::TranslationInstalled {
            return Err(AdapterError::InvalidTransition);
        }
        let restoring_lower = self
            .installed_lower_stage1
            .as_ref()
            .is_some_and(|active| active.token == token);
        let slot = if self
            .installed_current_stage1
            .as_ref()
            .is_some_and(|active| active.token == token)
        {
            &mut self.installed_current_stage1
        } else if self
            .installed_lower_stage1
            .as_ref()
            .is_some_and(|active| active.token == token)
        {
            &mut self.installed_lower_stage1
        } else if self
            .installed_stage2
            .as_ref()
            .is_some_and(|active| active.token == token)
        {
            &mut self.installed_stage2
        } else {
            return Err(AdapterError::TranslationTokenMismatch);
        };
        let active = slot.take().ok_or(AdapterError::TranslationTokenMismatch)?;
        if active.token.generation() > self.generation || active.token.stage() != token.stage() {
            *slot = Some(active);
            return Err(AdapterError::TranslationTokenMismatch);
        }
        self.state = AdapterState::Restoring;
        if restore_saved(&active.saved) {
            if restoring_lower {
                self.installed_lower_stack = None;
            }
            self.state = if self.installed_current_stage1.is_some()
                || self.installed_lower_stage1.is_some()
                || self.installed_stage2.is_some()
            {
                AdapterState::TranslationInstalled
            } else {
                AdapterState::TestScoped
            };
            Ok(())
        } else {
            *slot = Some(active);
            self.state = AdapterState::Corrupted;
            Err(AdapterError::ArchitecturalState)
        }
    }

    pub fn switch_lower_stage1_root(
        &mut self,
        token: InstalledTranslation,
        root: vmsa_test_harness::PhysicalAddress,
        asid: vmsa_test_harness::Asid,
    ) -> Result<InstalledTranslation, AdapterError> {
        let active = self
            .installed_lower_stage1
            .as_mut()
            .ok_or(AdapterError::TranslationTokenMismatch)?;
        if active.token != token || !matches!(active.saved, SavedTranslation::LowerStage1(_)) {
            return Err(AdapterError::TranslationTokenMismatch);
        }
        let mut setup = token.setup();
        if setup.stage != TranslationStage::Stage1 || root.get() & 0xfff != 0 {
            return Err(AdapterError::ArchitecturalState);
        }
        let ttbr = encode_table_base(root.get(), asid.0, setup.output_bits.get())?;
        // SAFETY: The active lower-stage guard exclusively owns EL1 translation state.
        if !unsafe { registers::switch_el1_ttbr0(ttbr) } {
            return Err(AdapterError::ArchitecturalState);
        }
        setup.root = root;
        setup.asid = Some(asid);
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AdapterError::ArchitecturalState)?;
        let updated = InstalledTranslation::new(
            setup,
            self.generation,
            [
                setup.root.get(),
                setup.controls.bits(),
                setup.input_bits.get() as u64,
                setup.output_bits.get() as u64,
                setup
                    .start_level
                    .map_or(u64::MAX, |level| level.get() as u64),
                u64::from(asid.0),
            ],
        );
        active.token = updated;
        Ok(updated)
    }

    pub fn emergency_restore(&mut self) {
        if matches!(self.state, AdapterState::Ready | AdapterState::Finished) {
            return;
        }
        if self.state == AdapterState::Corrupted {
            return;
        }
        if self.state == AdapterState::SecondaryActive {
            self.state = self
                .secondary_previous
                .take()
                .unwrap_or(AdapterState::Corrupted);
            if self.state == AdapterState::Corrupted {
                return;
            }
        }
        if self.state == AdapterState::RealmActive {
            if self.realm_stage2_mapped
                && self
                    .mutate_realm_stage2(vmsa_test_harness::RealmStage2Mutation::UnmapUnprotected)
                    .is_err()
            {
                self.state = AdapterState::Corrupted;
                handle_panic()
            }
            self.state = AdapterState::TestScoped;
        }
        self.state = AdapterState::Restoring;
        for slot in [
            &mut self.installed_stage2,
            &mut self.installed_lower_stage1,
            &mut self.installed_current_stage1,
        ] {
            if let Some(active) = slot.take()
                && !restore_saved(&active.saved)
            {
                self.state = AdapterState::Corrupted;
                handle_panic()
            }
        }
        self.installed_lower_stack = None;
        self.state = AdapterState::TestScoped;
    }

    fn validate_setup(&self, setup: TranslationSetup) -> Result<(), AdapterError> {
        match setup.format {
            vmsa_test_harness::TranslationFormat::Vmsa64 => {}
            vmsa_test_harness::TranslationFormat::Vmsa64Lpa2 if self.capabilities.lpa2 => {}
            vmsa_test_harness::TranslationFormat::Vmsa128 if self.capabilities.d128 => {}
            _ => return Err(AdapterError::UnsupportedStage),
        }
        if setup.format == vmsa_test_harness::TranslationFormat::Vmsa128
            && setup.granule != vmsa_test_harness::Granule::Size4KiB
        {
            return Err(AdapterError::UnsupportedStage);
        }
        let (granule_supported, root_alignment, base_minimum_level) = match setup.granule {
            vmsa_test_harness::Granule::Size4KiB => (self.capabilities.granule_4k, 4096, 0),
            vmsa_test_harness::Granule::Size16KiB => (self.capabilities.granule_16k, 16384, 0),
            vmsa_test_harness::Granule::Size64KiB => (self.capabilities.granule_64k, 65536, 1),
        };
        let minimum_level = match setup.format {
            vmsa_test_harness::TranslationFormat::Vmsa64 => base_minimum_level,
            vmsa_test_harness::TranslationFormat::Vmsa64Lpa2 => base_minimum_level.min(-1),
            vmsa_test_harness::TranslationFormat::Vmsa128 => base_minimum_level.min(-2),
        };
        let maximum_input_bits = match setup.stage {
            TranslationStage::Stage1 => self.capabilities.va_bits,
            TranslationStage::Stage2 => self.capabilities.pa_bits,
        };
        if !granule_supported
            || setup.root.get() & (root_alignment - 1) != 0
            || setup.input_bits.get() > maximum_input_bits
            || setup.output_bits.get() > self.capabilities.pa_bits
        {
            return Err(AdapterError::ArchitecturalState);
        }
        if setup.controls.preserves_current()
            && setup.granule != vmsa_test_harness::Granule::Size4KiB
        {
            return Err(AdapterError::UnsupportedStage);
        }
        if setup.output_bits.get() > 52 {
            return Err(AdapterError::UnsupportedStage);
        }
        if let Some(level) = setup.start_level
            && !(minimum_level..=3).contains(&level.get())
        {
            return Err(AdapterError::UnsupportedStage);
        }
        Ok(())
    }

    pub fn perform_access(&mut self, request: AccessRequest) -> AccessResult {
        let result = match (request.kind, request.operation) {
            (AccessKind::Read, AccessOperation::Plain) => {
                guarded_read(request.address, request.width)
            }
            (AccessKind::Write, AccessOperation::Plain) => {
                guarded_write(request.address, request.width, request.value)
            }
            (AccessKind::Execute, AccessOperation::Plain) => guarded_execute(request.address),
            (AccessKind::Read, AccessOperation::Acquire) => {
                vmsa_test_architecture::guarded_read_acquire(request.address)
            }
            (AccessKind::Write, AccessOperation::Release) => {
                vmsa_test_architecture::guarded_write_release(request.address, request.value)
            }
            (AccessKind::Write, AccessOperation::AtomicSwap) => {
                vmsa_test_architecture::guarded_atomic_swap(request.address, request.value)
            }
            (AccessKind::Write, AccessOperation::ExclusiveAdd) => {
                vmsa_test_architecture::guarded_exclusive_add(request.address, request.value)
            }
            (AccessKind::Read, AccessOperation::PairRead) => {
                return match vmsa_test_architecture::guarded_read_pair(request.address) {
                    Ok(vmsa_test_architecture::GuardedPairResult::Completed { first, second }) => {
                        AccessResult::CompletedPair { first, second }
                    }
                    Ok(vmsa_test_architecture::GuardedPairResult::Fault(raw)) => {
                        AccessResult::Fault(normalize_fault(raw, AccessKind::Read))
                    }
                    Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
                };
            }
            (AccessKind::Write, AccessOperation::PairWrite) => {
                return match vmsa_test_architecture::guarded_write_pair(
                    request.address,
                    request.value,
                    request.second_value,
                ) {
                    Ok(vmsa_test_architecture::GuardedPairResult::Completed { first, second }) => {
                        AccessResult::CompletedPair { first, second }
                    }
                    Ok(vmsa_test_architecture::GuardedPairResult::Fault(raw)) => {
                        AccessResult::Fault(normalize_fault(raw, AccessKind::Write))
                    }
                    Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
                };
            }
            _ => return AccessResult::HarnessFailure(HarnessError::InvalidState),
        };
        match result {
            Ok(GuardedResult::Completed(value)) => AccessResult::Completed { value },
            Ok(GuardedResult::Fault(raw)) => {
                let raw = self
                    .external_fault_source
                    .and_then(|source| source())
                    .unwrap_or(raw);
                AccessResult::Fault(normalize_fault(raw, request.kind))
            }
            Err(_) => AccessResult::HarnessFailure(HarnessError::GuardBusy),
        }
    }

    pub fn begin_secondary_session(&mut self) -> Result<(), AdapterError> {
        if !matches!(
            self.state,
            AdapterState::TestScoped | AdapterState::TranslationInstalled
        ) {
            return Err(AdapterError::InvalidTransition);
        }
        if self.run_on_secondary.is_none() || self.secondary_previous.is_some() {
            return Err(AdapterError::UnsupportedStage);
        }
        self.secondary_previous = Some(self.state);
        self.state = AdapterState::SecondaryActive;
        Ok(())
    }

    pub fn perform_secondary_access(&mut self, request: AccessRequest) -> AccessResult {
        if self.state != AdapterState::SecondaryActive || self.secondary_previous.is_none() {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        }
        self.perform_secondary_access_active(request)
    }

    pub fn end_secondary_session(&mut self) -> Result<(), AdapterError> {
        if self.state != AdapterState::SecondaryActive {
            return Err(AdapterError::InvalidTransition);
        }
        self.state = self
            .secondary_previous
            .take()
            .ok_or(AdapterError::InvalidTransition)?;
        Ok(())
    }

    fn perform_secondary_access_active(&mut self, request: AccessRequest) -> AccessResult {
        let Some(run) = self.run_on_secondary else {
            return AccessResult::HarnessFailure(HarnessError::Environment);
        };
        let Some(active) = self.installed_current_stage1.as_ref() else {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        };
        if !matches!(active.saved, SavedTranslation::Stage1(_)) {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        }
        let setup = active.token.setup();
        let Some(current) = registers::current_stage1_state() else {
            return AccessResult::HarnessFailure(HarnessError::Environment);
        };
        let Ok(ttbr) = encode_table_base(
            setup.root.get(),
            setup.asid.map_or(0, |asid| asid.0),
            setup.output_bits.get(),
        ) else {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        };
        let mut secondary = SecondaryAccess {
            abi_version: SECONDARY_ACCESS_ABI_VERSION,
            abi_size: core::mem::size_of::<SecondaryAccess>() as u32,
            reserved: [0; 2],
            ttbr,
            tcr: current.tcr,
            mair: current.mair,
            kind: access_kind_code(request.kind),
            operation: access_operation_code(request.operation),
            width: request.width as u64,
            address: request.address,
            value: request.value,
            second_value: request.second_value,
            status: u64::MAX,
            result: 0,
            second_result: 0,
            fault_class: 0,
            fault_status: 0,
            fault_level: u64::MAX,
            fault_address: 0,
            fault_ipa_valid: 0,
            fault_ipa: 0,
            fault_access: 0,
            fault_stage: 0,
        };
        vmsa_test_architecture::barriers::dsb_ishst();
        // SAFETY: The callback is synchronous and keeps `secondary` live until
        // the selected PE has powered off after returning from the trampoline.
        let status = unsafe {
            run(
                secondary_access_entry,
                (&mut secondary as *mut SecondaryAccess).cast(),
            )
        };
        vmsa_test_architecture::barriers::dsb_ish();
        if status != 0 {
            return AccessResult::HarnessFailure(HarnessError::Environment);
        }
        match secondary.status {
            0 => AccessResult::Completed {
                value: secondary.result,
            },
            1 => AccessResult::CompletedPair {
                first: secondary.result,
                second: secondary.second_result,
            },
            2 => secondary.observed_fault().map_or(
                AccessResult::HarnessFailure(HarnessError::Environment),
                AccessResult::Fault,
            ),
            _ => AccessResult::HarnessFailure(HarnessError::Environment),
        }
    }

    pub fn run_lower_el(&mut self, request: LowerElRequest) -> AccessResult {
        if !matches!(
            self.state,
            AdapterState::TestScoped | AdapterState::TranslationInstalled
        ) {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        }
        let previous = self.state;
        self.state = AdapterState::LowerElActive;
        let result = self.run_lower_el_active(request);
        if self.state != AdapterState::Corrupted {
            self.state = previous;
        }
        result
    }

    fn run_lower_el_active(&mut self, request: LowerElRequest) -> AccessResult {
        let lower_stack = self.installed_lower_stack.unwrap_or(self.lower_el_stack);
        if self.lower_el_entry == 0 || lower_stack == 0 {
            return AccessResult::HarnessFailure(HarnessError::Environment);
        }
        let mailbox_page = match self.memory.allocate_page() {
            Ok(page) => page,
            Err(_) => return AccessResult::HarnessFailure(HarnessError::Memory),
        };
        let mailbox_pointer = mailbox_page.virtual_address().cast::<LowerElMailbox>();
        let mailbox = lower_el_mailbox(
            request,
            self.lower_el_return,
            vmsa_test_architecture::exception::runtime_state_address(),
        );
        // SAFETY: The allocation is page-aligned, exclusively owned by this
        // command, and large enough for LowerElMailbox.
        unsafe { mailbox_pointer.write_volatile(mailbox) };
        let lower_stage1 = if matches!(
            self.installed_lower_stage1
                .as_ref()
                .map(|active| &active.saved),
            Some(SavedTranslation::LowerStage1(_) | SavedTranslation::LowerStage1D128(_))
        ) {
            LowerElStage1Mode::Configured
        } else {
            self.lower_el_stage1
        };
        if lower_stage1 == LowerElStage1Mode::Configured {
            let d128 = matches!(
                self.installed_lower_stage1
                    .as_ref()
                    .map(|active| &active.saved),
                Some(SavedTranslation::LowerStage1D128(_))
            );
            for (address, access) in [
                (
                    self.lower_el_entry,
                    vmsa_test_architecture::translation::TranslationAccess::Read,
                ),
                (
                    vmsa_test_architecture::exception::vector_address(),
                    vmsa_test_architecture::translation::TranslationAccess::Read,
                ),
                (
                    lower_stack.saturating_sub(16),
                    vmsa_test_architecture::translation::TranslationAccess::Write,
                ),
                (
                    mailbox_page.phys_addr(),
                    vmsa_test_architecture::translation::TranslationAccess::Write,
                ),
                (
                    vmsa_test_architecture::exception::runtime_state_address(),
                    vmsa_test_architecture::translation::TranslationAccess::Write,
                ),
            ] {
                let par = if d128 {
                    vmsa_test_architecture::translation::lower_stage1_d128(address, access)
                        .map(|(low, _)| low)
                } else {
                    vmsa_test_architecture::translation::lower_stage1(address, access)
                };
                let Some(par) = par else {
                    return AccessResult::HarnessFailure(HarnessError::Environment);
                };
                if par & 1 != 0 {
                    return AccessResult::HarnessFailure(HarnessError::Environment);
                }
            }
        }
        let host_el0_translation = match (request.target, request.command) {
            (
                vmsa_test_harness::adapter::LowerElTarget::El2El0,
                LowerElCommand::Translate { address, write },
            ) => Some(vmsa_test_architecture::transition::HostEl0Translation {
                address,
                access: if write {
                    vmsa_test_architecture::translation::TranslationAccess::Write
                } else {
                    vmsa_test_architecture::translation::TranslationAccess::Read
                },
            }),
            _ => None,
        };
        let transition_outcome = vmsa_test_architecture::transition::enter_lower_el(
            self.lower_el_entry,
            lower_stack,
            mailbox_page.phys_addr(),
            lower_stage1,
            self.lower_el_return,
            match request.target {
                vmsa_test_harness::adapter::LowerElTarget::El1 => {
                    vmsa_test_architecture::transition::LowerElTarget::El1
                }
                vmsa_test_harness::adapter::LowerElTarget::El0 => {
                    vmsa_test_architecture::transition::LowerElTarget::El0
                }
                vmsa_test_harness::adapter::LowerElTarget::El2El0 => {
                    vmsa_test_architecture::transition::LowerElTarget::El2El0
                }
            },
            host_el0_translation,
        );
        let host_el0_par = match transition_outcome {
            Ok(vmsa_test_architecture::transition::LowerElOutcome::Returned) => None,
            Ok(vmsa_test_architecture::transition::LowerElOutcome::HostEl0Translation { par }) => {
                Some(par)
            }
            Err(_) => return AccessResult::HarnessFailure(HarnessError::Environment),
        };
        // SAFETY: EL1 has returned ownership of the live arena allocation and
        // the exception transition provides the required synchronization.
        let mut mailbox = unsafe { mailbox_pointer.read_volatile() };
        if let Some(par) = host_el0_par {
            mailbox.result = par;
        }
        match mailbox.status {
            0 => AccessResult::Completed {
                value: mailbox.result,
            },
            3 => AccessResult::CompletedPair {
                first: mailbox.result,
                second: mailbox.second_result,
            },
            1 if mailbox.hpfar_valid <= 1 => AccessResult::Fault(normalize_fault(
                RawFault {
                    esr: mailbox.esr,
                    far: mailbox.far,
                    hpfar: (mailbox.hpfar_valid == 1).then_some(mailbox.hpfar),
                    elr: mailbox.elr,
                    spsr: mailbox.spsr,
                },
                access_kind(request),
            )),
            _ => AccessResult::HarnessFailure(HarnessError::InvalidState),
        }
    }

    fn merge_current_root(
        &mut self,
        destination_physical: u64,
        current_ttbr: u64,
        current_tcr: u64,
        output_size_shift: u8,
    ) -> Result<(u8, i8, u8, vmsa_test_harness::TranslationFormat), AdapterError> {
        let (source_mask, root_bytes, input_bits, start_level, output_bits, format) =
            current_root_geometry(current_tcr, output_size_shift)?;
        let offset = destination_physical
            .checked_sub(self.arena_physical)
            .ok_or(AdapterError::ArchitecturalState)? as usize;
        if offset
            .checked_add(root_bytes)
            .is_none_or(|end| end > self.arena_bytes)
        {
            return Err(AdapterError::ArchitecturalState);
        }
        let source_physical = (current_ttbr & source_mask)
            | if output_bits > 48 {
                ((current_ttbr >> 2) & 0xf) << 48
            } else {
                0
            };
        if format != vmsa_test_harness::TranslationFormat::Vmsa64 {
            return Err(AdapterError::UnsupportedStage);
        }
        self.clone_vmsa64_table(
            source_physical,
            destination_physical,
            start_level,
            root_bytes / core::mem::size_of::<u64>(),
        )?;
        vmsa_test_architecture::barriers::dsb_ishst();
        Ok((input_bits, start_level, output_bits, format))
    }

    fn clone_vmsa64_table(
        &mut self,
        source_physical: u64,
        destination_physical: u64,
        level: i8,
        entries: usize,
    ) -> Result<(), AdapterError> {
        const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
        if !(0..=3).contains(&level) || entries == 0 || entries > 512 {
            return Err(AdapterError::ArchitecturalState);
        }
        let source = source_physical as *const u64;
        let destination = destination_physical
            .checked_add(self.arena_offset)
            .ok_or(AdapterError::ArchitecturalState)? as *mut u64;
        for index in 0..entries {
            // SAFETY: Firmware keeps the active source tables readable and the
            // checked destination table is exclusively owned by this test.
            let raw = unsafe { source.add(index).read_volatile() };
            let cloned = if level < 3 && raw & 0b11 == 0b11 {
                let source_child = raw & ADDRESS_MASK;
                if source_child == 0 {
                    return Err(AdapterError::ArchitecturalState);
                }
                let child = self
                    .memory
                    .allocate_root(4096, 4096)
                    .map_err(|_| AdapterError::ArchitecturalState)?;
                self.clone_vmsa64_table(source_child, child.phys_addr(), level + 1, 512)?;
                (raw & !ADDRESS_MASK) | child.phys_addr()
            } else {
                raw
            };
            // SAFETY: Each destination entry is written once during the clone.
            unsafe { destination.add(index).write(cloned) };
        }
        Ok(())
    }
}

fn current_root_geometry(
    tcr: u64,
    output_size_shift: u8,
) -> Result<(u64, usize, u8, i8, u8, vmsa_test_harness::TranslationFormat), AdapterError> {
    const ADDRESS_MASK_48: u64 = 0x0000_ffff_ffff_ffff;
    let granule = (tcr >> 14) & 0x3;
    if granule != 0 {
        return Err(AdapterError::UnsupportedStage);
    }
    let input_bits = 64usize
        .checked_sub((tcr & 0x3f) as usize)
        .ok_or(AdapterError::ArchitecturalState)?;
    let lpa2 = tcr & (1 << 59) != 0;
    let maximum_input_bits = if lpa2 { 52 } else { 48 };
    if !(13..=maximum_input_bits).contains(&input_bits) {
        return Err(AdapterError::ArchitecturalState);
    }
    let translated_bits = input_bits - 12;
    let levels = translated_bits.div_ceil(9);
    let maximum_levels = if lpa2 { 5 } else { 4 };
    if !(1..=maximum_levels).contains(&levels) {
        return Err(AdapterError::ArchitecturalState);
    }
    let root_bits = translated_bits - 9 * (levels - 1);
    let root_bytes = (1usize << root_bits)
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(AdapterError::ArchitecturalState)?;
    let source_mask = ADDRESS_MASK_48 & !((root_bytes as u64) - 1);
    let output_bits = match (tcr >> output_size_shift) & 0x7 {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        _ => return Err(AdapterError::ArchitecturalState),
    };
    Ok((
        source_mask,
        root_bytes,
        input_bits as u8,
        (4 - levels) as i8,
        output_bits,
        if lpa2 {
            vmsa_test_harness::TranslationFormat::Vmsa64Lpa2
        } else {
            vmsa_test_harness::TranslationFormat::Vmsa64
        },
    ))
}

fn encode_table_base(root: u64, identifier: u16, output_bits: u8) -> Result<u64, AdapterError> {
    if root & 0xfff != 0 || output_bits > 52 {
        return Err(AdapterError::ArchitecturalState);
    }
    let low = root & 0x0000_ffff_ffff_f000;
    let high = if output_bits > 48 {
        ((root >> 48) & 0xf) << 2
    } else if root >> 48 == 0 {
        0
    } else {
        return Err(AdapterError::ArchitecturalState);
    };
    Ok(((identifier as u64) << 48) | low | high)
}

fn encode_d128_table_base(
    root: u64,
    identifier: u16,
    root_level: LookupLevel,
    input_bits: AddressBits,
) -> Result<(u64, u64), AdapterError> {
    if root & 0x1f != 0 || root >> 56 != 0 {
        return Err(AdapterError::ArchitecturalState);
    }
    let table_bits = input_bits
        .get()
        .checked_sub(12)
        .ok_or(AdapterError::ArchitecturalState)?;
    let levels = table_bits.div_ceil(8) as i8;
    let regular_start = 4i8
        .checked_sub(levels)
        .ok_or(AdapterError::ArchitecturalState)?;
    let skip = root_level
        .get()
        .checked_sub(regular_start)
        .filter(|value| (0..=3).contains(value))
        .ok_or(AdapterError::ArchitecturalState)? as u64;
    let low = ((identifier as u64) << 48) | (root & 0x0000_ffff_ffff_ffe0) | (skip << 1);
    let high = ((root >> 48) & 0xff) << 16;
    Ok((low, high))
}

fn restore_saved(saved: &SavedTranslation) -> bool {
    match *saved {
        // SAFETY: Saved state was captured by this adapter at the current EL.
        SavedTranslation::Stage1(state) => unsafe { registers::restore_stage1(state) },
        // SAFETY: Saved state was captured by the paired geometry installer.
        SavedTranslation::Stage1Geometry(state) => unsafe {
            registers::restore_el2_stage1_geometry(state)
        },
        // SAFETY: Saved state was captured by the paired D128 installer.
        SavedTranslation::Stage1D128(state) => unsafe { registers::restore_el2_stage1_d128(state) },
        // SAFETY: Saved state was captured from the inactive EL1 bank at EL2.
        SavedTranslation::LowerStage1(state) => unsafe { registers::restore_el1_stage1(state) },
        // SAFETY: Saved state was captured from the inactive EL1 D128 bank.
        SavedTranslation::LowerStage1D128(state) => unsafe {
            registers::restore_el1_stage1_d128(state)
        },
        // SAFETY: Saved state was captured by this adapter at EL2.
        SavedTranslation::Stage2(state) => {
            // SAFETY: Saved state was captured by this adapter at EL2.
            if !unsafe { registers::restore_stage2(state) } {
                return false;
            }
            registers::current_stage2_state() == Some(state)
        }
        // SAFETY: Saved state was captured by the paired full-width stage-2 installer.
        SavedTranslation::Stage2D128(state) => unsafe { registers::restore_stage2_d128(state) },
    }
}

impl Drop for AdapterCore {
    fn drop(&mut self) {
        self.emergency_restore();
        if let Some(vectors) = self.vectors.take() {
            vectors.restore();
        }
        self.fatal_exceptions.take();
    }
}

fn lower_el_mailbox(
    request: LowerElRequest,
    return_conduit: LowerElReturnConduit,
    exception_state: u64,
) -> LowerElMailbox {
    let (operation, address, width, value, second_value) = match request.command {
        LowerElCommand::Read { address, width } => (0, address, width as u64, 0, 0),
        LowerElCommand::Write {
            address,
            width,
            value,
        } => (1, address, width as u64, value, 0),
        LowerElCommand::Execute { address } => (2, address, 3, 0, 0),
        LowerElCommand::Exit => (3, 0, 3, 0, 0),
        LowerElCommand::Translate { address, write } => (4, address, 3, write as u64, 0),
        LowerElCommand::ReadAcquire { address } => (5, address, 3, 0, 0),
        LowerElCommand::WriteRelease { address, value } => (6, address, 3, value, 0),
        LowerElCommand::AtomicSwap { address, value } => (7, address, 3, value, 0),
        LowerElCommand::ExclusiveAdd { address, value } => (8, address, 3, value, 0),
        LowerElCommand::ReadPair { address } => (9, address, 3, 0, 0),
        LowerElCommand::WritePair {
            address,
            first,
            second,
        } => (10, address, 3, first, second),
    };
    LowerElMailbox {
        abi_version: LOWER_EL_MAILBOX_ABI_VERSION,
        abi_size: core::mem::size_of::<LowerElMailbox>() as u64,
        reserved: [0; 2],
        operation,
        return_conduit: return_conduit as u64,
        exception_state,
        target: request.target as u64,
        address,
        width,
        value,
        second_value,
        status: u64::MAX,
        result: 0,
        second_result: 0,
        esr: 0,
        far: 0,
        hpfar_valid: 0,
        hpfar: 0,
        elr: 0,
        spsr: 0,
    }
}

fn access_kind(request: LowerElRequest) -> AccessKind {
    match request.command {
        LowerElCommand::Read { .. } => AccessKind::Read,
        LowerElCommand::Write { .. } => AccessKind::Write,
        LowerElCommand::ReadAcquire { .. } | LowerElCommand::ReadPair { .. } => AccessKind::Read,
        LowerElCommand::WriteRelease { .. }
        | LowerElCommand::AtomicSwap { .. }
        | LowerElCommand::ExclusiveAdd { .. }
        | LowerElCommand::WritePair { .. } => AccessKind::Write,
        LowerElCommand::Execute { .. } => AccessKind::Execute,
        LowerElCommand::Translate { write: false, .. } => AccessKind::Read,
        LowerElCommand::Translate { write: true, .. } => AccessKind::Write,
        LowerElCommand::Exit => AccessKind::Execute,
    }
}

const fn access_kind_code(kind: AccessKind) -> u64 {
    match kind {
        AccessKind::Read => 0,
        AccessKind::Write => 1,
        AccessKind::Execute => 2,
    }
}

const fn access_operation_code(operation: AccessOperation) -> u64 {
    match operation {
        AccessOperation::Plain => 0,
        AccessOperation::Acquire => 1,
        AccessOperation::Release => 2,
        AccessOperation::AtomicSwap => 3,
        AccessOperation::ExclusiveAdd => 4,
        AccessOperation::PairRead => 5,
        AccessOperation::PairWrite => 6,
        AccessOperation::Translate => 7,
    }
}

const fn regime_code(regime: vmsa_test_harness::RegimeAttributes) -> u8 {
    use vmsa_test_harness::RegimeAttributes;
    match regime {
        RegimeAttributes::Normal => REGIME_NORMAL,
        RegimeAttributes::Secure => REGIME_SECURE,
        RegimeAttributes::Realm => REGIME_REALM,
        RegimeAttributes::Root => REGIME_ROOT,
    }
}

pub fn panic_report(callback: unsafe extern "C" fn(u8)) -> ! {
    for byte in b"VMSA-INFRA HARNESS_FAILURE\n" {
        // SAFETY: Callback originates from the validated boot context.
        unsafe { callback(*byte) }
    }
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn fatal_exception(
    esr: u64,
    far: u64,
    hpfar: u64,
    hpfar_valid: u64,
    elr: u64,
    spsr: u64,
) -> ! {
    let callback = PANIC_CALLBACK.load(Ordering::Acquire);
    if callback != 0 {
        // SAFETY: The value originates from the validated live boot context.
        let callback: unsafe extern "C" fn(u8) = unsafe { core::mem::transmute(callback) };
        write_bytes(callback, b"VMSA-INFRA HARNESS_FAILURE esr=0x");
        write_hex(callback, esr);
        write_bytes(callback, b" far=0x");
        write_hex(callback, far);
        write_bytes(callback, b" hpfar=0x");
        write_hex(callback, hpfar);
        write_bytes(callback, b" hpfar_valid=0x");
        write_hex(callback, hpfar_valid);
        write_bytes(callback, b" elr=0x");
        write_hex(callback, elr);
        write_bytes(callback, b" spsr=0x");
        write_hex(callback, spsr);
        write_bytes(callback, b"\n");
    }
    loop {
        core::hint::spin_loop();
    }
}

fn write_bytes(callback: unsafe extern "C" fn(u8), bytes: &[u8]) {
    for byte in bytes {
        // SAFETY: Callback originates from the validated live boot context.
        unsafe { callback(*byte) }
    }
}

fn write_hex(callback: unsafe extern "C" fn(u8), value: u64) {
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 0xf) as u8;
        let byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        // SAFETY: Callback originates from the validated live boot context.
        unsafe { callback(byte) }
    }
}

static PANIC_CALLBACK: AtomicUsize = AtomicUsize::new(0);

pub fn handle_panic() -> ! {
    let callback = PANIC_CALLBACK.load(Ordering::Acquire);
    if callback != 0 {
        // SAFETY: The value was stored from the validated firmware callback and
        // payload execution has not returned while a panic is being handled.
        let callback: unsafe extern "C" fn(u8) = unsafe { core::mem::transmute(callback) };
        panic_report(callback)
    }
    loop {
        core::hint::spin_loop();
    }
}

pub type EntryResult = u32;
pub const ENTRY_COMPLETE: EntryResult = 0;
pub const ENTRY_FAILED: EntryResult = 1;
pub const ENTRY_CAPABILITY: EntryResult = 22;
pub const ENTRY_INVALID_CONTEXT: EntryResult = 23;

pub fn outcome_code(outcome: RunnerOutcome) -> EntryResult {
    match outcome {
        RunnerOutcome::Complete { failed: 0, .. } => ENTRY_COMPLETE,
        RunnerOutcome::Complete { .. } | RunnerOutcome::HarnessCorrupted => ENTRY_FAILED,
        RunnerOutcome::BaselineCapabilityMissing => ENTRY_CAPABILITY,
    }
}

macro_rules! define_environment {
    ($name:ident, $regime:ty) => {
        define_environment!($name, $regime, Preserve, Hvc);
    };
    ($name:ident, $regime:ty, $lower_el_stage1:ident) => {
        define_environment!($name, $regime, $lower_el_stage1, Hvc);
    };
    ($name:ident, $regime:ty, $lower_el_stage1:ident, $lower_el_return:ident) => {
        pub struct $name {
            core: $crate::common::AdapterCore,
        }

        impl $name {
            pub fn from_boot(
                context: &$crate::common::BootContext,
                regime: u8,
            ) -> Result<(Self, Option<&str>), $crate::common::AdapterError> {
                let (mut core, filter) = $crate::common::AdapterCore::from_boot(
                    context,
                    regime,
                    vmsa_test_architecture::transition::LowerElStage1Mode::$lower_el_stage1,
                    vmsa_test_architecture::transition::LowerElReturnConduit::$lower_el_return,
                )?;
                core.set_external_fault_source(None);
                core.set_realm_stage2_service(None);
                Ok((Self { core }, filter))
            }
        }

        impl vmsa_test_harness::adapter::Environment for $name {
            type Error = $crate::common::AdapterError;

            fn begin_test_scope(&mut self) -> Result<(), Self::Error> {
                self.core.begin_test_scope()
            }

            fn end_test_scope(&mut self) -> Result<(), Self::Error> {
                self.core.end_test_scope()
            }

            fn mark_corrupted(&mut self) {
                self.core.mark_corrupted();
            }

            fn finish(&mut self) -> Result<(), Self::Error> {
                self.core.finish()
            }

            fn capabilities(&self) -> vmsa_test_harness::Capabilities {
                self.core.capabilities()
            }

            fn memory_pas(&self) -> vmsa_test_harness::PhysicalAddressSpace {
                self.core.memory_pas()
            }

            fn transition_runtime_data(&self) -> [u64; 2] {
                self.core.transition_runtime_data()
            }

            fn memory(&mut self) -> &mut vmsa_test_harness::adapter::TestMemory {
                self.core.memory()
            }

            fn install_translation(
                &mut self,
                setup: vmsa_test_harness::TranslationSetup,
                transition_stack: Option<vmsa_test_harness::adapter::TransitionStack>,
            ) -> Result<vmsa_test_harness::adapter::InstalledTranslation, Self::Error> {
                self.core.install_translation(setup, transition_stack)
            }

            fn install_lower_translation(
                &mut self,
                setup: vmsa_test_harness::TranslationSetup,
            ) -> Result<vmsa_test_harness::adapter::InstalledTranslation, Self::Error> {
                self.core
                    .install_lower_translation::<$crate::LowerRegime>(setup)
            }

            fn switch_lower_stage1_root(
                &mut self,
                installed: vmsa_test_harness::adapter::InstalledTranslation,
                root: vmsa_test_harness::PhysicalAddress,
                asid: vmsa_test_harness::Asid,
            ) -> Result<vmsa_test_harness::adapter::InstalledTranslation, Self::Error> {
                self.core.switch_lower_stage1_root(installed, root, asid)
            }

            fn perform_access(
                &mut self,
                request: vmsa_test_harness::adapter::AccessRequest,
            ) -> vmsa_test_harness::AccessResult {
                self.core.perform_access(request)
            }

            fn realm_rec_is_current(&self) -> bool {
                self.core.realm_rec_is_current()
            }

            fn verify_invalid_transition_rejected(&mut self) -> bool {
                self.core.verify_invalid_transition_rejected()
            }

            fn verify_common_abi_rejection(&self) -> bool {
                self.core.verify_common_abi_rejection()
            }

            fn begin_realm_stage2_session(
                &mut self,
            ) -> Result<vmsa_test_harness::RealmStage2Region, vmsa_test_harness::HarnessError> {
                self.core.begin_realm_stage2_session()
            }

            fn mutate_realm_stage2(
                &mut self,
                mutation: vmsa_test_harness::RealmStage2Mutation,
            ) -> Result<(), vmsa_test_harness::HarnessError> {
                self.core.mutate_realm_stage2(mutation)
            }

            fn end_realm_stage2_session(&mut self) -> Result<(), vmsa_test_harness::HarnessError> {
                self.core.end_realm_stage2_session()
            }

            fn begin_secondary_session(&mut self) -> Result<(), Self::Error> {
                self.core.begin_secondary_session()
            }

            fn perform_secondary_access(
                &mut self,
                request: vmsa_test_harness::adapter::AccessRequest,
            ) -> vmsa_test_harness::AccessResult {
                self.core.perform_secondary_access(request)
            }

            fn end_secondary_session(&mut self) -> Result<(), Self::Error> {
                self.core.end_secondary_session()
            }

            fn run_lower_el(
                &mut self,
                request: vmsa_test_harness::adapter::LowerElRequest,
            ) -> vmsa_test_harness::AccessResult {
                self.core.run_lower_el(request)
            }

            fn restore_translation(
                &mut self,
                installed: vmsa_test_harness::adapter::InstalledTranslation,
            ) -> Result<(), Self::Error> {
                self.core.restore_translation(installed)
            }

            fn emergency_restore(&mut self) {
                self.core.emergency_restore();
            }

            fn report(&mut self, event: vmsa_test_harness::adapter::ReportEvent) {
                self.core.report(event);
            }
        }

        impl vmsa_test_harness::adapter::TranslationRegimeEnvironment for $name {
            type Regime = $regime;
        }
    };
}

pub(crate) use define_environment;
