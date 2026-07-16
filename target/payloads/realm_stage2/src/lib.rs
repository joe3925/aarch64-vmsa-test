#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/features.rs"]
#[allow(dead_code)]
mod features;
#[path = "../../common/pas.rs"]
#[allow(dead_code)]
mod pas;
#[path = "../../common/runtime_support.rs"]
#[allow(dead_code)]
mod runtime_support;

use common::{BootContext, REGIME_REALM, define_environment, outcome_code};
use vmsa_test_abi::{
    REALM_REC_STATUS_COMPLETE, REALM_REC_STATUS_FAILED, REALM_REC_STATUS_FAULT_PENDING,
    RealmRecRecord,
};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};

define_environment!(
    RealmStage2Environment,
    aarch64_vmsa::regime::RealmEl1Stage1,
    Disable,
    Smc
);

impl RealmStage2Environment {
    fn enable_rec_services(&mut self, record: &RealmRecRecord) {
        self.core
            .set_external_fault_source(Some(take_external_fault));
        self.core.set_realm_stage2_service(Some((
            vmsa_test_harness::RealmStage2Region {
                ipa: record.mutation_ipa,
                physical: record.mutation_physical,
            },
            vmsa_test_realm_stage2_mutate,
        )));
    }
}

unsafe extern "C" {
    fn vmsa_test_realm_stage2_mutate(operation: u64) -> u32;
}

pub type CurrentEnvironment = RealmStage2Environment;
pub type CurrentRegime = aarch64_vmsa::regime::RealmEl1Stage1;
pub type LowerRegime = aarch64_vmsa::regime::RealmEl1Stage1;

fn feature_snapshot_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::live_snapshot_agreement(context.capabilities())
}
fn security_state_membership(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::security_state_membership(
        context.capabilities(),
        aarch64_vmsa::arch::SecurityStates::REALM,
    )
}
fn regime_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::attrs::{Stage2Permissions, Stage2XnxPermissions};
    use aarch64_vmsa::regime::{RealmEl1Stage1, RealmEl2Stage2};
    let current = aarch64_vmsa::arch::VmsaFeatures::current();
    features::regime_result(features::require_regimes!(&current;
        RealmEl1Stage1,
        RealmEl2Stage2<Stage2Permissions>,
        RealmEl2Stage2<Stage2XnxPermissions>,
    ))
}
fn regime_format_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::attrs::{Stage2Permissions, Stage2XnxPermissions};
    use aarch64_vmsa::regime::{RealmEl1Stage1, RealmEl2Stage2};
    let current = &aarch64_vmsa::arch::VmsaFeatures::current();
    macro_rules! check {
        ($regime:ty) => {
            features::require_base_format!(current; $regime)
                && features::require_live_format_agreement!(current; $regime, stage2 = false)
        };
    }
    features::regime_result(
        check!(RealmEl1Stage1)
            && features::require_base_format!(current; RealmEl2Stage2<Stage2Permissions>)
            && features::require_live_format_agreement!(current; RealmEl2Stage2<Stage2Permissions>, stage2 = true)
            && features::require_base_format!(current; RealmEl2Stage2<Stage2XnxPermissions>)
            && features::require_live_format_agreement!(current; RealmEl2Stage2<Stage2XnxPermissions>, stage2 = true),
    )
}

static REC_TEST_IPA: AtomicU64 = AtomicU64::new(0);
static REC_FAULT_IPA: AtomicU64 = AtomicU64::new(0);
static REC_RECORD: AtomicU64 = AtomicU64::new(0);

fn take_external_fault() -> Option<vmsa_test_architecture::exception::RawFault> {
    let pointer = REC_RECORD.load(Ordering::Acquire) as *const RealmRecRecord;
    if pointer.is_null() {
        return None;
    }
    if !vmsa_test_architecture::barriers::invalidate_data_cache_range(
        pointer as u64,
        core::mem::size_of::<RealmRecRecord>(),
    ) {
        return None;
    }
    // SAFETY: Entry validation keeps the host/Realm shared record live for the
    // complete catalog run. Volatile reads synchronize with the host update
    // performed while the REC is exited.
    let status = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*pointer).status)) };
    if status != REALM_REC_STATUS_FAULT_PENDING {
        return None;
    }
    // SAFETY: Same live shared-record contract as above.
    let (esr, far, hpfar, hpfar_valid) = unsafe {
        (
            core::ptr::read_volatile(core::ptr::addr_of!((*pointer).esr)),
            core::ptr::read_volatile(core::ptr::addr_of!((*pointer).far)),
            core::ptr::read_volatile(core::ptr::addr_of!((*pointer).hpfar)),
            core::ptr::read_volatile(core::ptr::addr_of!((*pointer).hpfar_valid)),
        )
    };
    Some(vmsa_test_architecture::exception::RawFault {
        esr,
        far,
        hpfar: (hpfar_valid == 1).then_some(hpfar),
        elr: 0,
        spsr: 0,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn vmsa_test_realm_stage2_plan() -> u64 {
    use aarch64_vmsa::attrs::{
        D128Stage1AliasKind, DataAccess, LiveVmsaConfig, RealmOrNonSecurePa, Shareability,
        Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::mapper::decode_semantic_leaf;
    use vmsa_test_harness::MappingAttributes;
    use vmsa_test_harness::adapter::TestRegimeFor;

    let Ok(raw) = <aarch64_vmsa::regime::RealmEl2Stage2 as TestRegimeFor<
        aarch64_vmsa::address::Granule4KiB,
    >>::raw_leaf(MappingAttributes::READ_WRITE) else {
        return 0;
    };
    let mut checks = 1;
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: RealmOrNonSecurePa::Realm,
    };
    let Ok(semantic) = decode_semantic_leaf::<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::regime::RealmEl2Stage2,
        aarch64_vmsa::address::Granule4KiB,
        VmsaAttributeCodec,
        _,
    >(&config, aarch64_vmsa::address::Level::L3, raw) else {
        return checks;
    };
    checks |= 1 << 1;
    if semantic.output_address_space == RealmOrNonSecurePa::Realm {
        checks |= 1 << 2;
    }
    if semantic.permissions.data == DataAccess::ReadWrite {
        checks |= 1 << 3;
    }
    if !semantic.permissions.privileged_execute {
        checks |= 1 << 4;
    }
    if !semantic.permissions.unprivileged_execute {
        checks |= 1 << 5;
    }
    checks
}

fn current_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let address = REC_TEST_IPA.load(Ordering::Acquire);
    if address == 0 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
    let initial = match execution.read_u64(address) {
        vmsa_test_harness::AccessResult::Completed { value } if value == 0x5245_432d_5332_2d4d => {
            TestResult::Pass
        }
        vmsa_test_harness::AccessResult::Completed { value } => {
            TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongValue,
                expected: 0x5245_432d_5332_2d4d,
                actual: value,
            })
        }
        vmsa_test_harness::AccessResult::Fault(fault) => {
            TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongFault,
                expected: 0,
                actual: fault.status_code(),
            })
        }
        vmsa_test_harness::AccessResult::HarnessFailure(error) => error.into(),
        vmsa_test_harness::AccessResult::CompletedPair { .. } => {
            vmsa_test_harness::HarnessError::InvalidState.into()
        }
    };
    if !matches!(initial, TestResult::Pass) {
        return initial;
    }
    let original_pair = match execution.read_pair_u64(address) {
        vmsa_test_harness::AccessResult::CompletedPair { first, second } => (first, second),
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    };
    match execution.translate(address, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => {}
        _ => return vmsa_test_harness::HarnessError::Environment.into(),
    }
    if !matches!(
        execution.write_u8(address, original_pair.0 as u8),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u8(address),
        vmsa_test_harness::AccessResult::Completed { value } if value == u64::from(original_pair.0 as u8)
    ) || !matches!(
        execution.write_u16(address, original_pair.0 as u16),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u16(address),
        vmsa_test_harness::AccessResult::Completed { value } if value == u64::from(original_pair.0 as u16)
    ) || !matches!(
        execution.write_u32(address, original_pair.0 as u32),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u32(address),
        vmsa_test_harness::AccessResult::Completed { value } if value == u64::from(original_pair.0 as u32)
    ) || !matches!(
        execution.execute(runtime_support::execution_probe as *const () as usize as u64),
        vmsa_test_harness::AccessResult::Completed {
            value: 0x5345_434f_4e44_4152
        }
    ) || !matches!(
        execution.write_release_u64(address, original_pair.0),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_acquire_u64(address),
        vmsa_test_harness::AccessResult::Completed { value } if value == original_pair.0
    ) || !matches!(
        execution.atomic_swap_u64(address, 0x5245_432d_4154_4f4d),
        vmsa_test_harness::AccessResult::Completed { value } if value == original_pair.0
    ) || !matches!(
        execution.exclusive_add_u64(address, 1),
        vmsa_test_harness::AccessResult::Completed {
            value: 0x5245_432d_4154_4f4d
        }
    ) || !matches!(
        execution.write_pair_u64(address, original_pair.0, original_pair.1),
        vmsa_test_harness::AccessResult::CompletedPair { .. }
    ) || !matches!(
        execution.read_pair_u64(address),
        vmsa_test_harness::AccessResult::CompletedPair { first, second }
            if first == original_pair.0 && second == original_pair.1
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let write = execution.write_u64(address, 0x5245_432d_564d_5341);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result =
        vmsa_test_harness::expect_value(execution.read_u64(address), 0x5245_432d_564d_5341);
    let restore = execution.write_u64(address, 0x5245_432d_5332_2d4d);
    if !matches!(restore, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(restore);
    }
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let restored =
        vmsa_test_harness::expect_value(execution.read_u64(address), 0x5245_432d_5332_2d4d);
    execution.finish()?;
    restored
}

fn current_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let address = REC_FAULT_IPA.load(Ordering::Acquire);
    if address == 0 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
    let result = vmsa_test_harness::expect_fault(
        execution.read_u64(address),
        vmsa_test_harness::ExpectedFault::translation(vmsa_test_harness::FaultStage::Stage2),
    );
    execution.finish()?;
    result
}

fn address_translation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let mut translation = context.realm_rec_stage2()?;
    translation.map()?;
    let address = translation.input_address();
    match context.translate_current_stage1(address, vmsa_test_harness::TranslationQueryAccess::Read)
    {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => {}
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            return vmsa_test_harness::HarnessError::Environment.into();
        }
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
            return vmsa_test_harness::HarnessError::Environment.into();
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            return vmsa_test_harness::HarnessError::Environment.into();
        }
    }
    translation.unmap()?;
    let result = match context
        .translate_current_stage1(address, vmsa_test_harness::TranslationQueryAccess::Read)
    {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
            vmsa_test_harness::HarnessError::Environment.into()
        }
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            vmsa_test_harness::HarnessError::Environment.into()
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::Environment.into()
        }
    };
    translation.finish()?;
    result
}

fn live_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    current_access(context)
}

fn pas_semantics(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    pas::realm_semantics(context)
}

fn fixed_realm_ipa_stage1_semantic_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttributeCodec, Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement,
        LiveVmsaConfig, MemoryAttributes, SemanticStage1LeafAttrs,
        SemanticVmsa64Stage1LeafControls, Shareability, SoftwareMetadata, Stage2MemoryMode,
        TwoPrivilegeLeafPermissions, VmsaAttributeCodec,
    };
    let config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: TwoPrivilegeLeafPermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let decoded = <VmsaAttributeCodec as AttributeCodec<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::regime::RealmEl1Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, Level::L3, leaf)
    .and_then(|raw| {
        <VmsaAttributeCodec as AttributeCodec<
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::regime::RealmEl1Stage1,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, Level::L3, raw)
    });
    if decoded != Ok(leaf) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    current_access(context)
}

fn realm_fresh_sentinel(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    context.realm_rec_stage2()?.finish()?;
    TestResult::Pass
}

fn realm_creation_phase_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
    point: vmsa_test_harness::HarnessFailurePoint,
) -> TestResult {
    let rejected = context.with_harness_failure(point, 0, || context.realm_rec_stage2());
    let rejected_as_expected = matches!(
        rejected,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    );
    drop(rejected);
    if !rejected_as_expected {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    realm_fresh_sentinel(context)
}

fn realm_delegation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_creation_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::GranuleDelegation,
    )
}

fn realm_creation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_creation_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::RealmCreation,
    )
}

fn realm_rec_creation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_creation_phase_failure(context, vmsa_test_harness::HarnessFailurePoint::RecCreation)
}

fn realm_rec_entry_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_creation_phase_failure(context, vmsa_test_harness::HarnessFailurePoint::RecEntry)
}

fn realm_map_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let mut translation = context.realm_rec_stage2()?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::RealmMap, 0, || {
            translation.map()
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.map()?;
    translation.unmap()?;
    translation.finish()?;
    realm_fresh_sentinel(context)
}

fn realm_protect_read_only_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let mut translation = context.realm_rec_stage2()?;
    translation.map()?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::RealmMutation,
        0,
        || translation.protect_read_only(),
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.protect_read_only()?;
    translation.protect_read_write()?;
    translation.unmap()?;
    translation.finish()?;
    realm_fresh_sentinel(context)
}

fn realm_protect_read_write_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let mut translation = context.realm_rec_stage2()?;
    translation.map()?;
    translation.protect_read_only()?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::RealmMutation,
        0,
        || translation.protect_read_write(),
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.protect_read_write()?;
    translation.unmap()?;
    translation.finish()?;
    realm_fresh_sentinel(context)
}

fn realm_unmap_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let mut translation = context.realm_rec_stage2()?;
    translation.map()?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::RealmMutation,
        0,
        || translation.unmap(),
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.unmap()?;
    translation.finish()?;
    realm_fresh_sentinel(context)
}

fn realm_finish_phase_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
    point: vmsa_test_harness::HarnessFailurePoint,
) -> TestResult {
    let translation = context.realm_rec_stage2()?;
    let rejected = context.with_harness_failure(point, 0, || translation.finish());
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    realm_fresh_sentinel(context)
}

fn realm_destruction_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_finish_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::RealmDestruction,
    )
}

fn realm_undelegation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    realm_finish_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::GranuleUndelegation,
    )
}

fn realm_translation_cycle(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    const INITIAL: u64 = 0x5245_432d_554e_5052;
    const MUTATED: u64 = 0x5245_432d_4d41_5050;

    let mut translation = context.realm_rec_stage2()?;
    translation.map()?;
    let address = translation.input_address();
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
    let initial = vmsa_test_harness::expect_value(execution.read_u64(address), INITIAL);
    if !matches!(initial, TestResult::Pass) {
        return initial;
    }
    translation.protect_read_only()?;
    let read_only = vmsa_test_harness::expect_value(execution.read_u64(address), INITIAL);
    if !matches!(read_only, TestResult::Pass) {
        return read_only;
    }
    let permission = vmsa_test_harness::expect_fault(
        execution.write_u64(address, MUTATED),
        vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Permission),
            access: Some(vmsa_test_harness::AccessKind::Write),
            stage: Some(vmsa_test_harness::FaultStage::Stage2),
            level: None,
        },
    );
    if !matches!(permission, TestResult::Pass) {
        return permission;
    }
    translation.protect_read_write()?;
    let written = vmsa_test_harness::expect_completed(execution.write_u64(address, MUTATED));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    let mutated = vmsa_test_harness::expect_value(execution.read_u64(address), MUTATED);
    if !matches!(mutated, TestResult::Pass) {
        return mutated;
    }
    let restored = vmsa_test_harness::expect_completed(execution.write_u64(address, INITIAL));
    if !matches!(restored, TestResult::Pass) {
        return restored;
    }
    execution.finish()?;

    translation.unmap()?;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
    let fault = vmsa_test_harness::expect_fault(
        execution.read_u64(address),
        vmsa_test_harness::ExpectedFault::translation(vmsa_test_harness::FaultStage::Stage2),
    );
    execution.finish()?;
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }

    translation.map()?;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
    let remapped = vmsa_test_harness::expect_value(execution.read_u64(address), INITIAL);
    execution.finish()?;
    if !matches!(remapped, TestResult::Pass) {
        return remapped;
    }
    translation.unmap()?;
    translation.finish()?;
    TestResult::Pass
}

macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_rec_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $rec),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_rec_dispatch);

#[unsafe(no_mangle)]
/// Enters the Realm stage-2 harness from a REC at R-EL1.
///
/// TFTF and TF-RMM retain ownership of the REC's stage-2 translation and
/// lifecycle while the payload performs the architecturally visible access.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_realm_stage2_entry(
    context: *const BootContext,
    record: *mut RealmRecRecord,
) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    let Some(record) = (unsafe { RealmRecRecord::from_abi(record) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    REC_TEST_IPA.store(record.ipa, Ordering::Release);
    REC_FAULT_IPA.store(record.result, Ordering::Release);
    REC_RECORD.store(record as *mut RealmRecRecord as u64, Ordering::Release);
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_REALM) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    environment.enable_rec_services(record);
    let result = outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Realm,
        dispatch,
        RunOptions {
            target: "realm-stage2",
            profile: vmsa_test_harness::BootProfile::RealmRecStage2,
            filter,
            baseline: Requirements::RME,
        },
    ));
    record.result = u64::from(result);
    record.status = if result == common::ENTRY_COMPLETE {
        REALM_REC_STATUS_COMPLETE
    } else {
        REALM_REC_STATUS_FAILED
    };
    result
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
