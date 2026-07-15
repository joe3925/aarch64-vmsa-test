#![no_std]
#![feature(try_trait_v2)]

mod access;
mod address_translation;
mod capability;
mod catalog;
mod context;
mod environment;
mod fault;
mod lower_el;
mod matrix;
mod memory;
mod registry;
mod report;
mod runner;
mod test;
mod translation;

/// Firmware-adapter integration surface. Test logic must use the stable
/// high-level facade re-exported at this crate's root instead.
#[doc(hidden)]
pub mod adapter {
    pub use crate::access::AccessRequest;
    pub use crate::environment::{Environment, TranslationRegimeEnvironment};
    pub use crate::lower_el::{LowerElCommand, LowerElRequest, LowerElTarget};
    pub use crate::memory::{MemoryScope, TestMemory};
    pub use crate::report::{ByteSink, ProtocolWriter, ReportEvent};
    pub use crate::runner::{RunOptions, RunnerOutcome, run_catalog_tests};
    pub use crate::translation::{
        HardwareManagedStage1Regime, InstalledTranslation, TestFormat, TestGranule, TestRegime,
        TestRegimeFor, TransitionStack, prepare_lower_runtime, prepare_lower_runtime_d128,
    };

    pub const fn translation_controls_from_register(bits: u64) -> crate::TranslationControls {
        crate::TranslationControls::from_bits(bits)
    }

    pub const fn stage1_memory_registers(controls: crate::Stage1MemoryControls) -> (u64, u64) {
        controls.registers()
    }

    pub fn read_capabilities() -> crate::Capabilities {
        crate::Capabilities::read()
    }

    pub fn normalize_fault(
        raw: vmsa_test_architecture::exception::RawFault,
        requested: crate::AccessKind,
    ) -> crate::ObservedFault {
        crate::ObservedFault::from_raw(raw, requested)
    }

    /// Deliberately suppresses a live guard's `Drop` path so the runner's
    /// independent emergency restoration can be exercised by infrastructure
    /// payload adapter logic. This is not part of the test-author facade.
    pub fn force_runner_emergency_restoration<E: Environment>(
        translation: crate::LiveTranslation<'_, E>,
    ) {
        core::mem::forget(translation);
    }
}

pub use access::{AccessKind, AccessOperation, AccessResult};
pub use address_translation::{TranslationQueryAccess, TranslationQueryResult};
pub use capability::{Capabilities, Requirements};
pub use catalog::{CatalogEntry, LogicalTest, TEST_CATALOG, tests_for};
pub use context::{
    CacheMaintenanceOperation, CombinedTlbiOperation, CombinedTranslation, ExecutionSession,
    HardwareUpdateGuard, HarnessFailurePoint, InfrastructureD128Stage1Snapshot,
    InfrastructureStage1Snapshot, LiveTranslation, RealmRecStage2Translation, RealmStage2Mutation,
    RealmStage2Region, SecondaryPeSession, SecondaryPeSessionState, Stage2HardwareUpdateGuard,
    TestContext, TransitionSandbox, TranslationRootId,
};
pub use fault::{ExpectedFault, FaultClass, FaultMatcher, FaultStage, FaultStatus, ObservedFault};
pub use matrix::*;
pub use memory::{MemoryError, MemoryFailurePoint, Page, RootTableMemory};
pub use test::{
    FailureKind, HarnessError, SkipReason, TestFailure, TestResult, TransitionPreparationError,
    expect_completed, expect_fault, expect_matching_fault, expect_permission_fault,
    expect_stage2_fault, expect_translation_fault, expect_value,
};
pub use translation::{
    AddressBits, Asid, AttributeError, D128HardwareManagedAttributes, D128HardwareUpdateInspection,
    D128MappingPermissions, DescriptorBits, Granule, HardwareManagedAttributes,
    HardwareUpdateInspection, IsolatedMalformedTable, LookupLevel, MapLeafResult, MapRangeResult,
    MapperConstructionError, MapperOperationError, MappingAttributes, MappingInspection,
    MemoryAttributeSlot, PhysicalAddress, RegimeAttributes, Stage1MemoryControls, TestGranule,
    TestMapper, TlbiOperation, TlbiScope, TranslationControls, TranslationFormat, TranslationSetup,
    TranslationStage, UnmapResult, Vmid, WalkDescriptorInspection, WalkDescriptorKind,
    WalkInspection, d128_el1_stage1_controls, d128_el1_stage1_controls_4k,
    d128_el2_stage1_controls_4k, d128_stage2_controls, d128_stage2_controls_4k,
    lpa2_el1_stage1_controls, lpa2_el1_stage1_controls_4k, lpa2_el2_stage1_controls,
    lpa2_el2_stage1_controls_4k, lpa2_stage2_controls, lpa2_stage2_controls_4k,
    vmsa64_el1_stage1_controls, vmsa64_el1_stage1_controls_4k, vmsa64_el2_stage1_controls,
    vmsa64_stage2_controls, vmsa64_stage2_controls_4k,
};
