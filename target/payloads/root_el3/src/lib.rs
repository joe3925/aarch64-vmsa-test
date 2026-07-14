#![no_std]
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/smoke.rs"]
pub mod smoke;
use common::{BootContext, REGIME_ROOT, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};
define_environment!(RootEl3Environment, aarch64_vmsa::regime::RootEl3Stage1);
pub type CurrentEnvironment = RootEl3Environment;
pub type CurrentRegime = aarch64_vmsa::regime::RootEl3Stage1;
pub type LowerRegime = aarch64_vmsa::regime::RootEl3Stage1;
fn current_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_access(c)
}
fn current_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_fault(c)
}
fn address_translation(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::address_translation(c)
}
fn d128_mapper(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_d128(c)
}
fn d128_reserved_rejection(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::low_level::raw::{
        FourBit, PermissionIndices, RawShareability, RawVmsa128Stage1LeafAttrs, Stage1NotDirty,
        TenBit,
    };
    type Layout = <Vmsa128 as HasLayout<
        aarch64_vmsa::translation::Stage1,
        aarch64_vmsa::address::Granule4KiB,
    >>::Layout;
    let zero4 = FourBit::new(0).map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let fields = RawVmsa128Stage1LeafAttrs {
        attr_index: zero4,
        bbm_nt: true,
        not_dirty: Stage1NotDirty::new(false),
        shareability: RawShareability::from_bits(0)
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: false,
        contiguous: false,
        guarded: false,
        protected: false,
        permissions: PermissionIndices {
            pi: zero4,
            po: zero4,
        },
        ns: false,
        software: TenBit::new(0).map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?,
    };
    match <Layout as DescriptorLayout<
        Vmsa128,
        aarch64_vmsa::translation::Stage1,
        aarch64_vmsa::address::Granule4KiB,
    >>::leaf_descriptor(
        aarch64_vmsa::address::PhysAddr(0x4000),
        aarch64_vmsa::address::Level::L3,
        fields,
    ) {
        Err(DescriptorError::InvalidNtBbmCombination { .. }) => TestResult::Pass,
        _ => vmsa_test_harness::HarnessError::InvalidState.into(),
    }
}
fn d128_permission_indirection(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyState, LiveVmsaConfig,
        MemoryAttributes, RootExtendedPa, SemanticStage1LeafAttrs,
        SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs, Shareability,
        SoftwareMetadata, Stage1EffectivePermissions, Stage1PermissionRegisterPair,
        Stage1PermissionRegisters, Stage2MemoryMode, VmsaAttributeCodec,
    };
    let permissions = Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadOnly,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let config = LiveVmsaConfig {
        mair: 0x0000_0000_0000_0044,
        mair2: None,
        stage1_permissions: Some(Stage1PermissionRegisters {
            privileged: Stage1PermissionRegisterPair {
                base: 0x5555_5555_5555_5555,
                overlay: Some(0x1111_1111_1111_1111),
            },
            unprivileged: None,
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonSecureExtension,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let attributes = |pas| SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions,
        pas,
        controls: SemanticVmsa128Stage1LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Dirty,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            contiguous: false,
            guarded: false,
            protected: false,
            software: SoftwareMetadata::new(0),
        },
    };
    const ADDRESS: u64 = 0x4000;
    let output = context.allocate_contiguous(4)?;
    let mut root = context.allocate_root()?;
    let input_bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = vmsa_test_harness::LookupLevel::new(-2)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut mapper =
        context.offline_mapper_d128_4k(&mut root, start_level, input_bits, input_bits)?;
    for (index, pas) in [
        RootExtendedPa::Secure,
        RootExtendedPa::NonSecure,
        RootExtendedPa::Root,
        RootExtendedPa::Realm,
    ]
    .into_iter()
    .enumerate()
    {
        let address = ADDRESS + index as u64 * 4096;
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            address,
            output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            attributes(pas),
            SemanticVmsa128Stage1TableAttrs::default(),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.permissions != permissions || decoded.pas != pas {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    TestResult::Pass
}
fn translation_cycle(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::stage1_translation_cycle(c, vmsa_test_harness::RegimeAttributes::Root)
}
macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_root_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $root),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_root_dispatch);
#[unsafe(no_mangle)]
/// Enters the Root EL3 harness from TF-A's integration shim.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_root_el3_entry(context: *const BootContext) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_ROOT) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Root,
        dispatch,
        RunOptions {
            target: "root-el3",
            profile: vmsa_test_harness::BootProfile::RootEl3,
            filter,
            baseline: Requirements::NONE,
        },
    ))
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
