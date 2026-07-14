#![no_std]
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/smoke.rs"]
pub mod smoke;
use common::{BootContext, REGIME_SECURE, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};
define_environment!(SecureEl2Environment, aarch64_vmsa::regime::SecureEl2Stage1);
pub type CurrentEnvironment = SecureEl2Environment;
pub type CurrentRegime = aarch64_vmsa::regime::SecureEl2Stage1;
pub type LowerRegime = aarch64_vmsa::regime::SecureEl1Stage1;
pub type Stage2Regime = aarch64_vmsa::regime::SecureEl2SecureIpaStage2;
fn current_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_access(c)
}
fn current_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_fault(c)
}
fn address_translation(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::address_translation(c)
}
fn pas_semantics(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience, SecureSelectablePa,
        SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissionLimits, SoftwareMetadata,
        Stage2LeafPermissions, Stage2MemoryAttributes, Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::{SecureEl2NonSecureIpaStage2, SecureEl2SecureIpaStage2};

    const SECURE_VA: u64 = 0x5000_0000;
    const NON_SECURE_VA: u64 = 0x5000_1000;
    let cacheability = Cacheability::Cacheable {
        policy: CachePolicy::WriteBack,
        transience: MemoryTransience::NonTransient,
        allocation: AllocationHints::ReadWriteAllocate,
    };
    let memory = MemoryAttributes::Normal {
        inner: cacheability,
        outer: cacheability,
    };
    let config = LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let stage1_leaf = |pas| SemanticStage1LeafAttrs {
        memory,
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
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
    let stage1_table = |pas| SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let secure_page = context.allocate_page()?;
    let non_secure_page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper(&mut root)?;
    for (address, output, pas) in [
        (
            SECURE_VA,
            secure_page.phys_addr(),
            SecureSelectablePa::Secure,
        ),
        (
            NON_SECURE_VA,
            non_secure_page.phys_addr(),
            SecureSelectablePa::NonSecure,
        ),
    ] {
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            address,
            output,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_leaf(pas),
            stage1_table(pas),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.pas != pas {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }

    let stage2_leaf = |output_address_space| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory),
        permissions: Stage2LeafPermissions {
            data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let stage2_config = |output_pas| LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas,
    };
    let secure_config = stage2_config(SecureSelectablePa::Secure);
    let non_secure_config = stage2_config(SecureSelectablePa::NonSecure);
    let input_bits = 48;
    let output_bits = 48;
    let mut secure_root = context.allocate_root()?;
    let mut secure_mapper = context
        .offline_mapper_for_format_with_geometry::<SecureEl2SecureIpaStage2, Granule4KiB, Vmsa64>(
            &mut secure_root,
            aarch64_vmsa::address::Level::L0,
            input_bits,
            output_bits,
        )?;
    secure_mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &secure_config,
        SECURE_VA,
        secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::Secure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if secure_mapper
        .inspect_semantic_leaf::<VmsaAttributeCodec, _>(SECURE_VA, &secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::Secure
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut non_secure_root = context.allocate_root()?;
    let mut non_secure_mapper = context.offline_mapper_for_format_with_geometry::<
        SecureEl2NonSecureIpaStage2,
        Granule4KiB,
        Vmsa64,
    >(
        &mut non_secure_root,
        aarch64_vmsa::address::Level::L0,
        input_bits,
        output_bits,
    )?;
    non_secure_mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &non_secure_config,
        NON_SECURE_VA,
        non_secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::NonSecure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if non_secure_mapper
        .inspect_semantic_leaf::<VmsaAttributeCodec, _>(NON_SECURE_VA, &non_secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::NonSecure
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}
fn lower_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_access(c)
}
fn lower_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_fault_expected(
        c,
        vmsa_test_harness::ExpectedFault::translation_read_stage1(),
    )
}
fn lpa2_mapper(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_lpa2(c)
}
fn translation_cycle(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::stage1_translation_cycle(c, vmsa_test_harness::RegimeAttributes::Secure)
}
macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_secure_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $secure),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_secure_dispatch);
#[unsafe(no_mangle)]
/// Enters the Secure EL2 harness from Hafnium's integration shim.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_secure_el2_entry(context: *const BootContext) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    if context.lower_el_entry != vmsa_test_lower_el::entry_address() {
        return common::ENTRY_INVALID_CONTEXT;
    }
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_SECURE)
    else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Secure,
        dispatch,
        RunOptions {
            target: "secure-el2",
            profile: vmsa_test_harness::BootProfile::SecureEl2,
            filter,
            baseline: Requirements::SEL2,
        },
    ))
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
