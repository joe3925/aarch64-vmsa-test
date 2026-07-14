#![no_std]

#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/smoke.rs"]
pub mod smoke;
#[path = "../../common/translation_smoke.rs"]
mod translation_smoke;

use common::{BootContext, REGIME_NORMAL, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};

define_environment!(NsEl2Environment, aarch64_vmsa::regime::NonSecureEl2Stage1);
pub type CurrentEnvironment = NsEl2Environment;
pub type CurrentRegime = aarch64_vmsa::regime::NonSecureEl2Stage1;
pub type Stage2Regime = aarch64_vmsa::regime::NonSecureEl2Stage2;
pub type LowerRegime = aarch64_vmsa::regime::NonSecureEl1Stage1;

fn current_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_access(context)
}
fn current_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::current_fault(context)
}
fn access_widths(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::access_widths(context)
}
fn pair_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::pair_access(context)
}
fn ordered_atomic_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::ordered_atomic_access(context)
}
fn address_translation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::address_translation(context)
}
fn lower_address_translation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_address_translation(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn generated_execution(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::generated_execution(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn live_range_mapping(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::live_range_mapping(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn multi_pe_visibility(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::multi_pe_translation_visibility(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn semantic_codec(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::semantic_codec(context)
}
fn permission_semantics(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::permission_semantics(context)
}
fn hardware_access_dirty(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::hardware_access_dirty(context)
}
fn recursive_table_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::recursive_table_access(context)
}
fn allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::allocation_failure(context)
}
fn lower_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_access(context)
}
fn lower_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_fault_expected(
        context,
        vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::External),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: None,
            level: None,
        },
    )
}
fn el0_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::el0_access(context)
}
fn el2_el0_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let baseline = smoke::el2_el0_access(context);
    if !matches!(baseline, TestResult::Pass) {
        return baseline;
    }
    const ADDRESS: u64 = 0x6a00_0000;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = vmsa_test_harness::AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = vmsa_test_harness::AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = vmsa_test_harness::PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: vmsa_test_harness::LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: vmsa_test_harness::TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    translation.map_for::<
        aarch64_vmsa::regime::NonSecureEl2HostStage1,
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
    >(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes {
            writable: true,
            executable: false,
            user_accessible: true,
        },
    )?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, 7),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    if !matches!(
        execution.atomic_swap_u64(ADDRESS, 11),
        vmsa_test_harness::AccessResult::Completed { value: 7 }
    ) || !matches!(
        execution.exclusive_add_u64(ADDRESS, 5),
        vmsa_test_harness::AccessResult::Completed { value: 11 }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    execution.finish()?;
    drop(translation);
    TestResult::Pass
}
fn lpa2_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_lpa2(context)
}
fn d128_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_d128(context)
}
fn translation_cycle(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::stage1_translation_cycle(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn asid_isolation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_stage1_asid_isolation::<CurrentEnvironment, LowerRegime>(
        context,
        vmsa_test_harness::RegimeAttributes::Normal,
    )
}
fn vmid_isolation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::stage2_vmid_isolation(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn combined_stage1_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::combined_stage1_stage2(context)
}
fn mapper_16k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_16k(context)
}
fn mapper_64k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::mapper_64k(context)
}

fn active_16k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_16k(context)
}
fn malformed_descriptor_recovery(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::malformed_descriptor_recovery(context)
}
fn active_4k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_4k(context)
}
fn active_64k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_64k(context)
}
fn active_lpa2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_lpa2(context)
}
fn active_d128(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_d128(context)
}
fn active_d128_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    translation_smoke::active_d128_stage2(context)
}
macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_normal_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $normal),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_normal_dispatch);

#[unsafe(no_mangle)]
/// Enters the Normal-world EL2 harness from the firmware integration shim.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_ns_el2_entry(context: *const BootContext) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    if context.lower_el_entry != vmsa_test_lower_el::entry_address() {
        return common::ENTRY_INVALID_CONTEXT;
    }
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_NORMAL)
    else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Normal,
        dispatch,
        RunOptions {
            target: "ns-el2",
            profile: vmsa_test_harness::BootProfile::NsEl2,
            filter,
            baseline: Requirements::NONE,
        },
    ))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
