#![no_std]
#[path = "../../common/access.rs"]
#[allow(dead_code)]
mod access;
#[path = "../../common/address_translation.rs"]
#[allow(dead_code)]
mod address_translation;
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/faults.rs"]
#[allow(dead_code)]
mod faults;
#[path = "../../common/features.rs"]
#[allow(dead_code)]
mod features;
#[path = "../../common/invalidation.rs"]
#[allow(dead_code)]
mod invalidation;
#[path = "../../common/mapper_live.rs"]
#[allow(dead_code)]
mod mapper_live;
#[path = "../../common/root_pas.rs"]
mod pas;
#[path = "../../common/root_cases.rs"]
mod root_cases;
#[path = "../../common/runtime_support.rs"]
#[allow(dead_code)]
mod runtime_support;
#[path = "../../common/semantic_root.rs"]
mod semantic_root;
use common::{BootContext, REGIME_ROOT, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};
define_environment!(RootEl3Environment, aarch64_vmsa::regime::RootEl3Stage1);
pub type CurrentEnvironment = RootEl3Environment;
pub type CurrentRegime = aarch64_vmsa::regime::RootEl3Stage1;
pub type LowerRegime = aarch64_vmsa::regime::RootEl3Stage1;
fn feature_snapshot_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::live_snapshot_agreement(context.capabilities())
}
fn security_state_membership(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::security_state_membership(
        context.capabilities(),
        aarch64_vmsa::arch::SecurityStates::ROOT,
    )
}
fn regime_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let current = aarch64_vmsa::arch::VmsaFeatures::current();
    features::regime_result(
        aarch64_vmsa::regime::validate_regime::<aarch64_vmsa::regime::RootEl3Stage1>(&current)
            .is_ok(),
    )
}
fn regime_format_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::regime::RootEl3Stage1;
    let current = &aarch64_vmsa::arch::VmsaFeatures::current();
    let supported = features::require_base_format!(current; RootEl3Stage1)
        && features::require_live_format_agreement!(current; RootEl3Stage1, stage2 = false);
    features::regime_result(supported)
}
fn current_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::current_access(c)
}
fn current_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    faults::current_fault(c)
}
fn address_translation(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    address_translation::address_translation(c)
}
fn d128_mapper(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::mapper_d128(c)
}
fn d128_reserved_rejection(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    root_cases::d128_reserved_rejection()
}
fn d128_permission_indirection(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    root_cases::d128_permission_indirection(context)
}
fn translation_cycle(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::stage1_translation_cycle(c, vmsa_test_harness::RegimeAttributes::Root)
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
