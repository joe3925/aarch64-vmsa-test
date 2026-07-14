#![no_std]
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/smoke.rs"]
pub mod smoke;
use common::{BootContext, REGIME_REALM, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};
define_environment!(RealmEl2Environment, aarch64_vmsa::regime::RealmEl2Stage1);
pub type CurrentEnvironment = RealmEl2Environment;
pub type CurrentRegime = aarch64_vmsa::regime::RealmEl2Stage1;
pub type LowerRegime = aarch64_vmsa::regime::RealmEl1Stage1;
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
    smoke::realm_pas_semantics(context)
}
fn lower_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::lower_access(c)
}
fn lower_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let address = 1u64 << c.capabilities().va_bits.min(47);
    let result = c.lower_read_u64(address);
    vmsa_test_harness::expect_fault(
        result,
        vmsa_test_harness::ExpectedFault::granule_protection_read_stage1(),
    )
}
fn translation_cycle(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    smoke::stage1_translation_cycle(c, vmsa_test_harness::RegimeAttributes::Realm)
}
macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_realm_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $realm),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_realm_dispatch);
#[unsafe(no_mangle)]
/// Enters the Realm EL2 harness from the TRP integration shim.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_realm_el2_entry(context: *const BootContext) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    if context.lower_el_entry != vmsa_test_lower_el::entry_address() {
        return common::ENTRY_INVALID_CONTEXT;
    }
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_REALM) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Realm,
        dispatch,
        RunOptions {
            target: "realm-el2",
            profile: vmsa_test_harness::BootProfile::RealmEl2,
            filter,
            baseline: Requirements::RME,
        },
    ))
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
