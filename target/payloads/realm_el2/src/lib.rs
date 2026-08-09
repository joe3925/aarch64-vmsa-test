#![no_std]
pub type StageOf<R> = <R as aarch64_vmsa::regime::TranslationRegime>::Stage;
pub type LeafFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeLeafFields<F, R, G>;
pub type TableFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeTableFields<F, R, G>;
#[path = "../../common/access.rs"]
#[allow(dead_code)]
mod access;
#[path = "../../common/address_translation.rs"]
#[allow(dead_code)]
mod address_translation;
#[path = "../../common/coherency.rs"]
#[allow(dead_code)]
mod coherency;
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/faults.rs"]
#[allow(dead_code)]
mod faults;
#[path = "../../common/features.rs"]
#[allow(dead_code)]
mod features;
#[path = "../../common/formats_live.rs"]
#[allow(dead_code)]
mod formats_live;
#[path = "../../common/hardware_updates.rs"]
#[allow(dead_code)]
mod hardware_updates;
#[path = "../../common/invalidation.rs"]
#[allow(dead_code)]
mod invalidation;
#[path = "../../common/malformed_descriptors.rs"]
#[allow(dead_code)]
mod malformed_descriptors;
#[path = "../../common/mapper_live.rs"]
#[allow(dead_code)]
mod mapper_live;
#[path = "../../common/mapper_plans.rs"]
#[allow(dead_code)]
mod mapper_plans;
#[path = "../../common/pas.rs"]
#[allow(dead_code)]
mod pas;
#[path = "../../common/runtime_support.rs"]
#[allow(dead_code)]
mod runtime_support;
#[path = "../../common/semantic_d128.rs"]
mod semantic_d128;
#[path = "../../common/semantic_extended.rs"]
mod semantic_extended;
#[path = "../../common/semantic_host.rs"]
mod semantic_host;
#[path = "../../common/semantic_normal.rs"]
mod semantic_normal;
#[path = "../../common/stage2_leaf_matrix.rs"]
mod stage2_leaf_matrix;
use common::{BootContext, REGIME_REALM, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};
define_environment!(
    RealmEl2Environment,
    aarch64_vmsa::config::regime::RealmEl2Stage1
);
pub type CurrentEnvironment = RealmEl2Environment;
pub type CurrentRegime = aarch64_vmsa::config::regime::RealmEl2Stage1;
pub type D128Regime = aarch64_vmsa::config::regime::RealmEl2HostStage1;
pub const fn current_d128_asid() -> Option<vmsa_test_harness::Asid> {
    Some(vmsa_test_harness::Asid(0x31))
}
pub const fn current_d128_controls(
    bits: vmsa_test_harness::AddressBits,
) -> Option<vmsa_test_harness::TranslationControls> {
    vmsa_test_harness::d128_el1_stage1_controls_4k(bits, bits)
}
pub type LowerRegime = aarch64_vmsa::config::regime::RealmEl1Stage1;
pub type HostRegime = aarch64_vmsa::config::regime::RealmEl2HostStage1;
pub type Stage2Regime = aarch64_vmsa::config::regime::RealmEl2Stage2;
pub type Stage2XnxRegime = aarch64_vmsa::config::regime::RealmEl2Stage2<
    aarch64_vmsa::config::stage2::Stage2XnxPermissions,
>;
pub type AlternateStage2Regime = aarch64_vmsa::config::regime::RealmEl2Stage2;
pub type AlternateStage2XnxRegime = aarch64_vmsa::config::regime::RealmEl2Stage2<
    aarch64_vmsa::config::stage2::Stage2XnxPermissions,
>;
pub type Stage2Pas = aarch64_vmsa::attrs::RealmOrNonSecurePa;
pub const fn stage2_pas() -> Stage2Pas {
    Stage2Pas::Realm
}
pub type LowerPas = ();
pub type HostPas = aarch64_vmsa::attrs::RealmOrNonSecurePa;
pub type HostTablePas = ();
pub type CurrentPas = aarch64_vmsa::attrs::RealmOrNonSecurePa;
pub type CurrentTablePas = ();
pub const fn current_config_pas() -> CurrentPas {
    CurrentPas::Realm
}
pub const fn current_pas() -> CurrentPas {
    CurrentPas::Realm
}
pub const fn current_table_pas() -> CurrentTablePas {}
pub const fn alternate_current_pas() -> Option<CurrentPas> {
    Some(CurrentPas::NonSecure)
}
pub const fn alternate_current_table_pas() -> Option<CurrentTablePas> {
    None
}
pub fn alternate_stage1_pas_fault(address: u64) -> vmsa_test_harness::FaultMatcher {
    vmsa_test_harness::FaultMatcher::new(
        vmsa_test_harness::ExpectedFault::granule_protection_read_stage1(),
    )
    .with_class(vmsa_test_harness::FaultClass::DataAbort)
    .at_address(address)
}
pub const fn current_d128_alias() -> aarch64_vmsa::attrs::D128Stage1AliasKind {
    aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal
}
pub const fn current_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Realm
}
pub const fn lower_pas() -> LowerPas {}
pub const fn host_pas() -> HostPas {
    HostPas::Realm
}
pub const fn host_table_pas() -> HostTablePas {}
pub const fn lower_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Realm
}
pub const fn host_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Realm
}
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
    use aarch64_vmsa::config::regime::{
        RealmEl1Stage1, RealmEl2HostStage1, RealmEl2Stage1, RealmEl2Stage2,
    };
    use aarch64_vmsa::config::stage2::Stage2Permissions;
    use aarch64_vmsa::config::stage2::Stage2XnxPermissions;
    let current = aarch64_vmsa::arch::VmsaFeatures::current();
    features::regime_result(features::require_regimes!(&current;
        RealmEl2Stage1,
        RealmEl1Stage1,
        RealmEl2HostStage1,
        RealmEl2Stage2<Stage2Permissions>,
        RealmEl2Stage2<Stage2XnxPermissions>,
    ))
}
fn regime_format_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::config::regime::{
        RealmEl1Stage1, RealmEl2HostStage1, RealmEl2Stage1, RealmEl2Stage2,
    };
    use aarch64_vmsa::config::stage2::Stage2Permissions;
    use aarch64_vmsa::config::stage2::Stage2XnxPermissions;
    let current = &aarch64_vmsa::arch::VmsaFeatures::current();
    macro_rules! check {
        ($regime:ty) => {
            features::require_base_format!(current; $regime)
                && features::require_live_format_agreement!(current; $regime, stage2 = false)
        };
    }
    features::regime_result(
        check!(RealmEl2Stage1)
            && check!(RealmEl1Stage1)
            && check!(RealmEl2HostStage1)
            && features::require_base_format!(current; RealmEl2Stage2<Stage2Permissions>)
            && features::require_live_format_agreement!(current; RealmEl2Stage2<Stage2Permissions>, stage2 = true)
            && features::require_base_format!(current; RealmEl2Stage2<Stage2XnxPermissions>)
            && features::require_live_format_agreement!(current; RealmEl2Stage2<Stage2XnxPermissions>, stage2 = true),
    )
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
fn pas_semantics(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    pas::realm_semantics(context)
}
fn lower_access(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::lower_access(c)
}
fn lower_fault(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let address = 1u64 << c.capabilities().va_bits.min(47);
    let result = c.lower_read_u64(address);
    vmsa_test_harness::expect_fault(
        result,
        vmsa_test_harness::ExpectedFault::granule_protection_read_stage1(),
    )
}
fn multi_pe_visibility(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    coherency::multi_pe_translation_visibility(context, vmsa_test_harness::RegimeAttributes::Realm)
}
fn live_break_before_make(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::live_break_before_make(context, vmsa_test_harness::RegimeAttributes::Realm)
}
fn translation_cycle(c: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::stage1_translation_cycle(c, vmsa_test_harness::RegimeAttributes::Realm)
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
