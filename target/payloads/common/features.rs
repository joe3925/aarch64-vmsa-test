#![allow(unused_imports, unused_macros)]

use aarch64_vmsa::arch::{IdRegisterSnapshot, SecurityStates, VmsaFeatures, decode_features};
use vmsa_test_harness::{Capabilities, FailureKind, TestFailure, TestResult};

macro_rules! require_regimes {
    ($features:expr; $($regime:ty),+ $(,)?) => {
        true $(&& aarch64_vmsa::regime::validate_regime::<$regime>($features).is_ok())+
    };
}
pub(crate) use require_regimes;

macro_rules! require_base_format {
    ($features:expr; $regime:ty) => {{
        use aarch64_vmsa::address::{Granule4KiB, Granule16KiB, Granule64KiB};
        use aarch64_vmsa::descriptor::Vmsa64;
        aarch64_vmsa::regime::validate_regime_format::<Vmsa64, $regime, Granule4KiB>($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa64, $regime, Granule16KiB>(
                $features,
            )
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa64, $regime, Granule64KiB>(
                $features,
            )
            .is_ok()
    }};
}
pub(crate) use require_base_format;

macro_rules! require_all_formats {
    ($features:expr; $regime:ty) => {{
        use aarch64_vmsa::address::{Granule16KiB, Granule4KiB, Granule64KiB};
        use aarch64_vmsa::descriptor::{Vmsa128, Vmsa64Lpa2};
        $crate::features::require_base_format!($features; $regime)
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa64Lpa2,
                $regime,
                Granule4KiB,
            >($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa64Lpa2,
                $regime,
                Granule16KiB,
            >($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa64Lpa2,
                $regime,
                Granule64KiB,
            >($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa128,
                $regime,
                Granule4KiB,
            >($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa128,
                $regime,
                Granule16KiB,
            >($features)
            .is_ok()
            && aarch64_vmsa::regime::validate_regime_format::<
                Vmsa128,
                $regime,
                Granule64KiB,
            >($features)
            .is_ok()
    }};
}
pub(crate) use require_all_formats;

#[allow(unused_macros)]
macro_rules! require_extended_formats_unsupported {
    ($features:expr; $regime:ty) => {{
        use aarch64_vmsa::address::{Granule4KiB, Granule16KiB, Granule64KiB};
        use aarch64_vmsa::descriptor::{Vmsa64Lpa2, Vmsa128};
        aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule4KiB>($features)
            .is_err()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule16KiB>(
                $features,
            )
            .is_err()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule64KiB>(
                $features,
            )
            .is_err()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule4KiB>(
                $features,
            )
            .is_err()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule16KiB>(
                $features,
            )
            .is_err()
            && aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule64KiB>(
                $features,
            )
            .is_err()
    }};
}
pub(crate) use require_extended_formats_unsupported;

pub fn regime_result(supported: bool) -> TestResult {
    if supported {
        TestResult::Pass
    } else {
        mismatch(0x30)
    }
}

pub fn requirement_unions() -> TestResult {
    let required = aarch64_vmsa::arch::FeatureRequirements::NONE
        .with_el2()
        .with_el3()
        .with_el2_and0()
        .with_sel2()
        .with_stage2()
        .with_xnx()
        .with_lpa2()
        .with_d128()
        .with_d128_stage2()
        .with_extended_input_address()
        .with_extended_output_address()
        .with_security_state(aarch64_vmsa::arch::SecurityStates::NON_SECURE);
    let current = VmsaFeatures::current();
    if !current.verify(required) {
        return mismatch(0x40);
    }
    let union = aarch64_vmsa::arch::FeatureRequirements::NONE
        .with_el2()
        .union(
            aarch64_vmsa::arch::FeatureRequirements::NONE
                .with_stage2()
                .with_security_state(aarch64_vmsa::arch::SecurityStates::NON_SECURE),
        );
    if !current.verify(union)
        || aarch64_vmsa::arch::FeatureStatus::Unknown(0xe).is_implemented()
        || aarch64_vmsa::arch::FeatureStatus::Unknown(0xe).unknown_raw() != Some(0xe)
    {
        return mismatch(0x41);
    }
    TestResult::Pass
}

pub fn live_snapshot_agreement(capabilities: Capabilities) -> TestResult {
    let snapshot = IdRegisterSnapshot::current();
    let decoded = decode_features(snapshot);
    if VmsaFeatures::current() != decoded {
        return mismatch(1);
    }

    let agreements = [
        (decoded.el2.is_implemented(), capabilities.el2),
        (decoded.el3.is_implemented(), capabilities.el3),
        (decoded.el2_and0.is_implemented(), capabilities.el2_and0),
        (decoded.sel2.is_implemented(), capabilities.sel2),
        (decoded.rme.is_implemented(), capabilities.rme),
        (decoded.stage2.is_implemented(), capabilities.stage2),
        (decoded.xnx.is_implemented(), capabilities.xnx),
        (decoded.lpa2.is_implemented(), capabilities.lpa2),
        (decoded.d128.is_implemented(), capabilities.d128),
        (
            decoded.d128_stage2.is_implemented(),
            capabilities.d128_stage2,
        ),
        (
            decoded.extended_input_address.is_implemented(),
            capabilities.extended_input_address,
        ),
        (
            decoded.extended_output_address.is_implemented(),
            capabilities.extended_output_address,
        ),
    ];
    for (index, (crate_value, harness_value)) in agreements.into_iter().enumerate() {
        if crate_value != harness_value {
            return mismatch(0x10 + index as u64);
        }
    }
    if decoded.security_states.bits() != capabilities.security_states {
        return mismatch(0x20);
    }
    TestResult::Pass
}

pub fn security_state_membership(
    capabilities: Capabilities,
    required_security_state: SecurityStates,
) -> TestResult {
    let features = VmsaFeatures::current();
    if features.security_states.contains(required_security_state) {
        TestResult::Pass
    } else if required_security_state == SecurityStates::ROOT && !capabilities.rme {
        TestResult::Skip(vmsa_test_harness::SkipReason::Unsupported)
    } else {
        mismatch(0x21)
    }
}

const fn mismatch(actual: u64) -> TestResult {
    TestResult::Fail(TestFailure {
        kind: FailureKind::WrongValue,
        expected: 0,
        actual,
    })
}
