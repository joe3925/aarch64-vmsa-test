#![allow(unused_imports, unused_macros)]

use aarch64_vmsa::arch::{
    Capability, FeatureStatus, IdRegisterSnapshot, SecurityStates, VmsaFeatures, decode_features,
};
use vmsa_test_harness::{Capabilities, FailureKind, TestFailure, TestResult};

macro_rules! require_regimes {
    ($features:expr; $($regime:ty),+ $(,)?) => {
        true $(&& aarch64_vmsa::regime::validate_regime::<$regime>($features).is_ok())+
    };
}
pub(crate) use require_regimes;

macro_rules! require_base_format {
    ($features:expr; $regime:ty) => {{
        use aarch64_vmsa::config::format::Vmsa64;
        use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
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
        use aarch64_vmsa::address::{};
        use aarch64_vmsa::config::granule::{Granule16KiB, Granule4KiB, Granule64KiB};
        use aarch64_vmsa::descriptor::{};
        use aarch64_vmsa::config::format::{Vmsa128, Vmsa64Lpa2};
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

macro_rules! require_live_format_agreement {
    ($features:expr; $regime:ty, stage2 = $stage2:expr) => {{
        use aarch64_vmsa::config::format::{Vmsa64Lpa2, Vmsa128};
        use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
        let regime_supported = aarch64_vmsa::regime::validate_regime::<$regime>($features).is_ok();
        let lpa2_expected = regime_supported
            && $features
                .status(aarch64_vmsa::arch::Capability::Lpa2)
                .is_implemented()
            && $features
                .status(aarch64_vmsa::arch::Capability::ExtendedOutputAddress)
                .is_implemented();
        let d128_expected = regime_supported
            && $features
                .status(aarch64_vmsa::arch::Capability::D128)
                .is_implemented()
            && (!$stage2
                || $features
                    .status(aarch64_vmsa::arch::Capability::D128Stage2)
                    .is_implemented());
        let lpa2_results = [
            aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule4KiB>(
                $features,
            )
            .is_ok(),
            aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule16KiB>(
                $features,
            )
            .is_ok(),
            aarch64_vmsa::regime::validate_regime_format::<Vmsa64Lpa2, $regime, Granule64KiB>(
                $features,
            )
            .is_ok(),
        ];
        let d128_results = [
            aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule4KiB>(
                $features,
            )
            .is_ok(),
            aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule16KiB>(
                $features,
            )
            .is_ok(),
            aarch64_vmsa::regime::validate_regime_format::<Vmsa128, $regime, Granule64KiB>(
                $features,
            )
            .is_ok(),
        ];
        lpa2_results
            .into_iter()
            .all(|actual| actual == lpa2_expected)
            && d128_results
                .into_iter()
                .all(|actual| actual == d128_expected)
    }};
}
pub(crate) use require_live_format_agreement;

pub fn regime_result(supported: bool) -> TestResult {
    if supported {
        TestResult::Pass
    } else {
        mismatch(0x30)
    }
}

pub fn requirement_unions() -> TestResult {
    let required = aarch64_vmsa::arch::FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::El3)
        .require(Capability::El2And0)
        .require(Capability::Sel2)
        .require(Capability::Stage2)
        .require(Capability::Xnx)
        .require(Capability::Lpa2)
        .require(Capability::D128)
        .require(Capability::D128Stage2)
        .require(Capability::ExtendedInputAddress)
        .require(Capability::ExtendedOutputAddress)
        .require_security_state(aarch64_vmsa::arch::SecurityStates::NON_SECURE);
    let current = VmsaFeatures::current();
    if !current.verify(required) {
        return mismatch(0x40);
    }
    let union = aarch64_vmsa::arch::FeatureRequirements::NONE
        .require(Capability::El2)
        .union(
            aarch64_vmsa::arch::FeatureRequirements::NONE
                .require(Capability::Stage2)
                .require_security_state(aarch64_vmsa::arch::SecurityStates::NON_SECURE),
        );
    if !current.verify(union)
        || aarch64_vmsa::arch::FeatureStatus::Unknown(0xe).is_implemented()
        || aarch64_vmsa::arch::FeatureStatus::Unknown(0xe).unknown_raw() != Some(0xe)
    {
        return mismatch(0x41);
    }
    TestResult::Pass
}

fn status_result(actual: FeatureStatus, expected: FeatureStatus, tag: u64) -> TestResult {
    if actual == expected {
        TestResult::Pass
    } else {
        mismatch(tag)
    }
}

const fn binary_expected(raw: u8) -> FeatureStatus {
    match raw {
        0 => FeatureStatus::NotImplemented,
        1 => FeatureStatus::Implemented,
        value => FeatureStatus::Unknown(value),
    }
}

pub fn decode_binary_raw_encodings() -> TestResult {
    for raw in 0u8..=15 {
        let nibble = u64::from(raw);
        let expected = binary_expected(raw);
        let snapshots = [
            IdRegisterSnapshot {
                id_aa64pfr0_el1: nibble << 36,
                ..IdRegisterSnapshot::default()
            },
            IdRegisterSnapshot {
                id_aa64mmfr1_el1: nibble << 8,
                ..IdRegisterSnapshot::default()
            },
            IdRegisterSnapshot {
                id_aa64mmfr1_el1: nibble << 28,
                ..IdRegisterSnapshot::default()
            },
            IdRegisterSnapshot {
                id_aa64mmfr3_el1: nibble << 32,
                ..IdRegisterSnapshot::default()
            },
            IdRegisterSnapshot {
                id_aa64mmfr3_el1: nibble << 36,
                ..IdRegisterSnapshot::default()
            },
        ];
        let actual = [
            decode_features(snapshots[0]).status(Capability::Sel2),
            decode_features(snapshots[1]).status(Capability::El2And0),
            decode_features(snapshots[2]).status(Capability::Xnx),
            decode_features(snapshots[3]).status(Capability::D128),
            decode_features(snapshots[4]).status(Capability::D128Stage2),
        ];
        if actual.into_iter().any(|value| value != expected) {
            return mismatch(0x100 + u64::from(raw));
        }
    }
    TestResult::Pass
}

pub fn decode_exception_level_raw_encodings() -> TestResult {
    for raw in 0u8..=15 {
        let expected = match raw {
            0 => FeatureStatus::NotImplemented,
            1 | 2 => FeatureStatus::Implemented,
            value => FeatureStatus::Unknown(value),
        };
        for shift in [8u8, 12u8] {
            let actual = decode_features(IdRegisterSnapshot {
                id_aa64pfr0_el1: u64::from(raw) << shift,
                ..IdRegisterSnapshot::default()
            });
            let value = if shift == 8 {
                actual.status(Capability::El2)
            } else {
                actual.status(Capability::El3)
            };
            if value != expected {
                return mismatch(0x200 + u64::from(raw));
            }
        }
    }
    TestResult::Pass
}

pub fn decode_rme_raw_encodings() -> TestResult {
    for raw in 0u8..=15 {
        let expected = match raw {
            0 => FeatureStatus::NotImplemented,
            1..=3 => FeatureStatus::Implemented,
            value => FeatureStatus::Unknown(value),
        };
        let actual = decode_features(IdRegisterSnapshot {
            id_aa64pfr0_el1: u64::from(raw) << 52,
            ..IdRegisterSnapshot::default()
        });
        if !matches!(
            status_result(actual.status(Capability::Rme), expected, 0),
            TestResult::Pass
        ) {
            return mismatch(0x300 + u64::from(raw));
        }
    }
    TestResult::Pass
}

pub fn decode_varange_raw_encodings() -> TestResult {
    for raw in 0u8..=15 {
        let expected = match raw {
            0 => FeatureStatus::NotImplemented,
            1 | 2 => FeatureStatus::Implemented,
            value => FeatureStatus::Unknown(value),
        };
        let actual = decode_features(IdRegisterSnapshot {
            id_aa64mmfr2_el1: u64::from(raw) << 16,
            ..IdRegisterSnapshot::default()
        });
        if actual.status(Capability::ExtendedInputAddress) != expected {
            return mismatch(0x400 + u64::from(raw));
        }
    }
    TestResult::Pass
}

pub fn decode_parange_raw_encodings() -> TestResult {
    for raw in 0u8..=15 {
        let expected = match raw {
            0..=5 => FeatureStatus::NotImplemented,
            6 | 7 => FeatureStatus::Implemented,
            value => FeatureStatus::Unknown(value),
        };
        let actual = decode_features(IdRegisterSnapshot {
            id_aa64mmfr0_el1: u64::from(raw),
            ..IdRegisterSnapshot::default()
        });
        if actual.status(Capability::ExtendedOutputAddress) != expected {
            return mismatch(0x500 + u64::from(raw));
        }
    }
    TestResult::Pass
}

fn decode_lpa2_field(shift: u8, implemented: u8, absent: &[u8]) -> TestResult {
    for raw in 0u8..=15 {
        let expected = if raw == implemented {
            FeatureStatus::Implemented
        } else if absent.contains(&raw) {
            FeatureStatus::NotImplemented
        } else {
            FeatureStatus::Unknown(raw)
        };
        let actual = decode_features(IdRegisterSnapshot {
            id_aa64mmfr0_el1: u64::from(raw) << shift,
            ..IdRegisterSnapshot::default()
        });
        if actual.status(Capability::Lpa2) != expected {
            return mismatch(0x600 + u64::from(shift) + u64::from(raw));
        }
    }
    TestResult::Pass
}

pub fn decode_lpa2_tg4_raw_encodings() -> TestResult {
    decode_lpa2_field(28, 1, &[0, 15])
}

pub fn decode_lpa2_tg16_raw_encodings() -> TestResult {
    decode_lpa2_field(20, 2, &[0, 1])
}

pub fn decode_lpa2_secondary_raw_encodings() -> TestResult {
    let first = decode_lpa2_field(40, 3, &[0, 1, 2]);
    if !matches!(first, TestResult::Pass) {
        return first;
    }
    decode_lpa2_field(32, 3, &[0, 1, 2])
}

pub fn decode_lpa2_priority() -> TestResult {
    let unknowns = [
        (2u64 << 28 | 3u64 << 20 | 4u64 << 40 | 5u64 << 32, 2),
        (3u64 << 20 | 4u64 << 40 | 5u64 << 32, 3),
        (4u64 << 40 | 5u64 << 32, 4),
        (5u64 << 32, 5),
    ];
    for (register, expected) in unknowns {
        if decode_features(IdRegisterSnapshot {
            id_aa64mmfr0_el1: register,
            ..IdRegisterSnapshot::default()
        })
        .status(Capability::Lpa2)
            != FeatureStatus::Unknown(expected)
        {
            return mismatch(0x700 + u64::from(expected));
        }
    }
    for register in [1u64 << 28 | 3u64 << 20, 2u64 << 20 | 4u64 << 40] {
        if decode_features(IdRegisterSnapshot {
            id_aa64mmfr0_el1: register,
            ..IdRegisterSnapshot::default()
        })
        .status(Capability::Lpa2)
            != FeatureStatus::Implemented
        {
            return mismatch(0x710);
        }
    }
    TestResult::Pass
}

pub fn decode_derived_merge_orderings() -> TestResult {
    let states = [
        (0u8, FeatureStatus::NotImplemented),
        (1u8, FeatureStatus::Implemented),
        (3u8, FeatureStatus::Unknown(3)),
    ];
    let derived = [
        (0u8, FeatureStatus::NotImplemented),
        (1u8, FeatureStatus::Implemented),
        (2u8, FeatureStatus::Unknown(2)),
    ];
    for (primary_raw, primary) in states {
        for (derived_raw, secondary) in derived {
            let expected_input = if primary.is_implemented() || secondary.is_implemented() {
                FeatureStatus::Implemented
            } else if matches!(primary, FeatureStatus::Unknown(_)) {
                primary
            } else {
                secondary
            };
            let output_primary = match primary_raw {
                0 => FeatureStatus::NotImplemented,
                1 => FeatureStatus::Implemented,
                _ => FeatureStatus::Unknown(8),
            };
            let expected_output = if output_primary.is_implemented() || secondary.is_implemented() {
                FeatureStatus::Implemented
            } else if matches!(output_primary, FeatureStatus::Unknown(_)) {
                output_primary
            } else {
                secondary
            };
            let snapshot = IdRegisterSnapshot {
                id_aa64mmfr0_el1: if primary_raw == 1 {
                    6
                } else if primary_raw == 3 {
                    8
                } else {
                    0
                },
                id_aa64mmfr2_el1: u64::from(primary_raw) << 16,
                id_aa64mmfr3_el1: u64::from(derived_raw) << 32,
                ..IdRegisterSnapshot::default()
            };
            let actual = decode_features(snapshot);
            if actual.status(Capability::ExtendedInputAddress) != expected_input
                || actual.status(Capability::ExtendedOutputAddress) != expected_output
            {
                return mismatch(0x800 + u64::from(primary_raw) * 16 + u64::from(derived_raw));
            }
        }
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
        (
            decoded.status(Capability::El2).is_implemented(),
            capabilities.el2,
        ),
        (
            decoded.status(Capability::El3).is_implemented(),
            capabilities.el3,
        ),
        (
            decoded.status(Capability::El2And0).is_implemented(),
            capabilities.el2_and0,
        ),
        (
            decoded.status(Capability::Sel2).is_implemented(),
            capabilities.sel2,
        ),
        (
            decoded.status(Capability::Rme).is_implemented(),
            capabilities.rme,
        ),
        (
            decoded.status(Capability::Stage2).is_implemented(),
            capabilities.stage2,
        ),
        (
            decoded.status(Capability::Xnx).is_implemented(),
            capabilities.xnx,
        ),
        (
            decoded.status(Capability::Lpa2).is_implemented(),
            capabilities.lpa2,
        ),
        (
            decoded.status(Capability::D128).is_implemented(),
            capabilities.d128,
        ),
        (
            decoded.status(Capability::D128Stage2).is_implemented(),
            capabilities.d128_stage2,
        ),
        (
            decoded
                .status(Capability::ExtendedInputAddress)
                .is_implemented(),
            capabilities.extended_input_address,
        ),
        (
            decoded
                .status(Capability::ExtendedOutputAddress)
                .is_implemented(),
            capabilities.extended_output_address,
        ),
    ];
    for (index, (crate_value, harness_value)) in agreements.into_iter().enumerate() {
        if crate_value != harness_value {
            return mismatch(0x10 + index as u64);
        }
    }
    if decoded.security_states().bits() != capabilities.security_states {
        return mismatch(0x20);
    }
    TestResult::Pass
}

pub fn security_state_membership(
    capabilities: Capabilities,
    required_security_state: SecurityStates,
) -> TestResult {
    let features = VmsaFeatures::current();
    if features.security_states().contains(required_security_state) {
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
