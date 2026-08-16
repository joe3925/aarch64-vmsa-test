use aarch64_vmsa::address::Level;
use aarch64_vmsa::attrs::{
    AttrError, AttributeCodec, D128Stage1AliasKind, DataAccess, DeviceMemoryType,
    DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, SemanticStage1LeafAttrs,
    SemanticStage2LeafAttrs, SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage2LeafControls,
    Shareability, SoftwareMetadata, Stage1EffectivePermissions, Stage2MemoryAttributes,
    Stage2MemoryMode, Stage2Permission,
};
use aarch64_vmsa::config::format::Vmsa64;
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::{NonSecureEl2Stage1, NonSecureEl2Stage2};
use vmsa_test_harness::TestResult;

pub fn vmsa64_four_bit() -> TestResult {
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let mut failures = 0;
    for value in 0..=15u16 {
        let one = stage1_leaf(value);
        let one_result =
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                one,
            )
            .and_then(|raw| {
                if raw.software.bits() != value as u8 {
                    return Err(AttrError::RawFieldOutOfRange);
                }
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                    &config,
                    Level::L3,
                    raw,
                )
            });
        let two = stage2_leaf(value);
        let two_result =
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage2, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                two,
            )
            .and_then(|raw| {
                if raw.software.bits() != value as u8 {
                    return Err(AttrError::RawFieldOutOfRange);
                }
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage2, Granule4KiB, _>>::decode_leaf(
                    &config,
                    Level::L3,
                    raw,
                )
            });
        if one_result != Ok(one) || two_result != Ok(two) {
            failures += 1;
        }
    }
    if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        stage1_leaf(16),
    ) != Err(AttrError::RawFieldOutOfRange)
        || <Vmsa64 as AttributeCodec<NonSecureEl2Stage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            stage2_leaf(16),
        ) != Err(AttrError::RawFieldOutOfRange)
    {
        failures += 1;
    }
    if failures == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0,
            actual: failures,
        })
    }
}

pub fn d128_stage1_ten_bit() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage1LeafControls, Stage1EffectivePermissions,
        Stage1PermissionRegisters,
    };
    use aarch64_vmsa::config::format::Vmsa128;

    let config = LiveVmsaConfig {
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings {
            base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
                aarch64_vmsa::attrs::Stage1PermissionRegisters {
                    privileged: 0x8888_8888_8888_8888,
                    unprivileged: None,
                    gcs_implemented: false,
                },
            ),
            overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
                privileged: None,
                unprivileged: None,
            },
        },
        mair: 0,
        mair2: None,
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = |value| SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadOnly,
            unprivileged_data: DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: (),
        controls: SemanticVmsa128Stage1LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            contiguous: false,
            guarded: false,
            protected: false,
            software: SoftwareMetadata::new(value),
        },
    };
    let mut failures = 0;
    for value in 0..=1023u16 {
        let semantic = leaf(value);
        let round_trip =
            <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            )
            .and_then(|raw| {
                if raw.software.bits() != value {
                    return Err(AttrError::RawFieldOutOfRange);
                }
                <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                    &config,
                    Level::L3,
                    raw,
                )
            });
        if round_trip != Ok(semantic) {
            failures += 1;
        }
    }
    if <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf(1024),
    ) != Err(AttrError::RawFieldOutOfRange)
    {
        failures += 1;
    }
    matrix_result(failures)
}

pub fn d128_stage2_ten_bit() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage2LeafControls, Stage2Permission, Stage2PermissionRegisters,
    };
    use aarch64_vmsa::config::format::Vmsa128;
    use aarch64_vmsa::config::stage2::Stage2Permissions;

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings {
            base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
                aarch64_vmsa::attrs::Stage2PermissionRegisters { s2pir_el2: 0 },
            ),
            s2por_el1: None,
        },
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = |value| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions: Stage2Permission::NoAccess,
        output_address_space: (),
        controls: SemanticVmsa128Stage2LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            software: SoftwareMetadata::new(value),
        },
    };
    let mut failures = 0;
    for value in 0..=1023u16 {
        let semantic = leaf(value);
        let round_trip = <Vmsa128 as AttributeCodec<
            NonSecureEl2Stage2<Stage2Permissions>,
            Granule4KiB,
            _,
        >>::encode_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            if raw.software.bits() != value {
                return Err(AttrError::RawFieldOutOfRange);
            }
            <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                Granule4KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        if round_trip != Ok(semantic) {
            failures += 1;
        }
    }
    if <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf(1024))
        != Err(AttrError::RawFieldOutOfRange)
    {
        failures += 1;
    }
    matrix_result(failures)
}

fn memory() -> MemoryAttributes {
    MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck)
}

fn stage1_leaf(
    value: u16,
) -> SemanticStage1LeafAttrs<Stage1EffectivePermissions, (), SemanticVmsa64Stage1LeafControls> {
    SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(value),
        },
    }
}

fn stage2_leaf(
    value: u16,
) -> SemanticStage2LeafAttrs<Stage2Permission, (), SemanticVmsa64Stage2LeafControls> {
    SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions: match DataAccess::ReadWrite {
            aarch64_vmsa::attrs::DataAccess::None => {
                aarch64_vmsa::attrs::Stage2Permission::NoAccess
            }
            aarch64_vmsa::attrs::DataAccess::ReadOnly => {
                aarch64_vmsa::attrs::Stage2Permission::ReadOnly {
                    privileged_execute: false,
                    unprivileged_execute: false,
                }
            }
            aarch64_vmsa::attrs::DataAccess::ReadWrite => {
                aarch64_vmsa::attrs::Stage2Permission::ReadWrite {
                    privileged_execute: false,
                    unprivileged_execute: false,
                }
            }
        },
        output_address_space: (),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            software: SoftwareMetadata::new(value),
        },
    }
}

fn matrix_result(failures: u64) -> TestResult {
    if failures == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0,
            actual: failures,
        })
    }
}
