use aarch64_vmsa::address::Level;
use aarch64_vmsa::attrs::{
    AttrError, AttributeCodec, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
    MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
    SinglePrivilegeTablePermissionLimits, SoftwareMetadata, Stage1EffectivePermissions,
    Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permission, TwoPrivilegeTablePermissionLimits,
};
use aarch64_vmsa::config::format::Vmsa64;
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::{NonSecureEl1Stage1, NonSecureEl2Stage1, NonSecureEl2Stage2};
use aarch64_vmsa::config::stage2::{Stage2Permissions, Stage2XnxPermissions};
use vmsa_test_harness::TestResult;

pub fn stage1_single_matrix() -> TestResult {
    use aarch64_vmsa::low_level::raw::{FourBit, TableAp};

    let config = config();
    let mut failures = 0;
    for data in [DataAccess::ReadOnly, DataAccess::ReadWrite] {
        for execute in [false, true] {
            let permissions = aarch64_vmsa::attrs::Stage1EffectivePermissions {
                privileged_data: data,
                unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
                privileged_execute: execute,
                unprivileged_execute: false,
                privileged_gcs: false,
                unprivileged_gcs: false,
            };
            let leaf = single_leaf(permissions);
            let result =
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
                    &config,
                    Level::L3,
                    leaf,
                )
                .and_then(|raw| {
                    <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                        &config,
                        Level::L3,
                        raw,
                    )
                });
            if result != Ok(leaf) {
                failures += 1;
            }
        }
    }
    if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        single_leaf(aarch64_vmsa::attrs::Stage1EffectivePermissions {
            privileged_data: DataAccess::None,
            unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        }),
    ) != Err(AttrError::UnencodablePermissions)
    {
        failures += 1;
    }
    let valid_leaf = single_leaf(aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadWrite,
        unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
        privileged_execute: true,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    });
    match <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        valid_leaf,
    ) {
        Ok(raw) => {
            for bits in [0, 2] {
                let mut invalid = raw;
                let primary = invalid.permissions.primary.bits();
                invalid.permissions.primary =
                    FourBit::new((primary & !1) | (bits & 1)).map_err(|_| {
                        vmsa_test_harness::HarnessError::CrateBehavior {
                            expected: 1,
                            actual: 0,
                        }
                    })?;
                invalid.permissions.dirty = bits & 2 != 0;
                if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                    &config,
                    Level::L3,
                    invalid,
                ) != Err(AttrError::InvalidLeafAp(bits))
                {
                    failures += 1;
                }
            }
            let mut invalid = raw;
            invalid.permissions.primary = FourBit::new(invalid.permissions.primary.bits() | 4)
                .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                })?;
            if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                &config,
                Level::L3,
                invalid,
            ) != Err(AttrError::UnencodablePermissions)
            {
                failures += 1;
            }
        }
        Err(_) => failures += 1,
    }
    for data_limit in [DataAccess::ReadOnly, DataAccess::ReadWrite] {
        for execute_limit in [false, true] {
            let limits = SinglePrivilegeTablePermissionLimits {
                data_limit,
                execute_limit,
            };
            let table = SemanticStage1TableAttrs {
                permission_limits: limits,
                pas: (),
                controls: SemanticVmsa64Stage1TableControls::default(),
            };
            let result =
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_table(
                    &config,
                    Level::L1,
                    table,
                )
                .and_then(|raw| {
                    <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_table(
                        &config,
                        Level::L1,
                        raw,
                    )
                });
            if result != Ok(table) {
                failures += 1;
            }
        }
    }
    let invalid_table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::None,
            execute_limit: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L1,
        invalid_table,
    ) != Err(AttrError::UnencodablePermissions)
    {
        failures += 1;
    }
    let valid_table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    match <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L1,
        valid_table,
    ) {
        Ok(raw) => {
            for bits in [1, 3] {
                let mut invalid = raw;
                invalid.ap_table = TableAp::from_bits(bits).map_err(|_| {
                    vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                })?;
                if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_table(
                    &config,
                    Level::L1,
                    invalid,
                ) != Err(AttrError::InvalidTableAp(bits))
                {
                    failures += 1;
                }
            }
            let mut invalid = raw;
            invalid.privileged_execute_never_limit = true;
            if <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_table(
                &config,
                Level::L1,
                invalid,
            ) != Err(AttrError::UnencodablePermissions)
            {
                failures += 1;
            }
        }
        Err(_) => failures += 1,
    }
    result(failures)
}

pub fn stage1_two_privilege_matrix() -> TestResult {
    let config = config();
    let valid_pairs = [
        (DataAccess::ReadWrite, DataAccess::None),
        (DataAccess::ReadWrite, DataAccess::ReadWrite),
        (DataAccess::ReadOnly, DataAccess::None),
        (DataAccess::ReadOnly, DataAccess::ReadOnly),
    ];
    let mut failures = 0;
    for (privileged_data, unprivileged_data) in valid_pairs {
        for privileged_execute in [false, true] {
            for unprivileged_execute in [false, true] {
                let permissions = Stage1EffectivePermissions {
                    privileged_data,
                    unprivileged_data,
                    privileged_execute,
                    unprivileged_execute,
                    privileged_gcs: false,
                    unprivileged_gcs: false,
                };
                let leaf = two_privilege_leaf(permissions);
                let round_trip =
                    <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::encode_leaf(
                        &config,
                        Level::L3,
                        leaf,
                    )
                    .and_then(|raw| {
                        <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        )
                    });
                if round_trip != Ok(leaf) {
                    failures += 1;
                }
            }
        }
    }
    for privileged_data in [
        DataAccess::None,
        DataAccess::ReadOnly,
        DataAccess::ReadWrite,
    ] {
        for unprivileged_data in [
            DataAccess::None,
            DataAccess::ReadOnly,
            DataAccess::ReadWrite,
        ] {
            if valid_pairs.contains(&(privileged_data, unprivileged_data)) {
                continue;
            }
            let invalid = two_privilege_leaf(Stage1EffectivePermissions {
                privileged_data,
                unprivileged_data,
                privileged_execute: false,
                unprivileged_execute: false,
                privileged_gcs: false,
                unprivileged_gcs: false,
            });
            if <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                invalid,
            ) != Err(AttrError::UnencodablePermissions)
            {
                failures += 1;
            }
        }
    }
    for (privileged_data_limit, unprivileged_data_limit) in valid_pairs {
        for privileged_execute_limit in [false, true] {
            for unprivileged_execute_limit in [false, true] {
                let table = SemanticStage1TableAttrs {
                    permission_limits: TwoPrivilegeTablePermissionLimits {
                        privileged_data_limit,
                        unprivileged_data_limit,
                        privileged_execute_limit,
                        unprivileged_execute_limit,
                    },
                    pas: (),
                    controls: SemanticVmsa64Stage1TableControls::default(),
                };
                let round_trip = <Vmsa64 as AttributeCodec<NonSecureEl1Stage1,
                    Granule4KiB,
                    _,
                >>::encode_table(&config, Level::L1, table)
                .and_then(|raw| {
                    <Vmsa64 as AttributeCodec<NonSecureEl1Stage1,
                        Granule4KiB,
                        _,
                    >>::decode_table(&config, Level::L1, raw)
                });
                if round_trip != Ok(table) {
                    failures += 1;
                }
            }
        }
    }
    for privileged_data_limit in [
        DataAccess::None,
        DataAccess::ReadOnly,
        DataAccess::ReadWrite,
    ] {
        for unprivileged_data_limit in [
            DataAccess::None,
            DataAccess::ReadOnly,
            DataAccess::ReadWrite,
        ] {
            if valid_pairs.contains(&(privileged_data_limit, unprivileged_data_limit)) {
                continue;
            }
            let invalid = SemanticStage1TableAttrs {
                permission_limits: TwoPrivilegeTablePermissionLimits {
                    privileged_data_limit,
                    unprivileged_data_limit,
                    privileged_execute_limit: false,
                    unprivileged_execute_limit: false,
                },
                pas: (),
                controls: SemanticVmsa64Stage1TableControls::default(),
            };
            if <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::encode_table(
                &config,
                Level::L1,
                invalid,
            ) != Err(AttrError::UnencodablePermissions)
            {
                failures += 1;
            }
        }
    }
    result(failures)
}

pub fn stage2_direct_matrix() -> TestResult {
    use aarch64_vmsa::low_level::raw::FourBit;

    let config = config();
    let mut failures = 0;
    for data in [
        DataAccess::None,
        DataAccess::ReadOnly,
        DataAccess::ReadWrite,
    ] {
        for (privileged_execute, unprivileged_execute) in [(false, false), (true, true)] {
            if !stage2_round_trip_direct(
                &config,
                Stage2Permission::direct(data, privileged_execute, unprivileged_execute),
            ) {
                failures += 1;
            }
        }
        if data != DataAccess::None {
            for (privileged_execute, unprivileged_execute) in [(false, true), (true, false)] {
                if stage2_resolve_direct(
                    &config,
                    Stage2Permission::direct(data, privileged_execute, unprivileged_execute),
                ) != Err(AttrError::InvalidStage2ExecuteNever)
                {
                    failures += 1;
                }
            }
        }
        for privileged_execute in [false, true] {
            for unprivileged_execute in [false, true] {
                if !stage2_round_trip_xnx(
                    &config,
                    Stage2Permission::direct(data, privileged_execute, unprivileged_execute),
                ) {
                    failures += 1;
                }
            }
        }
    }
    let valid = match DataAccess::ReadWrite {
        aarch64_vmsa::attrs::DataAccess::None => aarch64_vmsa::attrs::Stage2Permission::NoAccess,
        aarch64_vmsa::attrs::DataAccess::ReadOnly => {
            aarch64_vmsa::attrs::Stage2Permission::ReadOnly {
                privileged_execute: true,
                unprivileged_execute: true,
            }
        }
        aarch64_vmsa::attrs::DataAccess::ReadWrite => {
            aarch64_vmsa::attrs::Stage2Permission::ReadWrite {
                privileged_execute: true,
                unprivileged_execute: true,
            }
        }
    };
    match stage2_resolve_direct(&config, valid) {
        Ok(raw) => {
            let mut invalid_access = raw;
            let primary = invalid_access.permissions.primary.bits();
            invalid_access.permissions.primary = FourBit::new(primary & !1).map_err(|_| {
                vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
            })?;
            invalid_access.permissions.dirty = true;
            if <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                Granule4KiB,
                _,
            >>::decode_leaf(&config, Level::L3, invalid_access)
                != Err(AttrError::InvalidStage2Permission(2))
            {
                failures += 1;
            }
            for bits in [1, 3] {
                let mut invalid_execute = raw;
                invalid_execute.permissions.primary = FourBit::new(
                    (invalid_execute.permissions.primary.bits() & 0b0011) | (bits << 2),
                )
                .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                })?;
                if <Vmsa64 as AttributeCodec<
                    NonSecureEl2Stage2<Stage2Permissions>,
                    Granule4KiB,
                    _,
                >>::decode_leaf(&config, Level::L3, invalid_execute)
                    != Err(AttrError::InvalidStage2ExecuteNever)
                {
                    failures += 1;
                }
            }
        }
        Err(_) => failures += 1,
    }
    let table = SemanticVmsa64Stage2TableAttrs::default();
    for xnx in [false, true] {
        let round_trip = if xnx {
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2XnxPermissions>,
                Granule4KiB,
                _,
            >>::encode_table(&config, Level::L1, table)
            .and_then(|raw| {
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2XnxPermissions>,
                    Granule4KiB,
                    _,
                >>::decode_table(&config, Level::L1, raw)
            })
        } else {
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                Granule4KiB,
                _,
            >>::encode_table(&config, Level::L1, table)
            .and_then(|raw| {
                <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                    Granule4KiB,
                    _,
                >>::decode_table(&config, Level::L1, raw)
            })
        };
        if round_trip != Ok(table) {
            failures += 1;
        }
    }
    result(failures)
}

pub fn d128_stage2_base_matrix() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyState, MostlyReadOnly, SemanticVmsa128Stage2LeafControls, Stage2Permission,
        Stage2PermissionRegisters,
    };
    use aarch64_vmsa::config::format::Vmsa128;
    use aarch64_vmsa::low_level::raw::{FourBit, PermissionIndices};

    let mut config = config();
    config.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters {
                s2pir_el2: 0xfedc_ba98_7654_3210,
            },
        ),
        s2por_el1: None,
    };
    let expected = [
        Stage2Permission::NoAccess,
        Stage2Permission::NoAccess,
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::Unqualified),
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::TopLevel1),
        Stage2Permission::WriteOnly,
        Stage2Permission::NoAccess,
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::TopLevel0),
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::TopLevels0And1),
        Stage2Permission::ReadOnly {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: false,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: true,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: true,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: true,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: true,
            unprivileged_execute: true,
        },
    ];
    let controls = SemanticVmsa128Stage2LeafControls {
        bbm_nt: false,
        dirty_state: DirtyState::Clean,
        shareability: Shareability::InnerShareable,
        access_flag: true,
        force_no_execute: false,
        contiguous: false,
        assured_only: false,
        software: SoftwareMetadata::new(0),
    };
    let leaf = |permissions| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions,
        output_address_space: (),
        controls,
    };
    let mut failures = 0;
    let base_raw = <Vmsa128 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf(Stage2Permission::NoAccess));
    match base_raw {
        Ok(raw) => {
            for (index, expected_permission) in expected.into_iter().enumerate() {
                let mut indexed = raw;
                indexed.permissions = PermissionIndices {
                    pi: FourBit::new(index as u8).map_err(|_| {
                        vmsa_test_harness::HarnessError::CrateBehavior {
                            expected: 1,
                            actual: 0,
                        }
                    })?,
                    po: FourBit::ZERO,
                };
                let decoded = <Vmsa128 as AttributeCodec<
                    NonSecureEl2Stage2<Stage2Permissions>,
                    Granule4KiB,
                    _,
                >>::decode_leaf(&config, Level::L3, indexed);
                if !matches!(decoded, Ok(value) if value.permissions == expected_permission) {
                    failures += 1;
                }
            }
        }
        Err(_) => failures += 16,
    }
    for permission in [
        expected[0],
        expected[2],
        expected[3],
        expected[4],
        expected[6],
        expected[7],
        expected[8],
        expected[9],
        expected[10],
        expected[11],
        expected[12],
        expected[13],
        expected[14],
        expected[15],
    ] {
        let semantic = leaf(permission);
        let round_trip = <Vmsa128 as AttributeCodec<
            NonSecureEl2Stage2<Stage2Permissions>,
            Granule4KiB,
            _,
        >>::encode_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                Granule4KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        if round_trip != Ok(semantic) {
            failures += 1;
        }
    }
    let mut unavailable = config;
    unavailable.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings::direct();
    if <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&unavailable, Level::L3, leaf(Stage2Permission::NoAccess))
        != Err(AttrError::PermissionIndirectionUnavailable)
    {
        failures += 1;
    }
    config.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters { s2pir_el2: 0 },
        ),
        s2por_el1: None,
    };
    if <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf(Stage2Permission::WriteOnly))
        != Err(AttrError::PermissionCombinationNotConfigured)
    {
        failures += 1;
    }
    result(failures)
}

pub fn d128_stage2_overlay_matrix() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage2LeafControls, Stage2Permission, Stage2PermissionRegisters,
    };
    use aarch64_vmsa::config::format::Vmsa128;
    use aarch64_vmsa::low_level::raw::{FourBit, PermissionIndices};

    const IDENTITY_REGISTER: u64 = 0xfedc_ba98_7654_3210;
    let entries = [
        Stage2Permission::NoAccess,
        Stage2Permission::NoAccess,
        Stage2Permission::MostlyReadOnly(aarch64_vmsa::attrs::MostlyReadOnly::Unqualified),
        Stage2Permission::MostlyReadOnly(aarch64_vmsa::attrs::MostlyReadOnly::TopLevel1),
        Stage2Permission::WriteOnly,
        Stage2Permission::NoAccess,
        Stage2Permission::MostlyReadOnly(aarch64_vmsa::attrs::MostlyReadOnly::TopLevel0),
        Stage2Permission::MostlyReadOnly(aarch64_vmsa::attrs::MostlyReadOnly::TopLevels0And1),
        Stage2Permission::ReadOnly {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: false,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: true,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadOnly {
            privileged_execute: true,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: true,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: true,
            unprivileged_execute: false,
        },
        Stage2Permission::ReadWrite {
            privileged_execute: true,
            unprivileged_execute: true,
        },
    ];
    let mut config = config();
    config.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters {
                s2pir_el2: IDENTITY_REGISTER,
            },
        ),
        s2por_el1: Some(IDENTITY_REGISTER),
    };
    let leaf = |permissions| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions,
        output_address_space: (),
        controls: SemanticVmsa128Stage2LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let mut failures = 0;
    let template = <Vmsa128 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf(Stage2Permission::NoAccess));
    match template {
        Ok(template) => {
            for pi in 0..16 {
                for po in 0..16 {
                    let mut raw = template;
                    raw.permissions = PermissionIndices {
                        pi: FourBit::new(pi).map_err(|_| {
                            vmsa_test_harness::HarnessError::CrateBehavior {
                                expected: 1,
                                actual: 0,
                            }
                        })?,
                        po: FourBit::new(po).map_err(|_| {
                            vmsa_test_harness::HarnessError::CrateBehavior {
                                expected: 1,
                                actual: 0,
                            }
                        })?,
                    };
                    let decoded = <Vmsa128 as AttributeCodec<
                        NonSecureEl2Stage2<Stage2Permissions>,
                        Granule4KiB,
                        _,
                    >>::decode_leaf(&config, Level::L3, raw);
                    let expected = stage2_expected(entries[pi as usize], entries[po as usize]);
                    if !matches!(decoded, Ok(value) if value.permissions == expected) {
                        failures += 1;
                    }
                }
            }
        }
        Err(_) => failures += 256,
    }

    // With no overlay register, PO is architecturally ignored for every base entry.
    config.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters {
                s2pir_el2: IDENTITY_REGISTER,
            },
        ),
        s2por_el1: None,
    };
    let template = <Vmsa128 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf(Stage2Permission::NoAccess));
    match template {
        Ok(template) => {
            for pi in 0..16 {
                for po in 0..16 {
                    let mut raw = template;
                    raw.permissions = PermissionIndices {
                        pi: FourBit::new(pi).map_err(|_| {
                            vmsa_test_harness::HarnessError::CrateBehavior {
                                expected: 1,
                                actual: 0,
                            }
                        })?,
                        po: FourBit::new(po).map_err(|_| {
                            vmsa_test_harness::HarnessError::CrateBehavior {
                                expected: 1,
                                actual: 0,
                            }
                        })?,
                    };
                    let decoded = <Vmsa128 as AttributeCodec<
                        NonSecureEl2Stage2<Stage2Permissions>,
                        Granule4KiB,
                        _,
                    >>::decode_leaf(&config, Level::L3, raw);
                    if !matches!(decoded, Ok(value) if value.permissions == entries[pi as usize]) {
                        failures += 1;
                    }
                }
            }
        }
        Err(_) => failures += 256,
    }
    result(failures)
}

fn stage2_expected(
    base: aarch64_vmsa::attrs::Stage2Permission,
    overlay: aarch64_vmsa::attrs::Stage2Permission,
) -> aarch64_vmsa::attrs::Stage2Permission {
    use Stage2Permission::{MostlyReadOnly as Mro, *};
    use aarch64_vmsa::attrs::{MostlyReadOnly, Stage2Permission};
    match (base, overlay) {
        (Mro(a), Mro(b)) => {
            let mask = |value| match value {
                MostlyReadOnly::Unqualified => 0,
                MostlyReadOnly::TopLevel0 => 1,
                MostlyReadOnly::TopLevel1 => 2,
                MostlyReadOnly::TopLevels0And1 => 3,
            };
            Mro(match mask(a) | mask(b) {
                0 => MostlyReadOnly::Unqualified,
                1 => MostlyReadOnly::TopLevel0,
                2 => MostlyReadOnly::TopLevel1,
                _ => MostlyReadOnly::TopLevels0And1,
            })
        }
        (WriteOnly, WriteOnly) => WriteOnly,
        (WriteOnly, Mro(_)) | (Mro(_), WriteOnly) => NoAccess,
        (Mro(value), general) | (general, Mro(value)) => match general {
            NoAccess => NoAccess,
            ReadOnly { .. } => ReadOnly {
                privileged_execute: false,
                unprivileged_execute: false,
            },
            ReadWrite { .. } => Mro(value),
            _ => NoAccess,
        },
        (WriteOnly, general) | (general, WriteOnly) => match general {
            ReadWrite { .. } => WriteOnly,
            _ => NoAccess,
        },
        (a, b) => {
            let encode = |value| match value {
                NoAccess => 0,
                ReadOnly {
                    privileged_execute,
                    unprivileged_execute,
                } => 8 | (privileged_execute as u8) << 1 | unprivileged_execute as u8,
                ReadWrite {
                    privileged_execute,
                    unprivileged_execute,
                } => 12 | (privileged_execute as u8) << 1 | unprivileged_execute as u8,
                _ => 0,
            };
            match encode(a) & encode(b) {
                0..=7 => NoAccess,
                bits @ 8..=11 => ReadOnly {
                    privileged_execute: bits & 2 != 0,
                    unprivileged_execute: bits & 1 != 0,
                },
                bits => ReadWrite {
                    privileged_execute: bits & 2 != 0,
                    unprivileged_execute: bits & 1 != 0,
                },
            }
        }
    }
}

pub fn d128_stage1_indirection_matrix() -> TestResult {
    use aarch64_vmsa::attrs::{
        Stage1BasePermissions, Stage1PermissionOverlays, Stage1PermissionRegisters,
        Stage1PermissionSettings,
    };

    const IDENTITY_REGISTER: u64 = 0xfedc_ba98_7654_3210;
    let mut failures = 0;
    for gcs_implemented in [false, true] {
        for privileged_overlay in [false, true] {
            for unprivileged_overlay in [None, Some(false), Some(true)] {
                let mut config = config();
                config.stage1_permissions = Stage1PermissionSettings {
                    base: Stage1BasePermissions::Indirect(Stage1PermissionRegisters {
                        privileged: IDENTITY_REGISTER,
                        unprivileged: unprivileged_overlay.map(|_| IDENTITY_REGISTER),
                        gcs_implemented,
                    }),
                    overlays: Stage1PermissionOverlays {
                        privileged: privileged_overlay.then_some(IDENTITY_REGISTER),
                        unprivileged: unprivileged_overlay
                            .and_then(|enabled| enabled.then_some(IDENTITY_REGISTER)),
                    },
                };
                failures += stage1_decode_failures(
                    &config,
                    privileged_overlay,
                    unprivileged_overlay,
                    gcs_implemented,
                )
                .unwrap_or(256);
            }
        }
    }
    result(failures)
}

fn d128_stage1_permissions(data: DataAccess) -> aarch64_vmsa::attrs::Stage1EffectivePermissions {
    aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: data,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    }
}

fn d128_stage1_leaf(
    permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions,
) -> SemanticStage1LeafAttrs<
    aarch64_vmsa::attrs::Stage1EffectivePermissions,
    (),
    aarch64_vmsa::attrs::SemanticVmsa128Stage1LeafControls,
> {
    use aarch64_vmsa::attrs::{DirtyState, SemanticVmsa128Stage1LeafControls};
    SemanticStage1LeafAttrs {
        memory: memory(),
        permissions,
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
            software: SoftwareMetadata::new(0),
        },
    }
}

fn d128_stage1_resolve(
    config: &LiveVmsaConfig,
    permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs, AttrError> {
    <aarch64_vmsa::config::format::Vmsa128 as AttributeCodec<NonSecureEl2Stage1,
        Granule4KiB,
        _,
    >>::encode_leaf(config, Level::L3, d128_stage1_leaf(permissions))
}

pub fn d128_stage1_indirection_unavailable() -> TestResult {
    result(
        (d128_stage1_resolve(&config(), d128_stage1_permissions(DataAccess::None))
            != Err(AttrError::PermissionIndirectionUnavailable)) as u64,
    )
}

pub fn d128_stage1_missing_combination() -> TestResult {
    use aarch64_vmsa::attrs::Stage1PermissionRegisters;
    let mut config = config();
    config.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0,
                unprivileged: None,
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    result(
        (d128_stage1_resolve(&config, d128_stage1_permissions(DataAccess::ReadWrite))
            != Err(AttrError::PermissionCombinationNotConfigured)) as u64,
    )
}

pub fn d128_stage1_duplicate_selection() -> TestResult {
    use aarch64_vmsa::attrs::Stage1PermissionRegisters;
    use aarch64_vmsa::low_level::raw::{FourBit, PermissionIndices};
    let mut config = config();
    config.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0x1111_1111_1111_1111,
                unprivileged: None,
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let selected = d128_stage1_resolve(&config, d128_stage1_permissions(DataAccess::ReadOnly))
        .map(|raw| raw.permissions);
    result(
        (selected
            != Ok(PermissionIndices {
                pi: FourBit::ZERO,
                po: FourBit::ZERO,
            })) as u64,
    )
}

pub fn d128_stage1_conflicting_permissions() -> TestResult {
    use aarch64_vmsa::attrs::Stage1PermissionRegisters;
    use aarch64_vmsa::config::format::Vmsa128;
    let no_access = aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: DataAccess::None,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let mut template_config = config();
    template_config.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0,
                unprivileged: None,
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let template = d128_stage1_resolve(&template_config, no_access);
    let mut conflicting = config();
    conflicting.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0xeeee_eeee_eeee_eeee,
                unprivileged: Some(0xeeee_eeee_eeee_eeee),
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let decoded = template.and_then(|raw| {
        <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
            &conflicting,
            Level::L3,
            raw,
        )
    });
    result((decoded != Err(AttrError::UnencodablePermissions)) as u64)
}

fn d128_stage2_leaf(
    permissions: aarch64_vmsa::attrs::Stage2Permission,
) -> SemanticStage2LeafAttrs<
    aarch64_vmsa::attrs::Stage2Permission,
    (),
    aarch64_vmsa::attrs::SemanticVmsa128Stage2LeafControls,
> {
    use aarch64_vmsa::attrs::{DirtyState, SemanticVmsa128Stage2LeafControls};
    SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions,
        output_address_space: (),
        controls: SemanticVmsa128Stage2LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn d128_stage2_resolve(
    config: &LiveVmsaConfig,
    permissions: aarch64_vmsa::attrs::Stage2Permission,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa128Stage2LeafAttrs, AttrError> {
    <aarch64_vmsa::config::format::Vmsa128 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(config, Level::L3, d128_stage2_leaf(permissions))
}

pub fn d128_stage2_indirection_unavailable() -> TestResult {
    result(
        (d128_stage2_resolve(&config(), aarch64_vmsa::attrs::Stage2Permission::NoAccess)
            != Err(AttrError::PermissionIndirectionUnavailable)) as u64,
    )
}

pub fn d128_stage2_missing_combination() -> TestResult {
    use aarch64_vmsa::attrs::{Stage2Permission, Stage2PermissionRegisters};
    let mut missing = config();
    missing.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters { s2pir_el2: 0 },
        ),
        s2por_el1: None,
    };
    result(
        (d128_stage2_resolve(&missing, Stage2Permission::WriteOnly)
            != Err(AttrError::PermissionCombinationNotConfigured)) as u64,
    )
}

pub fn d128_stage2_duplicate_selection() -> TestResult {
    use aarch64_vmsa::attrs::{Stage2Permission, Stage2PermissionRegisters};
    use aarch64_vmsa::low_level::raw::{FourBit, PermissionIndices};
    let mut duplicate = config();
    duplicate.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters {
                s2pir_el2: 0x8888_8888_8888_8888,
            },
        ),
        s2por_el1: Some(0x8888_8888_8888_8888),
    };
    let wanted = Stage2Permission::ReadOnly {
        privileged_execute: false,
        unprivileged_execute: false,
    };
    let selected = d128_stage2_resolve(&duplicate, wanted).map(|raw| raw.permissions);
    result(
        (selected
            != Ok(PermissionIndices {
                pi: FourBit::ZERO,
                po: FourBit::ZERO,
            })) as u64,
    )
}

pub fn invalid_fixed_output_address_space() -> TestResult {
    use aarch64_vmsa::attrs::{Stage2Permission, Stage2PermissionRegisters};
    use aarch64_vmsa::config::format::Vmsa128;
    let mut config = config();
    config.stage2_permissions = aarch64_vmsa::attrs::Stage2PermissionSettings {
        base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage2PermissionRegisters { s2pir_el2: 0 },
        ),
        s2por_el1: None,
    };
    let raw = d128_stage2_resolve(&config, Stage2Permission::NoAccess).map(|mut raw| {
        raw.ns = true;
        raw
    });
    let decoded = raw.and_then(|raw| {
        <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, Level::L3, raw)
    });
    result((decoded != Err(AttrError::InvalidOutputAddressSpace)) as u64)
}

pub fn invalid_d128_alias() -> TestResult {
    use aarch64_vmsa::attrs::Stage1PermissionRegisters;
    use aarch64_vmsa::config::format::Vmsa128;
    let mut config = config();
    config.d128_stage1_alias = D128Stage1AliasKind::NonSecureExtension;
    config.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0,
                unprivileged: None,
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let resolved = <Vmsa128 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        d128_stage1_leaf(d128_stage1_permissions(DataAccess::None)),
    );
    result((resolved != Err(AttrError::InvalidD128Alias)) as u64)
}

pub fn invalid_d128_final_level_nt() -> TestResult {
    use aarch64_vmsa::attrs::Stage1PermissionRegisters;
    let mut config = config();
    config.stage1_permissions = aarch64_vmsa::attrs::Stage1PermissionSettings {
        base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
            aarch64_vmsa::attrs::Stage1PermissionRegisters {
                privileged: 0,
                unprivileged: None,
                gcs_implemented: false,
            },
        ),
        overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let mut leaf = d128_stage1_leaf(d128_stage1_permissions(DataAccess::None));
    leaf.controls.bbm_nt = true;
    let resolved = <aarch64_vmsa::config::format::Vmsa128 as AttributeCodec<
        NonSecureEl2Stage1,
        Granule4KiB,
        _,
    >>::encode_leaf(&config, Level::L3, leaf);
    result((resolved != Err(AttrError::InvalidD128Configuration)) as u64)
}

pub fn conflicting_stage1_semantics() -> TestResult {
    let config = config();
    let mut leaf = single_leaf(aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadOnly,
        unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    });
    leaf.controls.global = false;
    let resolved = <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    );
    result((resolved != Err(AttrError::ConflictingSemanticAttributes)) as u64)
}

fn stage1_decode_failures(
    config: &LiveVmsaConfig,
    privileged_overlay: bool,
    unprivileged_overlay: Option<bool>,
    gcs_implemented: bool,
) -> Result<u64, AttrError> {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage1LeafControls, Stage1EffectivePermissions,
    };
    use aarch64_vmsa::config::format::Vmsa128;
    use aarch64_vmsa::low_level::raw::{FourBit, PermissionIndices};

    let template_permissions = Stage1EffectivePermissions {
        privileged_data: DataAccess::None,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: template_permissions,
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
            software: SoftwareMetadata::new(0),
        },
    };
    let template = <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        config,
        Level::L3,
        leaf,
    )?;
    let mut failures = 0;
    for pi in 0..16 {
        for po in 0..16 {
            let mut raw = template;
            raw.permissions = PermissionIndices {
                pi: FourBit::new(pi)?,
                po: FourBit::new(po)?,
            };
            let decoded =
                <Vmsa128 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                    config,
                    Level::L3,
                    raw,
                )
                .map(|value| value.permissions);
            let expected = stage1_expected(
                pi,
                privileged_overlay.then_some(po),
                unprivileged_overlay.map(|has_overlay| has_overlay.then_some(po)),
                gcs_implemented,
            );
            if decoded != expected {
                failures += 1;
            }
        }
    }
    Ok(failures)
}

#[derive(Clone, Copy)]
struct Stage1Bits {
    read: bool,
    write: bool,
    execute: bool,
    gcs: bool,
    apply_overlay: bool,
    wxn: bool,
}

fn stage1_expected(
    pi: u8,
    privileged_po: Option<u8>,
    unprivileged_po: Option<Option<u8>>,
    gcs_implemented: bool,
) -> Result<aarch64_vmsa::attrs::Stage1EffectivePermissions, AttrError> {
    let decode_pair = |po: Option<u8>| {
        let mut bits = match pi {
            0 | 4 => Stage1Bits::new(false, false, false, false, true, false),
            1 => Stage1Bits::new(true, false, false, false, true, false),
            2 => Stage1Bits::new(false, false, true, false, true, false),
            3 => Stage1Bits::new(true, false, true, false, true, false),
            5 => Stage1Bits::new(true, true, false, false, true, false),
            6 => Stage1Bits::new(true, true, true, false, true, true),
            7 => Stage1Bits::new(true, true, true, false, true, false),
            8 => Stage1Bits::new(true, false, false, false, false, false),
            9 if gcs_implemented => Stage1Bits::new(true, false, false, true, false, false),
            10 => Stage1Bits::new(true, false, true, false, false, false),
            12 => Stage1Bits::new(true, true, false, false, false, false),
            14 => Stage1Bits::new(true, true, true, false, false, false),
            _ => Stage1Bits::new(false, false, false, false, false, false),
        };
        if let Some(po) = po.filter(|_| bits.apply_overlay) {
            let (read, mut write, execute) = match po {
                0 | 8..=15 => (false, false, false),
                1 => (true, false, false),
                2 => (false, false, true),
                3 => (true, false, true),
                4 => (false, true, false),
                5 => (true, true, false),
                6 => (false, true, true),
                _ => (true, true, true),
            };
            if bits.wxn && execute {
                write = false;
            }
            bits.read &= read;
            bits.write &= write;
            bits.execute &= execute;
        }
        bits
    };
    let privileged = decode_pair(privileged_po);
    let unprivileged = unprivileged_po
        .map(decode_pair)
        .unwrap_or(Stage1Bits::new(false, false, false, false, false, false));
    if (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs) {
        return Err(AttrError::UnencodablePermissions);
    }
    let data_access = |bits: Stage1Bits| match (bits.read, bits.write) {
        (false, false) => Ok(DataAccess::None),
        (true, false) => Ok(DataAccess::ReadOnly),
        (true, true) => Ok(DataAccess::ReadWrite),
        (false, true) => Err(AttrError::UnencodablePermissions),
    };
    Ok(aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: data_access(privileged)?,
        unprivileged_data: data_access(unprivileged)?,
        privileged_execute: privileged.execute,
        unprivileged_execute: unprivileged.execute,
        privileged_gcs: privileged.gcs,
        unprivileged_gcs: unprivileged.gcs,
    })
}

impl Stage1Bits {
    const fn new(
        read: bool,
        write: bool,
        execute: bool,
        gcs: bool,
        apply_overlay: bool,
        wxn: bool,
    ) -> Self {
        Self {
            read,
            write,
            execute,
            gcs,
            apply_overlay,
            wxn,
        }
    }
}

pub fn vmsa64_aie_round_trip() -> TestResult {
    let mut config = config();
    config.mair2 = Some(0x44);
    let mut leaf = single_leaf(Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadOnly,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    });
    leaf.memory = MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    };
    let round_trip = <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    )
    .and_then(|raw| {
        if raw.attr_index.bits() != 8 {
            return Err(AttrError::RawFieldOutOfRange);
        }
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    });
    result((round_trip != Ok(leaf)) as u64)
}

pub fn vmsa64_stage1_permission_extensions() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyControl, DirtyState, Stage1BasePermissions, Stage1PermissionOverlays,
        Stage1PermissionRegisters, Stage1PermissionSettings,
    };

    let read_only = Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadOnly,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let mut stage1 = config();
    stage1.stage1_permissions = Stage1PermissionSettings {
        base: Stage1BasePermissions::Indirect(Stage1PermissionRegisters {
            privileged: 0x8888_8888_8888_8888,
            unprivileged: None,
            gcs_implemented: false,
        }),
        overlays: Stage1PermissionOverlays::default(),
    };
    let mut stage1_leaf = single_leaf(read_only);
    stage1_leaf.controls.dirty = DirtyControl::Indirect(DirtyState::Clean);
    let stage1_ok = <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &stage1,
        Level::L3,
        stage1_leaf,
    )
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
            &stage1,
            Level::L3,
            raw,
        )
    }) == Ok(stage1_leaf);

    let mut stage1_direct_overlay = config();
    stage1_direct_overlay.stage1_permissions = Stage1PermissionSettings {
        base: Stage1BasePermissions::Direct,
        overlays: Stage1PermissionOverlays {
            privileged: Some(0x1111_1111_1111_1111),
            unprivileged: None,
        },
    };
    let stage1_direct_overlay_leaf = single_leaf(read_only);
    let stage1_direct_overlay_ok =
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
            &stage1_direct_overlay,
            Level::L3,
            stage1_direct_overlay_leaf,
        )
        .and_then(|raw| {
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
                &stage1_direct_overlay,
                Level::L3,
                raw,
            )
        }) == Ok(stage1_direct_overlay_leaf);

    let both_read_only = Stage1EffectivePermissions {
        unprivileged_data: DataAccess::ReadOnly,
        ..read_only
    };
    stage1.stage1_permissions = Stage1PermissionSettings {
        base: Stage1BasePermissions::Indirect(Stage1PermissionRegisters {
            privileged: 0x1111_1111_1111_1111,
            unprivileged: Some(0x1111_1111_1111_1111),
            gcs_implemented: false,
        }),
        overlays: Stage1PermissionOverlays {
            privileged: Some(0x1111_1111_1111_1111),
            unprivileged: Some(0x1111_1111_1111_1111),
        },
    };
    let mut stage1_overlay_leaf = two_privilege_leaf(both_read_only);
    stage1_overlay_leaf.controls.dirty = DirtyControl::Indirect(DirtyState::Dirty);
    let stage1_overlay_ok =
        <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::encode_leaf(
            &stage1,
            Level::L3,
            stage1_overlay_leaf,
        )
        .and_then(|raw| {
            <Vmsa64 as AttributeCodec<NonSecureEl1Stage1, Granule4KiB, _>>::decode_leaf(
                &stage1,
                Level::L3,
                raw,
            )
        }) == Ok(stage1_overlay_leaf);

    result((!stage1_ok) as u64 + (!stage1_direct_overlay_ok) as u64 + (!stage1_overlay_ok) as u64)
}

pub fn vmsa64_stage2_permission_extensions() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyControl, DirtyState, Stage2BasePermissions, Stage2PermissionRegisters,
        Stage2PermissionSettings,
    };

    let wanted_stage2 = Stage2Permission::ReadOnly {
        privileged_execute: false,
        unprivileged_execute: false,
    };
    let mut stage2_indirect = config();
    stage2_indirect.stage2_permissions = Stage2PermissionSettings {
        base: Stage2BasePermissions::Indirect(Stage2PermissionRegisters {
            s2pir_el2: 0x8888_8888_8888_8888,
        }),
        s2por_el1: None,
    };
    let mut stage2_indirect_leaf = stage2_leaf(wanted_stage2);
    stage2_indirect_leaf.controls.dirty = DirtyControl::Indirect(DirtyState::Clean);
    let stage2_indirect_ok = <Vmsa64 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&stage2_indirect, Level::L3, stage2_indirect_leaf)
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>, Granule4KiB, _>>::decode_leaf(
            &stage2_indirect,
            Level::L3,
            raw,
        )
    }) == Ok(stage2_indirect_leaf);

    let mut stage2_direct_overlay = config();
    stage2_direct_overlay.stage2_permissions = Stage2PermissionSettings {
        base: Stage2BasePermissions::Direct,
        s2por_el1: Some(0x8888_8888_8888_8888),
    };
    let stage2_direct_overlay_leaf = stage2_leaf(wanted_stage2);
    let stage2_direct_overlay_ok = <Vmsa64 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(
        &stage2_direct_overlay,
        Level::L3,
        stage2_direct_overlay_leaf,
    )
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>, Granule4KiB, _>>::decode_leaf(
            &stage2_direct_overlay,
            Level::L3,
            raw,
        )
    }) == Ok(stage2_direct_overlay_leaf);

    let mut stage2 = config();
    stage2.stage2_permissions = Stage2PermissionSettings {
        base: Stage2BasePermissions::Indirect(Stage2PermissionRegisters {
            s2pir_el2: 0x8888_8888_8888_8888,
        }),
        s2por_el1: Some(0x8888_8888_8888_8888),
    };
    let mut stage2_leaf = stage2_leaf(wanted_stage2);
    stage2_leaf.controls.dirty = DirtyControl::Indirect(DirtyState::Dirty);
    let stage2_ok = <Vmsa64 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(&stage2, Level::L3, stage2_leaf)
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>, Granule4KiB, _>>::decode_leaf(
            &stage2,
            Level::L3,
            raw,
        )
    }) == Ok(stage2_leaf);

    result((!stage2_indirect_ok) as u64 + (!stage2_direct_overlay_ok) as u64 + (!stage2_ok) as u64)
}

pub fn vmsa64_stage1_haft_round_trip() -> TestResult {
    let config = config();
    let stage1 = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls {
            access_flag: true,
            software: SoftwareMetadata::new(0),
        },
    };
    let stage1_ok = <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L1,
        stage1,
    )
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1, Granule4KiB, _>>::decode_table(
            &config,
            Level::L1,
            raw,
        )
    }) == Ok(stage1);
    result((!stage1_ok) as u64)
}

pub fn vmsa64_stage2_haft_round_trip() -> TestResult {
    let config = config();
    let stage2 = SemanticVmsa64Stage2TableAttrs {
        access_flag: true,
        software: SoftwareMetadata::new(0),
    };
    let stage2_ok = <Vmsa64 as AttributeCodec<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::encode_table(&config, Level::L1, stage2)
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>, Granule4KiB, _>>::decode_table(
            &config,
            Level::L1,
            raw,
        )
    }) == Ok(stage2);
    result((!stage2_ok) as u64)
}

fn config() -> LiveVmsaConfig {
    LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    }
}

fn memory() -> MemoryAttributes {
    MemoryAttributes::Device(
        aarch64_vmsa::attrs::DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
    )
}

fn stage1_controls() -> SemanticVmsa64Stage1LeafControls {
    SemanticVmsa64Stage1LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        global: true,
        dirty: aarch64_vmsa::attrs::DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
        contiguous: false,
        guarded: false,
        software: SoftwareMetadata::new(0),
    }
}

fn single_leaf(
    permissions: Stage1EffectivePermissions,
) -> SemanticStage1LeafAttrs<Stage1EffectivePermissions, (), SemanticVmsa64Stage1LeafControls> {
    SemanticStage1LeafAttrs {
        memory: memory(),
        permissions,
        pas: (),
        controls: stage1_controls(),
    }
}

fn two_privilege_leaf(
    permissions: Stage1EffectivePermissions,
) -> SemanticStage1LeafAttrs<Stage1EffectivePermissions, (), SemanticVmsa64Stage1LeafControls> {
    SemanticStage1LeafAttrs {
        memory: memory(),
        permissions,
        pas: (),
        controls: stage1_controls(),
    }
}

fn stage2_leaf(
    permissions: Stage2Permission,
) -> SemanticStage2LeafAttrs<Stage2Permission, (), SemanticVmsa64Stage2LeafControls> {
    SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions,
        output_address_space: (),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn stage2_resolve_direct(
    config: &LiveVmsaConfig,
    permissions: Stage2Permission,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa64Stage2LeafAttrs, AttrError> {
    <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>, Granule4KiB, _>>::encode_leaf(
        config,
        Level::L3,
        stage2_leaf(permissions),
    )
}

fn stage2_resolve_xnx(
    config: &LiveVmsaConfig,
    permissions: Stage2Permission,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa64Stage2LeafAttrs, AttrError> {
    <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2XnxPermissions>,
        Granule4KiB,
        _,
    >>::encode_leaf(config, Level::L3, stage2_leaf(permissions))
}

fn stage2_round_trip_direct(config: &LiveVmsaConfig, permissions: Stage2Permission) -> bool {
    let leaf = stage2_leaf(permissions);
    stage2_resolve_direct(config, permissions)
        .and_then(|raw| {
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
                Granule4KiB,
                _,
            >>::decode_leaf(config, Level::L3, raw)
        })
        .is_ok_and(|decoded| decoded == leaf)
}

fn stage2_round_trip_xnx(config: &LiveVmsaConfig, permissions: Stage2Permission) -> bool {
    let leaf = stage2_leaf(permissions);
    stage2_resolve_xnx(config, permissions)
        .and_then(|raw| {
            <Vmsa64 as AttributeCodec<NonSecureEl2Stage2<Stage2XnxPermissions>,
                Granule4KiB,
                _,
            >>::decode_leaf(config, Level::L3, raw)
        })
        .is_ok_and(|decoded| decoded == leaf)
}

fn result(failures: u64) -> TestResult {
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
