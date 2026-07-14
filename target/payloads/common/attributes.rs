use aarch64_vmsa::address::{Granule4KiB, Level};
use aarch64_vmsa::attrs::{
    AllocationHints, AttrError, AttributeCodec, CachePolicy, Cacheability, D128Stage1AliasKind,
    DataAccess, DeviceMemoryType, DirtyBitManagement, FwbStage2Memory, LiveVmsaConfig,
    MemoryAttributes, MemoryTransience, SemanticStage1LeafAttrs, SemanticStage2LeafAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage2LeafControls, Shareability,
    SinglePrivilegeLeafPermissions, SoftwareMetadata, Stage2LeafPermissions,
    Stage2MemoryAttributes, Stage2MemoryMode, VmsaAttributeCodec,
};
use aarch64_vmsa::descriptor::Vmsa64;
use aarch64_vmsa::regime::{NonSecureEl2Stage1, NonSecureEl2Stage2};
use vmsa_test_harness::TestResult;

const DEVICES: [DeviceMemoryType; 4] = [
    DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
    DeviceMemoryType::NonGatheringNonReorderingEarlyAck,
    DeviceMemoryType::NonGatheringReorderingEarlyAck,
    DeviceMemoryType::GatheringReorderingEarlyAck,
];

pub fn mair_device_matrix() -> TestResult {
    let mut failures = 0;
    for (encoding, device) in DEVICES.into_iter().enumerate() {
        let memory = MemoryAttributes::Device(device);
        let config = base_config((encoding as u64) << 2, Stage2MemoryMode::FwbDisabled);
        if !matches!(stage1_round_trip(&config, memory), Ok((0, decoded)) if decoded == memory) {
            failures += 1;
        }
    }
    matrix_result(failures)
}

pub fn mair_normal_matrix() -> TestResult {
    let cacheabilities = all_mair_cacheabilities();
    let mut failures = 0;
    for inner in cacheabilities {
        for outer in cacheabilities {
            let memory = MemoryAttributes::Normal { inner, outer };
            let mair = u64::from(mair_cache(inner) | (mair_cache(outer) << 4));
            let config = base_config(mair, Stage2MemoryMode::FwbDisabled);
            if !matches!(stage1_round_trip(&config, memory), Ok((0, decoded)) if decoded == memory)
            {
                failures += 1;
            }
        }
    }
    matrix_result(failures)
}

pub fn mair_error_matrix() -> TestResult {
    use aarch64_vmsa::low_level::raw::ThreeBit;

    let mut failures = 0;
    for policy in [CachePolicy::WriteThrough, CachePolicy::WriteBack] {
        let invalid = Cacheability::Cacheable {
            policy,
            transience: MemoryTransience::Transient,
            allocation: AllocationHints::None,
        };
        let config = base_config(0, Stage2MemoryMode::FwbDisabled);
        if resolve_stage1(
            &config,
            MemoryAttributes::Normal {
                inner: invalid,
                outer: Cacheability::NonCacheable,
            },
        ) != Err(AttrError::UnencodableMemoryAttribute)
        {
            failures += 1;
        }
    }

    let missing = base_config(0, Stage2MemoryMode::FwbDisabled);
    if resolve_stage1(
        &missing,
        MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
    ) != Err(AttrError::MemoryAttributeNotConfigured)
    {
        failures += 1;
    }

    let duplicate = base_config(0x4444, Stage2MemoryMode::FwbDisabled);
    if !matches!(
        resolve_stage1(
            &duplicate,
            MemoryAttributes::Normal {
                inner: Cacheability::NonCacheable,
                outer: Cacheability::NonCacheable,
            },
        ),
        Ok(raw) if raw.attr_index.bits() == 0
    ) {
        failures += 1;
    }

    let invalid_entry = base_config(0x0100, Stage2MemoryMode::FwbDisabled);
    match resolve_stage1(
        &invalid_entry,
        MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
    ) {
        Ok(mut raw) => {
            raw.attr_index =
                ThreeBit::new(1).map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
            if decode_stage1(&invalid_entry, raw) != Err(AttrError::UnencodableMemoryAttribute) {
                failures += 1;
            }
        }
        Err(_) => failures += 1,
    }
    matrix_result(failures)
}

pub fn stage2_combined_matrix() -> TestResult {
    let cacheabilities = all_mair_cacheabilities();
    let config = base_config(0, Stage2MemoryMode::FwbDisabled);
    let mut failures = 0;
    for inner in cacheabilities {
        for outer in cacheabilities {
            let memory =
                Stage2MemoryAttributes::Combined(MemoryAttributes::Normal { inner, outer });
            let valid =
                stage2_cacheability_is_encodable(inner) && stage2_cacheability_is_encodable(outer);
            let observed = if valid {
                stage2_round_trip(&config, memory).map(|decoded| decoded == memory)
            } else {
                resolve_stage2(&config, memory).map(|_| false)
            };
            if observed
                != if valid {
                    Ok(true)
                } else {
                    Err(AttrError::UnencodableMemoryAttribute)
                }
            {
                failures += 1;
            }
        }
    }
    for device in DEVICES {
        let memory = Stage2MemoryAttributes::Combined(MemoryAttributes::Device(device));
        if stage2_round_trip(&config, memory) != Ok(memory) {
            failures += 1;
        }
    }

    matrix_result(failures)
}

pub fn stage2_fwb_matrix() -> TestResult {
    use aarch64_vmsa::low_level::raw::FourBit;

    let without_mte = base_config(
        0,
        Stage2MemoryMode::FwbEnabled {
            mte_permission: false,
        },
    );
    let with_mte = base_config(
        0,
        Stage2MemoryMode::FwbEnabled {
            mte_permission: true,
        },
    );
    let mut failures = 0;
    for memory in [
        FwbStage2Memory::Device(DEVICES[0]),
        FwbStage2Memory::Device(DEVICES[1]),
        FwbStage2Memory::Device(DEVICES[2]),
        FwbStage2Memory::Device(DEVICES[3]),
        FwbStage2Memory::ForceNormalNonCacheable,
        FwbStage2Memory::ForceNormalWriteBack,
        FwbStage2Memory::UseStage1,
    ] {
        let semantic = Stage2MemoryAttributes::Fwb(memory);
        if stage2_round_trip(&without_mte, semantic) != Ok(semantic) {
            failures += 1;
        }
    }
    for memory in [
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess,
        FwbStage2Memory::UseStage1NoTagAccess,
    ] {
        let semantic = Stage2MemoryAttributes::Fwb(memory);
        if stage2_round_trip(&with_mte, semantic) != Ok(semantic) {
            failures += 1;
        }
        if resolve_stage2(&without_mte, semantic) != Err(AttrError::MtePermissionUnavailable) {
            failures += 1;
        }
    }
    let combined = base_config(0, Stage2MemoryMode::FwbDisabled);
    if resolve_stage2(
        &combined,
        Stage2MemoryAttributes::Fwb(FwbStage2Memory::UseStage1),
    ) != Err(AttrError::WrongStage2MemoryMode)
    {
        failures += 1;
    }
    if resolve_stage2(
        &without_mte,
        Stage2MemoryAttributes::Combined(MemoryAttributes::Device(DEVICES[0])),
    ) != Err(AttrError::WrongStage2MemoryMode)
    {
        failures += 1;
    }
    let seed = Stage2MemoryAttributes::Fwb(FwbStage2Memory::Device(DEVICES[0]));
    match resolve_stage2(&without_mte, seed) {
        Ok(raw) => {
            for bits in 0..16u8 {
                let mut encoded = raw;
                encoded.mem_attr = FourBit::new(bits)
                    .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
                let without = <VmsaAttributeCodec as AttributeCodec<
                    Vmsa64,
                    NonSecureEl2Stage2,
                    Granule4KiB,
                    _,
                >>::decode_leaf(&without_mte, Level::L3, encoded);
                let with = <VmsaAttributeCodec as AttributeCodec<
                    Vmsa64,
                    NonSecureEl2Stage2,
                    Granule4KiB,
                    _,
                >>::decode_leaf(&with_mte, Level::L3, encoded);
                let valid_without = matches!(bits, 0..=3 | 5..=7);
                let valid_with = valid_without || matches!(bits, 14 | 15);
                if without.is_ok() != valid_without
                    || with.is_ok() != valid_with
                    || (!valid_without && without != Err(AttrError::UnencodableMemoryAttribute))
                    || (!valid_with && with != Err(AttrError::UnencodableMemoryAttribute))
                {
                    failures += 1;
                }
            }
        }
        Err(_) => failures += 16,
    }
    matrix_result(failures)
}

pub fn d128_mair2_matrix() -> TestResult {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage1LeafControls, Stage1EffectivePermissions,
        Stage1PermissionRegisterPair, Stage1PermissionRegisters,
    };
    use aarch64_vmsa::descriptor::Vmsa128;

    let permissions = Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadOnly,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let leaf = |memory| SemanticStage1LeafAttrs {
        memory,
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
    };
    let make_config = |mair, mair2| LiveVmsaConfig {
        mair,
        mair2,
        stage1_permissions: Some(Stage1PermissionRegisters {
            privileged: Stage1PermissionRegisterPair {
                base: 0x8888_8888_8888_8888,
                overlay: None,
            },
            unprivileged: None,
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let mut failures = 0;
    for mair2_index in 0..8u8 {
        let config = make_config(0, Some(0x44u64 << (u32::from(mair2_index) * 8)));
        let semantic = leaf(memory);
        let result = <VmsaAttributeCodec as AttributeCodec<
            Vmsa128,
            NonSecureEl2Stage1,
            Granule4KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            if raw.attr_index.bits() != mair2_index + 8 {
                return Err(AttrError::RawFieldOutOfRange);
            }
            <VmsaAttributeCodec as AttributeCodec<
                Vmsa128,
                NonSecureEl2Stage1,
                Granule4KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        if result != Ok(semantic) {
            failures += 1;
        }
    }

    let duplicate = make_config(0x44 << 24, Some(0x44));
    if !matches!(
        <VmsaAttributeCodec as AttributeCodec<
            Vmsa128,
            NonSecureEl2Stage1,
            Granule4KiB,
            _,
        >>::resolve_leaf(&duplicate, Level::L3, leaf(memory)),
        Ok(raw) if raw.attr_index.bits() == 3
    ) {
        failures += 1;
    }

    let configured = make_config(0, Some(0x44));
    match <VmsaAttributeCodec as AttributeCodec<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&configured, Level::L3, leaf(memory))
    {
        Ok(raw) => {
            let unavailable = make_config(0, None);
            if <VmsaAttributeCodec as AttributeCodec<
                Vmsa128,
                NonSecureEl2Stage1,
                Granule4KiB,
                _,
            >>::decode_leaf(&unavailable, Level::L3, raw)
                != Err(AttrError::Mair2Unavailable)
            {
                failures += 1;
            }
            let invalid = make_config(0, Some(0x01));
            let mut invalid_raw = raw;
            invalid_raw.attr_index = aarch64_vmsa::low_level::raw::FourBit::new(8)
                .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
            if <VmsaAttributeCodec as AttributeCodec<
                Vmsa128,
                NonSecureEl2Stage1,
                Granule4KiB,
                _,
            >>::decode_leaf(&invalid, Level::L3, invalid_raw)
                != Err(AttrError::UnencodableMemoryAttribute)
            {
                failures += 1;
            }
        }
        Err(_) => failures += 1,
    }
    matrix_result(failures)
}

pub fn lpa2_shareability_matrix() -> TestResult {
    use aarch64_vmsa::address::{Granule16KiB, Granule64KiB};
    use aarch64_vmsa::descriptor::Vmsa64Lpa2;

    let memory = MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck);
    let leaf = |shareability| SemanticStage1LeafAttrs {
        memory,
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let values = [
        Shareability::NonShareable,
        Shareability::OuterShareable,
        Shareability::InnerShareable,
    ];
    let mut failures = 0;
    for effective in values {
        let mut config = base_config(0, Stage2MemoryMode::FwbDisabled);
        config.shareability = effective;
        let semantic = leaf(effective);
        let four = <VmsaAttributeCodec as AttributeCodec<
            Vmsa64Lpa2,
            NonSecureEl2Stage1,
            Granule4KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            <VmsaAttributeCodec as AttributeCodec<
                Vmsa64Lpa2,
                NonSecureEl2Stage1,
                Granule4KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        let sixteen = <VmsaAttributeCodec as AttributeCodec<
            Vmsa64Lpa2,
            NonSecureEl2Stage1,
            Granule16KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            <VmsaAttributeCodec as AttributeCodec<
                Vmsa64Lpa2,
                NonSecureEl2Stage1,
                Granule16KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        if four != Ok(semantic) || sixteen != Ok(semantic) {
            failures += 1;
        }
        for requested in values {
            if requested == effective {
                continue;
            }
            let expected = Err(AttrError::ShareabilityMismatch {
                requested,
                effective,
            });
            if <VmsaAttributeCodec as AttributeCodec<
                Vmsa64Lpa2,
                NonSecureEl2Stage1,
                Granule4KiB,
                _,
            >>::resolve_leaf(&config, Level::L3, leaf(requested))
                != expected
            {
                failures += 1;
            }
            if <VmsaAttributeCodec as AttributeCodec<
                Vmsa64Lpa2,
                NonSecureEl2Stage1,
                Granule16KiB,
                _,
            >>::resolve_leaf(&config, Level::L3, leaf(requested))
                != expected
            {
                failures += 1;
            }
        }
    }
    let config = base_config(0, Stage2MemoryMode::FwbDisabled);
    for requested in values {
        let semantic = leaf(requested);
        let sixty_four = <VmsaAttributeCodec as AttributeCodec<
            Vmsa64Lpa2,
            NonSecureEl2Stage1,
            Granule64KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, semantic)
        .and_then(|raw| {
            <VmsaAttributeCodec as AttributeCodec<
                Vmsa64Lpa2,
                NonSecureEl2Stage1,
                Granule64KiB,
                _,
            >>::decode_leaf(&config, Level::L3, raw)
        });
        if sixty_four != Ok(semantic) {
            failures += 1;
        }
    }
    matrix_result(failures)
}

fn base_config(mair: u64, stage2_memory_mode: Stage2MemoryMode) -> LiveVmsaConfig {
    LiveVmsaConfig {
        mair,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    }
}

fn stage1_leaf(
    memory: MemoryAttributes,
) -> SemanticStage1LeafAttrs<SinglePrivilegeLeafPermissions, (), SemanticVmsa64Stage1LeafControls> {
    SemanticStage1LeafAttrs {
        memory,
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn stage2_leaf(
    memory: Stage2MemoryAttributes,
) -> SemanticStage2LeafAttrs<Stage2LeafPermissions, (), SemanticVmsa64Stage2LeafControls> {
    SemanticStage2LeafAttrs {
        memory,
        permissions: Stage2LeafPermissions {
            data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: (),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

type RawStage1 = <VmsaAttributeCodec as AttributeCodec<
    Vmsa64,
    NonSecureEl2Stage1,
    Granule4KiB,
    LiveVmsaConfig,
>>::RawLeaf;

fn resolve_stage1(
    config: &LiveVmsaConfig,
    memory: MemoryAttributes,
) -> Result<RawStage1, AttrError> {
    <VmsaAttributeCodec as AttributeCodec<Vmsa64, NonSecureEl2Stage1, Granule4KiB, _>>::resolve_leaf(
        config,
        Level::L3,
        stage1_leaf(memory),
    )
}

fn decode_stage1(
    config: &LiveVmsaConfig,
    raw: RawStage1,
) -> Result<
    SemanticStage1LeafAttrs<SinglePrivilegeLeafPermissions, (), SemanticVmsa64Stage1LeafControls>,
    AttrError,
> {
    <VmsaAttributeCodec as AttributeCodec<Vmsa64, NonSecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
        config,
        Level::L3,
        raw,
    )
}

fn stage1_round_trip(
    config: &LiveVmsaConfig,
    memory: MemoryAttributes,
) -> Result<(u8, MemoryAttributes), AttrError> {
    let raw = resolve_stage1(config, memory)?;
    let index = raw.attr_index.bits();
    let decoded = decode_stage1(config, raw)?;
    Ok((index, decoded.memory))
}

type RawStage2 = <VmsaAttributeCodec as AttributeCodec<
    Vmsa64,
    NonSecureEl2Stage2,
    Granule4KiB,
    LiveVmsaConfig,
>>::RawLeaf;

fn resolve_stage2(
    config: &LiveVmsaConfig,
    memory: Stage2MemoryAttributes,
) -> Result<RawStage2, AttrError> {
    <VmsaAttributeCodec as AttributeCodec<Vmsa64, NonSecureEl2Stage2, Granule4KiB, _>>::resolve_leaf(
        config,
        Level::L3,
        stage2_leaf(memory),
    )
}

fn stage2_round_trip(
    config: &LiveVmsaConfig,
    memory: Stage2MemoryAttributes,
) -> Result<Stage2MemoryAttributes, AttrError> {
    let raw = resolve_stage2(config, memory)?;
    let decoded = <VmsaAttributeCodec as AttributeCodec<
        Vmsa64,
        NonSecureEl2Stage2,
        Granule4KiB,
        _,
    >>::decode_leaf(config, Level::L3, raw)?;
    Ok(decoded.memory)
}

fn all_mair_cacheabilities() -> [Cacheability; 15] {
    let mut values = [Cacheability::NonCacheable; 15];
    let mut count = 1;
    for policy in [CachePolicy::WriteThrough, CachePolicy::WriteBack] {
        for transience in [MemoryTransience::Transient, MemoryTransience::NonTransient] {
            for allocation in [
                AllocationHints::None,
                AllocationHints::WriteAllocate,
                AllocationHints::ReadAllocate,
                AllocationHints::ReadWriteAllocate,
            ] {
                if transience != MemoryTransience::Transient || allocation != AllocationHints::None
                {
                    values[count] = Cacheability::Cacheable {
                        policy,
                        transience,
                        allocation,
                    };
                    count += 1;
                }
            }
        }
    }
    debug_assert_eq!(count, values.len());
    values
}

fn mair_cache(value: Cacheability) -> u8 {
    match value {
        Cacheability::NonCacheable => 0b0100,
        Cacheability::Cacheable {
            policy,
            transience,
            allocation,
        } => {
            let high = match (policy, transience) {
                (CachePolicy::WriteThrough, MemoryTransience::Transient) => 0,
                (CachePolicy::WriteBack, MemoryTransience::Transient) => 4,
                (CachePolicy::WriteThrough, MemoryTransience::NonTransient) => 8,
                (CachePolicy::WriteBack, MemoryTransience::NonTransient) => 12,
            };
            high | match allocation {
                AllocationHints::None => 0,
                AllocationHints::WriteAllocate => 1,
                AllocationHints::ReadAllocate => 2,
                AllocationHints::ReadWriteAllocate => 3,
            }
        }
    }
}

fn stage2_cacheability_is_encodable(value: Cacheability) -> bool {
    matches!(
        value,
        Cacheability::NonCacheable
            | Cacheability::Cacheable {
                policy: CachePolicy::WriteThrough | CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            }
    )
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
