use crate::{CurrentEnvironment, LowerRegime};
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn stage1_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SoftwareMetadata, Stage2MemoryMode, TwoPrivilegeLeafPermissions,
        TwoPrivilegeTablePermissionLimits, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;

    const ADDRESS: u64 = 0x6800_0000;
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let direct_config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let stage1_controls = SemanticVmsa64Stage1LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        global: true,
        dirty_management: DirtyBitManagement::SoftwareManaged,
        contiguous: false,
        guarded: false,
        software: SoftwareMetadata::new(0),
    };
    let stage1_output = context.allocate_contiguous(4)?;
    let mut stage1_root = context.allocate_root()?;
    let mut stage1 = context
        .offline_mapper_for_format_with_geometry::<LowerRegime, Granule4KiB, Vmsa64>(
            &mut stage1_root,
            aarch64_vmsa::address::Level::L0,
            48,
            48,
        )?;
    let stage1_cases = [
        (
            TwoPrivilegeLeafPermissions {
                privileged_data: DataAccess::ReadWrite,
                unprivileged_data: DataAccess::None,
                privileged_execute: true,
                unprivileged_execute: false,
            },
            TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadWrite,
                unprivileged_data_limit: DataAccess::None,
                privileged_execute_limit: true,
                unprivileged_execute_limit: false,
            },
        ),
        (
            TwoPrivilegeLeafPermissions {
                privileged_data: DataAccess::ReadWrite,
                unprivileged_data: DataAccess::ReadWrite,
                privileged_execute: false,
                unprivileged_execute: true,
            },
            TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadWrite,
                unprivileged_data_limit: DataAccess::ReadWrite,
                privileged_execute_limit: false,
                unprivileged_execute_limit: true,
            },
        ),
        (
            TwoPrivilegeLeafPermissions {
                privileged_data: DataAccess::ReadOnly,
                unprivileged_data: DataAccess::None,
                privileged_execute: true,
                unprivileged_execute: true,
            },
            TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadOnly,
                unprivileged_data_limit: DataAccess::None,
                privileged_execute_limit: true,
                unprivileged_execute_limit: true,
            },
        ),
        (
            TwoPrivilegeLeafPermissions {
                privileged_data: DataAccess::ReadOnly,
                unprivileged_data: DataAccess::ReadOnly,
                privileged_execute: false,
                unprivileged_execute: false,
            },
            TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadOnly,
                unprivileged_data_limit: DataAccess::ReadOnly,
                privileged_execute_limit: false,
                unprivileged_execute_limit: false,
            },
        ),
    ];
    for (index, (permissions, permission_limits)) in stage1_cases.into_iter().enumerate() {
        let address = ADDRESS + index as u64 * 4096;
        stage1.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &direct_config,
            address,
            stage1_output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            SemanticStage1LeafAttrs {
                memory,
                permissions,
                pas: (),
                controls: stage1_controls,
            },
            SemanticStage1TableAttrs {
                permission_limits,
                pas: (),
                controls: SemanticVmsa64Stage1TableControls::default(),
            },
        )?;
        let decoded = stage1
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &direct_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.permissions != permissions {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    if stage1.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &direct_config,
        ADDRESS + 4 * 4096,
        stage1_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        SemanticStage1LeafAttrs {
            memory,
            permissions: TwoPrivilegeLeafPermissions {
                privileged_data: DataAccess::None,
                unprivileged_data: DataAccess::None,
                privileged_execute: false,
                unprivileged_execute: false,
            },
            pas: (),
            controls: stage1_controls,
        },
        SemanticStage1TableAttrs {
            permission_limits: TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadWrite,
                unprivileged_data_limit: DataAccess::None,
                privileged_execute_limit: true,
                unprivileged_execute_limit: false,
            },
            pas: (),
            controls: SemanticVmsa64Stage1TableControls::default(),
        },
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::UnencodablePermissions,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }

    TestResult::Pass
}
pub(super) fn stage2_direct_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage2LeafAttrs, SemanticVmsa64Stage2LeafControls,
        SemanticVmsa64Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2LeafPermissions,
        Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permissions, Stage2XnxPermissions,
        VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::NonSecureEl2Stage2;
    const ADDRESS: u64 = 0x6800_0000;
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let direct_config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let stage2_output = context.allocate_contiguous(12)?;
    let mut xnx_root = context.allocate_root()?;
    let mut xnx = context.offline_mapper_for_format_with_geometry::<
        NonSecureEl2Stage2<Stage2XnxPermissions>,
        Granule4KiB,
        Vmsa64,
    >(
        &mut xnx_root,
        aarch64_vmsa::address::Level::L0,
        48,
        48,
    )?;
    let stage2_controls = SemanticVmsa64Stage2LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        dirty_management: DirtyBitManagement::SoftwareManaged,
        contiguous: false,
        software: SoftwareMetadata::new(0),
    };
    let mut index = 0usize;
    for data in [
        DataAccess::None,
        DataAccess::ReadOnly,
        DataAccess::ReadWrite,
    ] {
        for (privileged_execute, unprivileged_execute) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let permissions = Stage2LeafPermissions {
                data,
                privileged_execute,
                unprivileged_execute,
            };
            let address = ADDRESS + 0x10_0000 + index as u64 * 4096;
            xnx.map_semantic_leaf::<VmsaAttributeCodec, _>(
                &direct_config,
                address,
                stage2_output.phys_addr() + index as u64 * 4096,
                vmsa_test_harness::LookupLevel::new(3)
                    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                SemanticStage2LeafAttrs {
                    memory: Stage2MemoryAttributes::Combined(memory),
                    permissions,
                    output_address_space: (),
                    controls: stage2_controls,
                },
                SemanticVmsa64Stage2TableAttrs::default(),
            )?;
            let decoded = xnx
                .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &direct_config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if decoded.permissions != permissions {
                return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
            }
            index += 1;
        }
    }
    let mut direct_stage2_root = context.allocate_root()?;
    let mut direct_stage2 = context.offline_mapper_for_format_with_geometry::<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        Vmsa64,
    >(
        &mut direct_stage2_root,
        aarch64_vmsa::address::Level::L0,
        48,
        48,
    )?;
    if direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &direct_config,
        ADDRESS + 0x1f_0000,
        stage2_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Combined(memory),
            permissions: Stage2LeafPermissions {
                data: DataAccess::ReadOnly,
                privileged_execute: true,
                unprivileged_execute: false,
            },
            output_address_space: (),
            controls: stage2_controls,
        },
        SemanticVmsa64Stage2TableAttrs::default(),
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::InvalidStage2ExecuteNever,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }

    TestResult::Pass
}
pub(super) fn stage2_fwb_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DeviceMemoryType, DirtyBitManagement,
        FwbStage2Memory, LiveVmsaConfig, MemoryAttributes, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SoftwareMetadata, Stage2LeafPermissions, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permissions, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::NonSecureEl2Stage2;
    const ADDRESS: u64 = 0x6800_0000;
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let direct_config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let stage2_controls = SemanticVmsa64Stage2LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        dirty_management: DirtyBitManagement::SoftwareManaged,
        contiguous: false,
        software: SoftwareMetadata::new(0),
    };
    let mut direct_stage2_root = context.allocate_root()?;
    let mut direct_stage2 = context.offline_mapper_for_format_with_geometry::<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        Vmsa64,
    >(
        &mut direct_stage2_root,
        aarch64_vmsa::address::Level::L0,
        48,
        48,
    )?;
    let stage2_output = context.allocate_page()?;
    let fwb_no_mte = LiveVmsaConfig {
        stage2_memory_mode: Stage2MemoryMode::FwbEnabled {
            mte_permission: false,
        },
        ..direct_config
    };
    let fwb_with_mte = LiveVmsaConfig {
        stage2_memory_mode: Stage2MemoryMode::FwbEnabled {
            mte_permission: true,
        },
        ..direct_config
    };
    let fwb_permissions = Stage2LeafPermissions {
        data: DataAccess::ReadWrite,
        privileged_execute: false,
        unprivileged_execute: false,
    };
    let fwb_values = [
        FwbStage2Memory::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
        FwbStage2Memory::Device(DeviceMemoryType::NonGatheringNonReorderingEarlyAck),
        FwbStage2Memory::Device(DeviceMemoryType::NonGatheringReorderingEarlyAck),
        FwbStage2Memory::Device(DeviceMemoryType::GatheringReorderingEarlyAck),
        FwbStage2Memory::ForceNormalNonCacheable,
        FwbStage2Memory::ForceNormalWriteBack,
        FwbStage2Memory::UseStage1,
    ];
    for (index, fwb_memory) in fwb_values.into_iter().enumerate() {
        let address = ADDRESS + 0x40_0000 + index as u64 * 4096;
        let leaf = SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Fwb(fwb_memory),
            permissions: fwb_permissions,
            output_address_space: (),
            controls: stage2_controls,
        };
        direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &fwb_no_mte,
            address,
            stage2_output.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            SemanticVmsa64Stage2TableAttrs::default(),
        )?;
        if direct_stage2
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &fwb_no_mte)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
            != leaf
        {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    for (index, fwb_memory) in [
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess,
        FwbStage2Memory::UseStage1NoTagAccess,
    ]
    .into_iter()
    .enumerate()
    {
        let address = ADDRESS + 0x48_0000 + index as u64 * 4096;
        let leaf = SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Fwb(fwb_memory),
            permissions: fwb_permissions,
            output_address_space: (),
            controls: stage2_controls,
        };
        if direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &fwb_no_mte,
            address,
            stage2_output.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            SemanticVmsa64Stage2TableAttrs::default(),
        ) != Err(vmsa_test_harness::HarnessError::Attribute(
            vmsa_test_harness::AttributeError::MtePermissionUnavailable,
        )) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &fwb_with_mte,
            address,
            stage2_output.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            SemanticVmsa64Stage2TableAttrs::default(),
        )?;
        if direct_stage2
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &fwb_with_mte)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
            != leaf
        {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    let combined_leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory),
        permissions: fwb_permissions,
        output_address_space: (),
        controls: stage2_controls,
    };
    if direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &fwb_no_mte,
        ADDRESS + 0x4f_0000,
        stage2_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        combined_leaf,
        SemanticVmsa64Stage2TableAttrs::default(),
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::WrongStage2MemoryMode,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let fwb_leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Fwb(FwbStage2Memory::UseStage1),
        permissions: fwb_permissions,
        output_address_space: (),
        controls: stage2_controls,
    };
    if direct_stage2.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &direct_config,
        ADDRESS + 0x4f_1000,
        stage2_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        fwb_leaf,
        SemanticVmsa64Stage2TableAttrs::default(),
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::WrongStage2MemoryMode,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }

    TestResult::Pass
}
pub(super) fn d128_stage2_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DirtyState, LiveVmsaConfig, MemoryAttributes,
        MostlyReadOnly, SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        SemanticVmsa128Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2MemoryAttributes,
        Stage2MemoryMode, Stage2Permission, Stage2PermissionRegisters, Stage2Permissions,
        VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::NonSecureEl2Stage2;
    const ADDRESS: u64 = 0x6800_0000;
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let direct_config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let d128_permissions = [
        Stage2Permission::NoAccess,
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::Unqualified),
        Stage2Permission::MostlyReadOnly(MostlyReadOnly::TopLevel1),
        Stage2Permission::WriteOnly,
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
    let d128_config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: Some(Stage2PermissionRegisters {
            s2pir_el2: 0xfedc_ba98_7654_3210,
            s2por_el1: None,
        }),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let d128_output = context.allocate_contiguous(d128_permissions.len())?;
    let mut d128_root = context.allocate_root()?;
    let mut d128 = context.offline_mapper_for_format_with_geometry::<
        NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        Vmsa128,
    >(
        &mut d128_root,
        aarch64_vmsa::address::Level::NEG2,
        52,
        52,
    )?;
    let d128_controls = SemanticVmsa128Stage2LeafControls {
        bbm_nt: false,
        dirty_state: DirtyState::Clean,
        shareability: Shareability::InnerShareable,
        access_flag: true,
        force_no_execute: false,
        contiguous: false,
        assured_only: false,
        software: SoftwareMetadata::new(0),
    };
    let d128_leaf = |permissions| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory),
        permissions,
        output_address_space: (),
        controls: d128_controls,
    };
    if d128.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &direct_config,
        ADDRESS + 0x2f_0000,
        d128_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        d128_leaf(Stage2Permission::NoAccess),
        SemanticVmsa128Stage2TableAttrs::default(),
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::PermissionIndirectionUnavailable,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let missing_combination_config = LiveVmsaConfig {
        stage2_permissions: Some(Stage2PermissionRegisters {
            s2pir_el2: 0,
            s2por_el1: None,
        }),
        ..direct_config
    };
    if d128.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &missing_combination_config,
        ADDRESS + 0x2f_1000,
        d128_output.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        d128_leaf(Stage2Permission::WriteOnly),
        SemanticVmsa128Stage2TableAttrs::default(),
    ) != Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::PermissionCombinationNotConfigured,
    )) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    for (index, permissions) in d128_permissions.into_iter().enumerate() {
        let address = ADDRESS + 0x20_0000 + index as u64 * 4096;
        d128.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &d128_config,
            address,
            d128_output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            d128_leaf(permissions),
            SemanticVmsa128Stage2TableAttrs::default(),
        )?;
        let decoded = d128
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &d128_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.permissions != permissions {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    TestResult::Pass
}
pub(super) fn d128_stage1_effective_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyState, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticVmsa128Stage1LeafControls,
        SemanticVmsa128Stage1TableAttrs, Shareability, SoftwareMetadata,
        Stage1EffectivePermissions, Stage1PermissionRegisterPair, Stage1PermissionRegisters,
        Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa128;

    const ADDRESS: u64 = 0x6800_0000;
    let memory = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let effective_output = context.allocate_contiguous(2)?;
    let mut effective_root = context.allocate_root()?;
    let mut effective = context
        .offline_mapper_for_format_with_geometry::<LowerRegime, Granule4KiB, Vmsa128>(
            &mut effective_root,
            aarch64_vmsa::address::Level::NEG2,
            52,
            52,
        )?;
    for (index, (privileged_base, unprivileged_base, privileged_gcs, unprivileged_gcs)) in [
        (0x9999_9999_9999_9999, 0x8888_8888_8888_8888, true, false),
        (0x8888_8888_8888_8888, 0x9999_9999_9999_9999, false, true),
    ]
    .into_iter()
    .enumerate()
    {
        let permissions = Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadOnly,
            unprivileged_data: DataAccess::ReadOnly,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs,
            unprivileged_gcs,
        };
        let config = LiveVmsaConfig {
            mair: 0x44,
            mair2: None,
            stage1_permissions: Some(Stage1PermissionRegisters {
                privileged: Stage1PermissionRegisterPair {
                    base: privileged_base,
                    overlay: None,
                },
                unprivileged: Some(Stage1PermissionRegisterPair {
                    base: unprivileged_base,
                    overlay: None,
                }),
                gcs_implemented: true,
            }),
            stage2_permissions: None,
            stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
            d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
            shareability: Shareability::InnerShareable,
            output_pas: (),
        };
        let address = ADDRESS + 0x30_0000 + index as u64 * 4096;
        effective.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            address,
            effective_output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            SemanticStage1LeafAttrs {
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
            },
            SemanticVmsa128Stage1TableAttrs::default(),
        )?;
        let decoded = effective
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.permissions != permissions {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    TestResult::Pass
}
