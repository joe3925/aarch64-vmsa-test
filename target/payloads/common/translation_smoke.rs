use crate::{CurrentEnvironment, CurrentRegime, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn semantic_codec(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    if !context.verify_fault_normalization() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    const ADDRESS: u64 = 0x6400_0000;
    let page = context.allocate_page()?;
    let mut offline_root = context.allocate_root()?;
    let leaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
        memory: aarch64_vmsa::attrs::MemoryAttributes::Normal {
            inner: aarch64_vmsa::attrs::Cacheability::Cacheable {
                policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
                transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
                allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
            },
            outer: aarch64_vmsa::attrs::Cacheability::Cacheable {
                policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
                transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
                allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
            },
        },
        permissions: aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute: false,
        },
        pas: (),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls {
            shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
        },
    };
    let table = aarch64_vmsa::attrs::SemanticStage1TableAttrs {
        permission_limits: aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits {
            data_limit: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls::default(),
    };
    let semantic = {
        let mut mapper = context.offline_mapper(&mut offline_root)?;
        let missing_memory_config = aarch64_vmsa::attrs::LiveVmsaConfig {
            mair: 0,
            mair2: None,
            stage1_permissions: None,
            stage2_permissions: None,
            stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
            d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
            shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
            output_pas: (),
        };
        if mapper.map_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            &missing_memory_config,
            ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        ) != Err(vmsa_test_harness::HarnessError::Attribute(
            vmsa_test_harness::AttributeError::MemoryAttributeNotConfigured,
        )) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        mapper.map_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            &config,
            ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        )?;
        mapper
            .inspect_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(ADDRESS, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
    };
    let capabilities = context.capabilities();
    let input_bits = vmsa_test_harness::AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = vmsa_test_harness::AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
    let root_address = vmsa_test_harness::PhysicalAddress::new(root.phys_addr());
    let mut live = context.install_owned(
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
    live.map_semantic_for::<
        CurrentRegime,
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::attrs::VmsaAttributeCodec,
        _,
    >(
        &config,
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let live_mapping = live
        .inspect_for::<
            CurrentRegime,
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::address::Granule4KiB,
        >(ADDRESS)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_mapping.output != page.phys_addr() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let live_semantic = live
        .inspect_semantic_for::<
            CurrentRegime,
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::attrs::VmsaAttributeCodec,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_semantic != semantic {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    live.restore()?;
    let observations =
        u64::from(semantic.permissions.data == aarch64_vmsa::attrs::DataAccess::ReadWrite)
            | (u64::from(!semantic.permissions.execute) << 1)
            | (u64::from(semantic.controls.access_flag) << 2)
            | (u64::from(
                semantic.controls.shareability == aarch64_vmsa::attrs::Shareability::InnerShareable,
            ) << 3);
    if observations != 0xf {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0xf,
            actual: observations,
        });
    }
    TestResult::Pass
}
pub(super) fn permission_semantics(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DeviceMemoryType, DirtyBitManagement,
        DirtyState, FwbStage2Memory, LiveVmsaConfig, MemoryAttributes, MostlyReadOnly,
        SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
        SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs,
        SemanticVmsa128Stage2LeafControls, SemanticVmsa128Stage2TableAttrs, Shareability,
        SoftwareMetadata, Stage1EffectivePermissions, Stage1PermissionRegisterPair,
        Stage1PermissionRegisters, Stage2LeafPermissions, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permission, Stage2PermissionRegisters, Stage2Permissions, Stage2XnxPermissions,
        TwoPrivilegeLeafPermissions, TwoPrivilegeTablePermissionLimits, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::{Vmsa64, Vmsa128};
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
            return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

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
                return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

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
            return vmsa_test_harness::HarnessError::InvalidState.into();
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
            return vmsa_test_harness::HarnessError::InvalidState.into();
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
            return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
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
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    TestResult::Pass
}
pub(super) fn hardware_access_dirty(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::descriptor::Vmsa64;
    use vmsa_test_harness::{
        AddressBits, Granule, HardwareManagedAttributes, LookupLevel, MappingAttributes,
        PhysicalAddress, TranslationControls, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    const ADDRESS: u64 = 0x6500_0000;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    translation.map_hardware_managed::<Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        HardwareManagedAttributes {
            mapping: MappingAttributes::READ_WRITE,
            access_flag: false,
            dirty_modifier: false,
        },
    )?;
    let access_flag_fault = vmsa_test_harness::expect_matching_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::AccessFlag),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: LookupLevel::new(3),
        })
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(ADDRESS)
        .with_ipa(None),
    );
    if !matches!(access_flag_fault, TestResult::Pass) {
        return access_flag_fault;
    }
    {
        let _updates = context.enable_hardware_updates(false)?;
        let result = vmsa_test_harness::expect_completed(context.read_u64(ADDRESS));
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    if !translation
        .inspect_hardware_updates::<Granule4KiB>(ADDRESS)?
        .access_flag
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    translation.unmap::<Vmsa64, Granule4KiB>(ADDRESS)?;
    translation.map_hardware_managed::<Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        HardwareManagedAttributes {
            mapping: MappingAttributes::READ_ONLY,
            access_flag: true,
            dirty_modifier: true,
        },
    )?;
    {
        let _updates = context.enable_hardware_updates(true)?;
        let result = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x4841_4844));
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    let became_writable = translation
        .inspect_hardware_updates::<Granule4KiB>(ADDRESS)?
        .writable;
    if became_writable {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}
pub(super) fn recursive_table_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, MappingAttributes, PhysicalAddress, TranslationControls,
        TranslationFormat, TranslationSetup, TranslationStage,
    };

    const ADDRESS: u64 = 0x6700_0000;
    const RECURSIVE_INDEX: usize = 1;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits: AddressBits::new(capabilities.va_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            output_bits: AddressBits::new(capabilities.pa_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    let start_level = translation
        .setup()
        .start_level
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .get();
    let mut recursive_base = 0u64;
    for level in start_level..=3 {
        let shift = match level {
            0 => 39,
            1 => 30,
            2 => 21,
            3 => 12,
            _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
        };
        recursive_base |= (RECURSIVE_INDEX as u64) << shift;
    }
    let updates = context.enable_hardware_updates(false)?;
    let mapping = translation.map_recursive_4k(
        RECURSIVE_INDEX,
        recursive_base,
        ADDRESS,
        page.phys_addr(),
        MappingAttributes::READ_WRITE,
    )?;
    if mapping.output != page.phys_addr() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    drop(updates);
    let written = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x5245_4355));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    vmsa_test_harness::expect_value(context.read_u64(ADDRESS), 0x5245_4355)
}
pub(super) fn allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    for point in [
        vmsa_test_harness::MemoryFailurePoint::Page,
        vmsa_test_harness::MemoryFailurePoint::Contiguous,
        vmsa_test_harness::MemoryFailurePoint::Root,
    ] {
        let failed = context.with_memory_failure(point, 0, || match point {
            vmsa_test_harness::MemoryFailurePoint::Page => context.allocate_page().is_err(),
            vmsa_test_harness::MemoryFailurePoint::Contiguous => {
                context.allocate_contiguous(2).is_err()
            }
            vmsa_test_harness::MemoryFailurePoint::Root => context.allocate_root().is_err(),
            vmsa_test_harness::MemoryFailurePoint::TableFrame => false,
        })?;
        if !failed {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        match point {
            vmsa_test_harness::MemoryFailurePoint::Page => {
                context.allocate_page()?;
            }
            vmsa_test_harness::MemoryFailurePoint::Contiguous => {
                context.allocate_contiguous(2)?;
            }
            vmsa_test_harness::MemoryFailurePoint::Root => {
                context.allocate_root()?;
            }
            vmsa_test_harness::MemoryFailurePoint::TableFrame => {}
        }
    }
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    const INTERMEDIATE_ADDRESS: u64 = 0x6800_0000;
    let failed = context.with_table_allocation_failure(1, || {
        let mut mapper = context.offline_mapper(&mut root)?;
        Ok::<bool, vmsa_test_harness::HarnessError>(
            mapper
                .map_block(
                    INTERMEDIATE_ADDRESS,
                    page.phys_addr(),
                    vmsa_test_harness::MappingAttributes::READ_WRITE,
                )
                .is_err(),
        )
    })??;
    if !failed {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut mapper = context.offline_mapper(&mut root)?;
    if mapper.translate(INTERMEDIATE_ADDRESS)?.is_some() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if mapper
        .map_block(
            INTERMEDIATE_ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::MappingAttributes::READ_WRITE,
        )
        .is_err()
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let Some(mapping) = mapper.translate(INTERMEDIATE_ADDRESS)? else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    if mapping.output != page.phys_addr() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if context.verify_arena_exhaustion_boundary() {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}
pub(super) fn combined_stage1_stage2(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationQueryAccess, TranslationQueryResult, TranslationSetup,
        TranslationStage, Vmid, vmsa64_el1_stage1_controls_4k, vmsa64_stage2_controls_4k,
    };

    const VIRTUAL_ADDRESS: u64 = 0x5000_0000;
    let input_bits = AddressBits::new(39).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_width = context.capabilities().pa_bits.min(48);
    let output_bits =
        AddressBits::new(output_width).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let level3 = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls = vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let cacheability = aarch64_vmsa::attrs::Cacheability::Cacheable {
        policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
        transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
        allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
    };
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT
        .with_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::attrs::MemoryAttributes::Normal {
                inner: cacheability,
                outer: cacheability,
            },
        )
        .map_err(vmsa_test_harness::HarnessError::Attribute)?;

    for mode in 0u16..3 {
        let inject_partial = mode == 0;
        let omit_target = mode == 2;
        let data_page = context.allocate_page()?;
        const DATA_VALUE: u64 = 0x434f_4d42_494e_4544;
        if !matches!(
            context.write_u64(data_page.virtual_address() as u64, DATA_VALUE),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let mut stage1_root = context.allocate_root()?;
        let mut stage2_root = context.allocate_root()?;
        let table_walk_region = stage1_root.phys_addr() & !0x3fff_ffff;
        let target_region = table_walk_region ^ 0x4000_0000;
        let target_ipa = target_region | (data_page.phys_addr() - table_walk_region);
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                LowerRegime,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut stage1_root,
                aarch64_vmsa::address::Level::L1,
                input_bits.get(),
                output_bits.get(),
            )?;
            mapper.map_leaf(
                VIRTUAL_ADDRESS,
                target_ipa,
                level3,
                MappingAttributes::READ_WRITE,
            )?;
            let inspection = mapper
                .translate(VIRTUAL_ADDRESS)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if inspection.output != target_ipa {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                Stage2Regime,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut stage2_root,
                aarch64_vmsa::address::Level::L1,
                input_bits.get(),
                output_bits.get(),
            )?;
            let recovery_attributes = MappingAttributes {
                writable: true,
                executable: true,
                user_accessible: false,
            };
            mapper.map_leaf(
                table_walk_region,
                table_walk_region,
                start_level,
                recovery_attributes,
            )?;
            // The lower-EL firmware conduit and its fault mailbox live in the
            // low 1 GiB IPA region. Keep that invariant recovery path reachable
            // while stage 2 is active so a candidate-target fault can return.
            mapper.map_leaf(0, 0, start_level, recovery_attributes)?;
            if !omit_target {
                mapper.map_leaf(
                    target_region,
                    table_walk_region,
                    start_level,
                    MappingAttributes::READ_WRITE,
                )?;
            }
        }
        let stage1_setup = TranslationSetup {
            root: PhysicalAddress::new(stage1_root.phys_addr()),
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start_level),
            asid: Some(Asid(0x40 + mode)),
            vmid: None,
            controls: stage1_controls,
            stage1_memory,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        };
        let stage2_setup = TranslationSetup {
            root: PhysicalAddress::new(stage2_root.phys_addr()),
            stage: TranslationStage::Stage2,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start_level),
            asid: None,
            vmid: Some(Vmid(0x30 + mode)),
            controls: stage2_controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        };
        if inject_partial {
            let injected = context.with_harness_failure(
                vmsa_test_harness::HarnessFailurePoint::PartialCombinedInstallation,
                0,
                || {
                    context.install_combined_owned(
                        stage1_root,
                        stage1_setup,
                        stage2_root,
                        stage2_setup,
                    )
                },
            );
            if !matches!(
                injected,
                Err(vmsa_test_harness::HarnessError::InjectedFailure)
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            continue;
        }
        let mut combined =
            context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
        if combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(VIRTUAL_ADDRESS),
            ),
        ) != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        combined.tlbi(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::VirtualAddress(VIRTUAL_ADDRESS),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::Asid(Asid(0x40 + mode)),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage2(
                vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(target_region),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::CombinedTlbiOperation::Stage2(
                vmsa_test_harness::TlbiOperation::Vmid(Vmid(0x30 + mode)),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::All,
        )?;
        let installed_stage1_output = combined
            .stage1_mut()?
            .inspect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(VIRTUAL_ADDRESS)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
            .output;
        if installed_stage1_output != target_ipa {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        if !omit_target {
            let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
                mair: 0x0000_ff44,
                mair2: None,
                stage1_permissions: None,
                stage2_permissions: None,
                stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
                output_pas: (),
            };
            let semantic = combined
                .stage2_mut()?
                .inspect_semantic_for::<
                    Stage2Regime,
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                    aarch64_vmsa::attrs::VmsaAttributeCodec,
                    _,
                >(target_region, &semantic_config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if semantic.permissions.data != aarch64_vmsa::attrs::DataAccess::ReadWrite
                || semantic.controls.shareability
                    != aarch64_vmsa::attrs::Shareability::InnerShareable
                || !semantic.controls.access_flag
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        let query = combined.translate(VIRTUAL_ADDRESS, TranslationQueryAccess::Read);
        if omit_target {
            match query {
                TranslationQueryResult::Fault { stage2: true, .. } => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
        } else {
            match query {
                TranslationQueryResult::Success {
                    physical_address, ..
                } if physical_address == data_page.phys_addr() => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            let original_pair = match combined.read_pair_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::CompletedPair { first, second } => (first, second),
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            };
            if !matches!(
                combined.read_u8(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xff
            ) || !matches!(
                combined.read_u16(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xffff
            ) || !matches!(
                combined.read_u32(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xffff_ffff
            ) || !matches!(
                combined.write_release_u64(VIRTUAL_ADDRESS, DATA_VALUE),
                vmsa_test_harness::AccessResult::Completed { .. }
            ) || !matches!(
                combined.read_acquire_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) || !matches!(
                combined.atomic_swap_u64(VIRTUAL_ADDRESS, DATA_VALUE + 1),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) || !matches!(
                combined.exclusive_add_u64(VIRTUAL_ADDRESS, 1),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE + 1
            ) || !matches!(
                combined.write_pair_u64(VIRTUAL_ADDRESS, original_pair.0, original_pair.1),
                vmsa_test_harness::AccessResult::CompletedPair { .. }
            ) || !matches!(
                combined.read_pair_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::CompletedPair { first, second }
                    if first == original_pair.0 && second == original_pair.1
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            match combined.execute(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.access == vmsa_test_harness::AccessKind::Execute => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(
                VIRTUAL_ADDRESS,
                MappingAttributes {
                    writable: false,
                    executable: false,
                    user_accessible: true,
                },
            )?;
            match combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 3) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage1 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(
                VIRTUAL_ADDRESS,
                MappingAttributes {
                    writable: true,
                    executable: false,
                    user_accessible: true,
                },
            )?;
            combined.stage2_mut()?.protect_for::<
                Stage2Regime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(target_region, MappingAttributes::READ_ONLY)?;
            match combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 4) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage2_mut()?.protect_for::<
                Stage2Regime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(target_region, MappingAttributes::READ_WRITE)?;
            if !matches!(
                combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        combined.restore()?;
    }
    TestResult::Pass
}
#[derive(Clone, Copy)]
struct ActiveGeometry {
    granule: vmsa_test_harness::Granule,
    format: vmsa_test_harness::TranslationFormat,
    start_level: aarch64_vmsa::address::Level,
    input_width: u8,
    output_width: u8,
    controls: vmsa_test_harness::TranslationControls,
}

fn active_granule<F, G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    geometry: ActiveGeometry,
    malformed_terminal: bool,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    F: vmsa_test_harness::adapter::TestFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::descriptor::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::translation::Stage1,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    CurrentRegime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    CurrentRegime,
                    G,
                >,
            >,
    aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, CurrentRegime, G>: Copy,
    aarch64_vmsa::attrs::VmsaAttributeCodec: aarch64_vmsa::attrs::AttributeCodec<
            F,
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<()>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
                (),
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, CurrentRegime, G>,
            RawTable = aarch64_vmsa::regime::TableFieldsOf<F, CurrentRegime, G>,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, MappingAttributes, PhysicalAddress};

    const ADDRESS: u64 = 0x6a00_0000;
    const FAULT_ADDRESS: u64 = 0x6d00_0000;
    const VALUE: u64 = 0x4143_5449_5645_474e;
    let page = context.allocate_page()?;
    let write = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let input_bits = AddressBits::new(geometry.input_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(geometry.output_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let level = LookupLevel::new(geometry.start_level.as_i8())
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<CurrentRegime, G, F>(
            &mut root,
            geometry.start_level,
            input_bits.get(),
            output_bits.get(),
        )?;
        mapper.map_attributes_leaf(
            ADDRESS,
            page.phys_addr(),
            leaf_level,
            MappingAttributes::READ_WRITE,
        )?;
        sandbox = context
            .prepare_transition_runtime(&mut mapper, active_granule::<F, G> as *const () as u64)?;
        let walk = mapper.inspect_walk(ADDRESS)?;
        let Some(leaf) = walk.leaf() else {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        };
        if walk.steps().len() < 2
            || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
            || leaf.raw.is_none()
            || leaf.next_table.is_some()
            || leaf.output != Some(page.phys_addr())
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        if malformed_terminal {
            let Some(mut replacement) = leaf.raw else {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            };
            replacement.low &= !0b10;
            let original = mapper
                .isolated_malformed_table()
                .replace_terminal_descriptor(ADDRESS, replacement)?;
            if original != leaf.raw.unwrap_or(replacement) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned_in_sandbox(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule: geometry.granule,
            format: geometry.format,
            input_bits,
            output_bits,
            start_level: Some(level),
            asid: None,
            vmid: None,
            controls: geometry.controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
        &sandbox,
    )?;
    if !translation.transition_sandbox_active(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if malformed_terminal {
        let result = vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            vmsa_test_harness::FaultMatcher::new(
                vmsa_test_harness::ExpectedFault::translation_read_stage1(),
            )
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(ADDRESS)
            .with_ipa(None),
        );
        if !translation.transition_sandbox_active(&sandbox) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        drop(translation);
        if !context.transition_sandbox_restored(&sandbox) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        return result;
    }
    let fault = vmsa_test_harness::expect_matching_fault(
        context.read_u64(FAULT_ADDRESS),
        vmsa_test_harness::FaultMatcher::new(
            vmsa_test_harness::ExpectedFault::translation_read_stage1(),
        )
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(FAULT_ADDRESS)
        .with_ipa(None),
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    if !translation.transition_sandbox_active(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let live_walk = translation.inspect_walk::<F, G>(ADDRESS)?;
    let Some(live_leaf) = live_walk.leaf() else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    if live_walk.steps().len() < 2
        || live_leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || live_leaf.output != Some(page.phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    let semantic = translation
        .inspect_semantic_for::<CurrentRegime, F, G, aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            ADDRESS,
            &semantic_config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if semantic.permissions.data != aarch64_vmsa::attrs::DataAccess::ReadWrite
        || semantic.permissions.execute
        || !semantic.controls.access_flag
        || semantic.controls.shareability != aarch64_vmsa::attrs::Shareability::InnerShareable
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let result = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    result
}

pub(super) fn active_16k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root_16k()?;
    let input = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size16KiB,
        input,
        output,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule16KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size16KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level: aarch64_vmsa::address::Level::L0,
            input_width: 48,
            output_width: 48,
            controls,
        },
        false,
    )
}

pub(super) fn malformed_descriptor_recovery(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    let input = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size16KiB,
        input,
        output,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule16KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size16KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level: aarch64_vmsa::address::Level::L0,
            input_width: 48,
            output_width: 48,
            controls,
        },
        true,
    )
}

pub(super) fn active_4k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    let input = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size4KiB,
        input,
        output,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level: aarch64_vmsa::address::Level::L0,
            input_width: 48,
            output_width: 48,
            controls,
        },
        false,
    )
}

pub(super) fn active_64k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root_64k()?;
    let input = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size64KiB,
        input,
        output,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule64KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size64KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level: aarch64_vmsa::address::Level::L1,
            input_width: 48,
            output_width: 48,
            controls,
        },
        false,
    )
}

pub(super) fn active_lpa2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_el2_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule4KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
            start_level: aarch64_vmsa::address::Level::NEG1,
            input_width: 52,
            output_width: 52,
            controls,
        },
        false,
    )
}

pub(super) fn active_d128(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, D128HardwareManagedAttributes, D128MappingPermissions, ExpectedFault,
        FaultMatcher, Granule, LookupLevel, PhysicalAddress, TlbiOperation, TranslationFormat,
        TranslationSetup, TranslationStage,
    };

    const ADDRESS: u64 = 0x6b00_0000;
    const MAIR2_ADDRESS: u64 = ADDRESS + 0x1000;
    const VALUE: u64 = 0x4431_3238_4c49_5645;
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::d128_el1_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let invalid_root = context.allocate_root_16k()?;
    let invalid_root_address = PhysicalAddress::new(invalid_root.phys_addr());
    if !matches!(
        context.install_lower_owned(
            invalid_root,
            TranslationSetup {
                root: invalid_root_address,
                stage: TranslationStage::Stage1,
                granule: Granule::Size16KiB,
                format: TranslationFormat::Vmsa128,
                input_bits: bits,
                output_bits: bits,
                start_level: Some(start),
                asid: None,
                vmid: None,
                controls,
                stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
                regime: vmsa_test_harness::RegimeAttributes::Normal,
            },
        ),
        Err(vmsa_test_harness::HarnessError::InvalidState)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let page = context.allocate_page()?;
    let replacement = context.allocate_page()?;
    let write = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let replacement_value = VALUE ^ u64::MAX;
    let write = context.write_u64(replacement.virtual_address() as u64, replacement_value);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let d128_permissions = aarch64_vmsa::attrs::Stage1PermissionRegisterPair {
        base: 0xcccc_cccc_cccc_ccca,
        overlay: None,
    };
    let mair2_memory = aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    };
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_44ff,
        mair2: Some(0x44),
        stage1_permissions: Some(aarch64_vmsa::attrs::Stage1PermissionRegisters {
            privileged: d128_permissions,
            unprivileged: Some(d128_permissions),
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::NonShareable,
        output_pas: (),
    };
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT
        .with_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(8)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            mair2_memory,
        )
        .map_err(vmsa_test_harness::HarnessError::Attribute)?;
    let mut root = context.allocate_root()?;
    {
        let mut mapper = context.offline_mapper_d128_4k(&mut root, start, bits, bits)?;
        mapper.map_hardware_managed_page(
            ADDRESS,
            page.phys_addr(),
            D128HardwareManagedAttributes {
                permissions: D128MappingPermissions::ReadWrite,
                access_flag: false,
                dirty: false,
            },
        )?;
        mapper.map_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            &semantic_config,
            MAIR2_ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
                memory: mair2_memory,
                permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions {
                    privileged_data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
                    unprivileged_data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
                    privileged_execute: false,
                    unprivileged_execute: false,
                    privileged_gcs: false,
                    unprivileged_gcs: false,
                },
                pas: (),
                controls: aarch64_vmsa::attrs::SemanticVmsa128Stage1LeafControls {
                    bbm_nt: false,
                    dirty_state: aarch64_vmsa::attrs::DirtyState::Dirty,
                    shareability: aarch64_vmsa::attrs::Shareability::NonShareable,
                    access_flag: true,
                    global: true,
                    contiguous: false,
                    guarded: false,
                    protected: false,
                    software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
                },
            },
            aarch64_vmsa::attrs::SemanticVmsa128Stage1TableAttrs::default(),
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_lower_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa128,
            input_bits: bits,
            output_bits: bits,
            start_level: Some(start),
            asid: None,
            vmid: None,
            controls,
            stage1_memory,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    let walk = translation.inspect_walk_for::<
        LowerRegime,
        aarch64_vmsa::descriptor::Vmsa128,
        aarch64_vmsa::address::Granule4KiB,
    >(ADDRESS)?;
    if walk.leaf().and_then(|leaf| leaf.output) != Some(page.phys_addr()) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let d128_semantic = translation
        .inspect_semantic_for::<
            LowerRegime,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::attrs::VmsaAttributeCodec,
            _,
        >(ADDRESS, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if d128_semantic.controls.access_flag
        || d128_semantic.controls.dirty_state != aarch64_vmsa::attrs::DirtyState::Clean
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mair2_semantic = translation
        .inspect_semantic_for::<
            LowerRegime,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::attrs::VmsaAttributeCodec,
            _,
        >(MAIR2_ADDRESS, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if mair2_semantic.memory != mair2_memory {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(MAIR2_ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let initial = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if initial.access_flag || initial.dirty {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let updates = context.enable_lower_el1_hardware_updates(true)?;
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let after_read = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if !after_read.access_flag || after_read.dirty {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let result = vmsa_test_harness::expect_completed(context.lower_write_u64(ADDRESS, VALUE));
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let after_write = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if !after_write.access_flag || !after_write.dirty {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    drop(updates);
    translation
        .protect_d128_stage1_for::<LowerRegime>(ADDRESS, D128MappingPermissions::ReadExecute)?;
    let fault = vmsa_test_harness::expect_matching_fault(
        context.lower_write_u64(ADDRESS, VALUE),
        FaultMatcher::new(ExpectedFault::permission_write()).at_address(ADDRESS),
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    translation
        .protect_d128_stage1_for::<LowerRegime>(ADDRESS, D128MappingPermissions::ReadWrite)?;
    translation.remap_d128_stage1_for::<LowerRegime>(
        ADDRESS,
        replacement.phys_addr(),
        D128MappingPermissions::ReadWrite,
    )?;
    translation.tlbi(TlbiOperation::VirtualAddress(ADDRESS))?;
    let result =
        vmsa_test_harness::expect_value(context.lower_read_u64(ADDRESS), replacement_value);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let removed = translation.unmap_for::<
        LowerRegime,
        aarch64_vmsa::descriptor::Vmsa128,
        aarch64_vmsa::address::Granule4KiB,
    >(ADDRESS)?;
    if removed.output != replacement.phys_addr() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.tlbi(TlbiOperation::VirtualAddress(ADDRESS))?;
    let result = vmsa_test_harness::expect_matching_fault(
        context.lower_read_u64(ADDRESS),
        FaultMatcher::new(ExpectedFault::translation_read_stage1()).at_address(ADDRESS),
    );
    drop(translation);
    result
}

pub(super) fn active_d128_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid, d128_stage2_controls_4k,
        lpa2_el1_stage1_controls,
    };

    const VIRTUAL_ADDRESS: u64 = 0x5100_0000;
    const DATA_VALUE: u64 = 0x4431_3238_5332_4c49;
    let stage1_input = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_output = stage1_input;
    let d128_bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_start = vmsa_test_harness::stage1_start_level(
        TranslationFormat::Vmsa64Lpa2,
        Granule::Size16KiB,
        stage1_input,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let d128_start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let block = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls = lpa2_el1_stage1_controls(Granule::Size16KiB, stage1_input, stage1_output)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = d128_stage2_controls_4k(d128_bits, d128_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;

    let invalid_root = context.allocate_root_16k()?;
    let invalid_root_address = PhysicalAddress::new(invalid_root.phys_addr());
    if !matches!(
        context.install_lower_owned(
            invalid_root,
            TranslationSetup {
                root: invalid_root_address,
                stage: TranslationStage::Stage1,
                granule: Granule::Size16KiB,
                format: TranslationFormat::Vmsa64Lpa2,
                input_bits: stage1_input,
                output_bits: stage1_output,
                start_level: LookupLevel::new(-1),
                asid: Some(Asid(0x51)),
                vmid: None,
                controls: stage1_controls,
                stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
                regime: vmsa_test_harness::RegimeAttributes::Normal,
            },
        ),
        Err(vmsa_test_harness::HarnessError::InvalidState)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let page = context.allocate_granule(Granule::Size16KiB)?;
    let replacement = context.allocate_granule(Granule::Size16KiB)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, DATA_VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let replacement_value = DATA_VALUE ^ u64::MAX;
    if !matches!(
        context.write_u64(replacement.virtual_address() as u64, replacement_value),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut stage1_root = context.allocate_root_16k()?;
    let mut stage2_root = context.allocate_root()?;
    let physical_region = stage1_root.phys_addr() & !0x3fff_ffff;
    let target_region = physical_region ^ 0x4000_0000;
    let target_ipa = target_region | (page.phys_addr() - physical_region);
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::address::Granule16KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(
            &mut stage1_root,
            aarch64_vmsa::address::Level::L0,
            stage1_input.get(),
            stage1_output.get(),
        )?;
        mapper.map_leaf(
            VIRTUAL_ADDRESS,
            target_ipa,
            leaf,
            MappingAttributes::READ_WRITE,
        )?;
    }
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            Stage2Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >(
            &mut stage2_root,
            aarch64_vmsa::address::Level::NEG1,
            d128_bits.get(),
            d128_bits.get(),
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_stage2_leaf(physical_region, physical_region, block, recovery)?;
        mapper.map_stage2_leaf(0, 0, block, recovery)?;
        mapper.map_stage2_page(target_ipa, page.phys_addr(), MappingAttributes::READ_WRITE)?;
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size16KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: stage1_input,
        output_bits: stage1_output,
        start_level: Some(stage1_start),
        asid: Some(Asid(0x52)),
        vmid: None,
        controls: stage1_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa128,
        input_bits: d128_bits,
        output_bits: d128_bits,
        start_level: Some(d128_start),
        asid: None,
        vmid: Some(Vmid(0x53)),
        controls: stage2_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let result = vmsa_test_harness::expect_value(combined.read_u64(VIRTUAL_ADDRESS), DATA_VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let walk = combined.stage2_mut()?.inspect_walk_for::<
        Stage2Regime,
        aarch64_vmsa::descriptor::Vmsa128,
        aarch64_vmsa::address::Granule4KiB,
    >(target_ipa)?;
    if walk.leaf().and_then(|entry| entry.output) != Some(page.phys_addr()) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: Some(aarch64_vmsa::attrs::Stage2PermissionRegisters {
            s2pir_el2: 0x0000_0000_0000_fb8c,
            s2por_el1: None,
        }),
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    if combined
        .stage2_mut()?
        .inspect_semantic_for::<
            Stage2Regime,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::attrs::VmsaAttributeCodec,
            _,
        >(target_ipa, &config)?
        .is_none()
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    combined
        .stage2_mut()?
        .protect_d128_stage2_for::<Stage2Regime>(target_ipa, MappingAttributes::READ_ONLY)?;
    combined.tlbi(
        vmsa_test_harness::TlbiScope::InnerShareable,
        vmsa_test_harness::CombinedTlbiOperation::Stage2(
            vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(target_ipa),
        ),
    )?;
    let fault = vmsa_test_harness::expect_matching_fault(
        combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 1),
        vmsa_test_harness::FaultMatcher::new(
            vmsa_test_harness::ExpectedFault::permission_write_stage2(),
        )
        .at_address(VIRTUAL_ADDRESS),
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    combined
        .stage2_mut()?
        .remap_d128_stage2_for::<Stage2Regime>(
            target_ipa,
            replacement.phys_addr(),
            MappingAttributes::READ_WRITE,
        )?;
    combined.tlbi(
        vmsa_test_harness::TlbiScope::InnerShareable,
        vmsa_test_harness::CombinedTlbiOperation::Stage2(
            vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(target_ipa),
        ),
    )?;
    let result =
        vmsa_test_harness::expect_value(combined.read_u64(VIRTUAL_ADDRESS), replacement_value);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let removed = combined.stage2_mut()?.unmap_for::<
        Stage2Regime,
        aarch64_vmsa::descriptor::Vmsa128,
        aarch64_vmsa::address::Granule4KiB,
    >(target_ipa)?;
    if removed.output != replacement.phys_addr() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    combined.tlbi(
        vmsa_test_harness::TlbiScope::InnerShareable,
        vmsa_test_harness::CombinedTlbiOperation::Stage2(
            vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(target_ipa),
        ),
    )?;
    let fault = vmsa_test_harness::expect_matching_fault(
        combined.read_u64(VIRTUAL_ADDRESS),
        vmsa_test_harness::FaultMatcher::new(
            vmsa_test_harness::ExpectedFault::translation_read_stage2(),
        )
        .at_address(VIRTUAL_ADDRESS),
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    combined.restore()?;
    if !matches!(
        context.read_u64(page.virtual_address() as u64),
        vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}
