use crate::{CurrentEnvironment, CurrentRegime, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
enum UpdateObservation {
    AccessFlagDisabled,
    AccessFlagEnabled,
    DirtyDisabled,
    DirtyEnabled,
}

fn vmsa64_update_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    observation: UpdateObservation,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience,
        SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticVmsa64Stage1LeafControls,
        SemanticVmsa64Stage1TableControls, Shareability, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits, SoftwareMetadata, Stage2MemoryMode,
        VmsaAttributeCodec,
    };
    use vmsa_test_harness::{
        AccessKind, AddressBits, ExpectedFault, FaultClass, FaultMatcher, FaultStage, FaultStatus,
        Granule, LookupLevel, PhysicalAddress, TranslationControls, TranslationFormat,
        TranslationSetup, TranslationStage,
    };

    const ADDRESS: u64 = 0x6500_0000;
    const VALUE: u64 = 0x4841_4844_5550_4454;
    let access_flag = !matches!(
        observation,
        UpdateObservation::AccessFlagDisabled | UpdateObservation::AccessFlagEnabled
    );
    let dirty_managed = matches!(
        observation,
        UpdateObservation::DirtyDisabled | UpdateObservation::DirtyEnabled
    );
    let config = LiveVmsaConfig {
        mair: 0x0000_00ff,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: crate::current_config_pas(),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
            outer: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
        },
        permissions: SinglePrivilegeLeafPermissions {
            data: if dirty_managed {
                DataAccess::ReadOnly
            } else {
                DataAccess::ReadWrite
            },
            execute: false,
        },
        pas: crate::current_pas(),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag,
            global: true,
            dirty_management: if dirty_managed {
                DirtyBitManagement::HardwareManaged
            } else {
                DirtyBitManagement::SoftwareManaged
            },
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: crate::current_table_pas(),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let page = context.allocate_page()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
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
            regime: crate::current_regime_attributes(),
        },
    )?;
    translation.map_semantic_for::<
        CurrentRegime,
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        VmsaAttributeCodec,
        _,
    >(
        &config,
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let installed = translation
        .inspect_semantic_for::<
            CurrentRegime,
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::address::Granule4KiB,
            VmsaAttributeCodec,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed != leaf {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let result = match observation {
        UpdateObservation::AccessFlagDisabled => vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            FaultMatcher::new(ExpectedFault {
                status: Some(FaultStatus::AccessFlag),
                access: Some(AccessKind::Read),
                stage: Some(FaultStage::Stage1),
                level: LookupLevel::new(3),
            })
            .with_class(FaultClass::DataAbort)
            .at_address(ADDRESS)
            .with_ipa(None),
        ),
        UpdateObservation::AccessFlagEnabled => {
            let _updates = context.enable_hardware_updates(false)?;
            let access = vmsa_test_harness::expect_completed(context.read_u64(ADDRESS));
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = translation
                .inspect_semantic_for::<
                    CurrentRegime,
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.access_flag {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyDisabled => {
            let _updates = context.enable_hardware_updates(false)?;
            let fault = vmsa_test_harness::expect_matching_fault(
                context.write_u64(ADDRESS, VALUE),
                FaultMatcher::new(ExpectedFault::permission_write())
                    .with_class(FaultClass::DataAbort)
                    .at_address(ADDRESS),
            );
            if !matches!(fault, TestResult::Pass) {
                return fault;
            }
            let after = translation
                .inspect_semantic_for::<
                    CurrentRegime,
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.permissions.data == DataAccess::ReadOnly {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyEnabled => {
            let _updates = context.enable_hardware_updates(true)?;
            let access = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, VALUE));
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = translation
                .inspect_semantic_for::<
                    CurrentRegime,
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.permissions.data == DataAccess::ReadWrite {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
    };
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    translation.restore()?;
    TestResult::Pass
}

fn d128_update_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    observation: UpdateObservation,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess, DirtyState,
        LiveVmsaConfig, MemoryAttributes, MemoryTransience, SemanticStage1LeafAttrs,
        SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs, Shareability,
        SoftwareMetadata, Stage1EffectivePermissions, Stage1PermissionRegisterPair,
        Stage1PermissionRegisters, Stage2MemoryMode, VmsaAttributeCodec,
    };
    use vmsa_test_harness::{
        AccessKind, AddressBits, ExpectedFault, FaultClass, FaultMatcher, FaultStage, FaultStatus,
        Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    const ADDRESS: u64 = 0x6510_0000;
    const VALUE: u64 = 0x4431_3238_5550_4454;
    let access_flag = !matches!(
        observation,
        UpdateObservation::AccessFlagDisabled | UpdateObservation::AccessFlagEnabled
    );
    let permission_pair = Stage1PermissionRegisterPair {
        base: 0xcccc_cccc_cccc_ccca,
        overlay: None,
    };
    let config = LiveVmsaConfig {
        mair: 0x0000_00ff,
        mair2: None,
        stage1_permissions: Some(Stage1PermissionRegisters {
            privileged: permission_pair,
            unprivileged: Some(permission_pair),
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::NonShareable,
        output_pas: crate::lower_pas(),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
            outer: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
        },
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: crate::lower_pas(),
        controls: SemanticVmsa128Stage1LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::NonShareable,
            access_flag,
            global: true,
            contiguous: false,
            guarded: false,
            protected: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            crate::LowerRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >(
            &mut root,
            aarch64_vmsa::address::Level::new(start.get()),
            bits.get(),
            bits.get(),
        )?;
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            SemanticVmsa128Stage1TableAttrs {
                table_nt: false,
                access_flag: false,
                disch: false,
                protected: false,
                pas: crate::lower_pas(),
                software: SoftwareMetadata::new(0),
            },
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
            controls: vmsa_test_harness::d128_el1_stage1_controls_4k(bits, bits)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::lower_regime_attributes(),
        },
    )?;
    let installed = translation
        .inspect_semantic_for::<
            LowerRegime,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            VmsaAttributeCodec,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed != leaf {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let result = match observation {
        UpdateObservation::AccessFlagDisabled => vmsa_test_harness::expect_matching_fault(
            context.lower_read_u64(ADDRESS),
            FaultMatcher::new(ExpectedFault {
                status: Some(FaultStatus::AccessFlag),
                access: Some(AccessKind::Read),
                stage: Some(FaultStage::Stage1),
                level: LookupLevel::new(3),
            })
            .with_class(FaultClass::DataAbort)
            .at_address(ADDRESS),
        ),
        UpdateObservation::AccessFlagEnabled => {
            let _updates = context.enable_lower_el1_hardware_updates(false)?;
            let access = vmsa_test_harness::expect_completed(context.lower_read_u64(ADDRESS));
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = translation
                .inspect_semantic_for::<
                    LowerRegime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.access_flag {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyDisabled => {
            let _updates = context.enable_lower_el1_hardware_updates(false)?;
            let fault = vmsa_test_harness::expect_matching_fault(
                context.lower_write_u64(ADDRESS, VALUE),
                FaultMatcher::new(ExpectedFault::permission_write())
                    .with_class(FaultClass::DataAbort)
                    .at_address(ADDRESS),
            );
            if !matches!(fault, TestResult::Pass) {
                return fault;
            }
            let after = translation
                .inspect_semantic_for::<
                    LowerRegime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.dirty_state == DirtyState::Clean {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyEnabled => {
            let _updates = context.enable_lower_el1_hardware_updates(true)?;
            let access =
                vmsa_test_harness::expect_completed(context.lower_write_u64(ADDRESS, VALUE));
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = translation
                .inspect_semantic_for::<
                    LowerRegime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(ADDRESS, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.dirty_state == DirtyState::Dirty {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
    };
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    translation.restore()?;
    TestResult::Pass
}

macro_rules! update_cases {
    ($vmsa:ident, $d128:ident, $observation:ident) => {
        pub(super) fn $vmsa(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            vmsa64_update_case(context, UpdateObservation::$observation)
        }
        pub(super) fn $d128(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            d128_update_case(context, UpdateObservation::$observation)
        }
    };
}

update_cases!(vmsa64_af_disabled, d128_af_disabled, AccessFlagDisabled);
update_cases!(vmsa64_af_enabled, d128_af_enabled, AccessFlagEnabled);
update_cases!(vmsa64_dirty_disabled, d128_dirty_disabled, DirtyDisabled);
update_cases!(vmsa64_dirty_enabled, d128_dirty_enabled, DirtyEnabled);

fn d128_stage2_update_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    observation: UpdateObservation,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DirtyState, LiveVmsaConfig, MemoryAttributes,
        SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        SemanticVmsa128Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2MemoryAttributes,
        Stage2MemoryMode, Stage2Permission, Stage2PermissionRegisters, VmsaAttributeCodec,
    };
    use vmsa_test_harness::{
        AccessKind, AddressBits, Asid, ExpectedFault, FaultClass, FaultMatcher, FaultStage,
        FaultStatus, Granule, LookupLevel, MappingAttributes, PhysicalAddress, TranslationFormat,
        TranslationSetup, TranslationStage, Vmid,
    };

    const ADDRESS: u64 = 0x6520_0000;
    const VALUE: u64 = 0x5332_4431_3238_5550;
    let access_flag = !matches!(
        observation,
        UpdateObservation::AccessFlagDisabled | UpdateObservation::AccessFlagEnabled
    );
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: Some(Stage2PermissionRegisters {
            s2pir_el2: 0x0000_0000_0000_fb8c,
            s2por_el1: None,
        }),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: crate::stage2_pas(),
    };
    let leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        }),
        permissions: Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: crate::stage2_pas(),
        controls: SemanticVmsa128Stage2LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Clean,
            shareability: Shareability::InnerShareable,
            access_flag,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_start = LookupLevel::new(0).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let recovery_level =
        LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls =
        vmsa_test_harness::lpa2_el1_stage1_controls(Granule::Size16KiB, bits, bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = vmsa_test_harness::d128_stage2_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let page = context.allocate_granule(Granule::Size16KiB)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut stage1_root = context.allocate_root_16k()?;
    let mut stage2_root = context.allocate_root()?;
    let recovery_size = aarch64_vmsa::table::TableGeometry::<
        aarch64_vmsa::descriptor::Vmsa128,
        aarch64_vmsa::address::Granule4KiB,
    >::offset_at_level_raw(u64::MAX, aarch64_vmsa::address::Level::L1)
    .and_then(|mask| mask.checked_add(1))
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let physical_region = stage1_root.phys_addr() & !(recovery_size - 1);
    let target_region = physical_region ^ recovery_size;
    let target_ipa = target_region | (page.phys_addr() - physical_region);
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::address::Granule16KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(
            &mut stage1_root,
            aarch64_vmsa::address::Level::L0,
            bits.get(),
            bits.get(),
        )?;
        mapper.map_leaf(
            ADDRESS,
            target_ipa,
            leaf_level,
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
            bits.get(),
            bits.get(),
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_stage2_leaf(physical_region, physical_region, recovery_level, recovery)?;
        if physical_region != 0 {
            mapper.map_stage2_leaf(0, 0, recovery_level, recovery)?;
        }
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            target_ipa,
            page.phys_addr(),
            leaf_level,
            leaf,
            SemanticVmsa128Stage2TableAttrs::default(),
        )?;
        let installed = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(target_ipa, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if installed != leaf {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size16KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: bits,
        output_bits: bits,
        start_level: Some(stage1_start),
        asid: Some(Asid(0x58)),
        vmid: None,
        controls: stage1_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: crate::lower_regime_attributes(),
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa128,
        input_bits: bits,
        output_bits: bits,
        start_level: Some(stage2_start),
        asid: None,
        vmid: Some(Vmid(0x59)),
        controls: stage2_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: crate::current_regime_attributes(),
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let before = combined
        .stage2_mut()?
        .inspect_semantic_for::<
            Stage2Regime,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            VmsaAttributeCodec,
            _,
        >(target_ipa, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if before != leaf {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let result = match observation {
        UpdateObservation::AccessFlagDisabled => vmsa_test_harness::expect_matching_fault(
            combined.read_u64(ADDRESS),
            FaultMatcher::new(ExpectedFault {
                status: Some(FaultStatus::AccessFlag),
                access: Some(AccessKind::Read),
                stage: Some(FaultStage::Stage2),
                level: Some(leaf_level),
            })
            .with_class(FaultClass::DataAbort)
            .at_address(ADDRESS)
            .with_ipa(Some(target_ipa)),
        ),
        UpdateObservation::AccessFlagEnabled => {
            let updates = context.enable_stage2_hardware_updates(false)?;
            let access = vmsa_test_harness::expect_value(combined.read_u64(ADDRESS), VALUE);
            drop(updates);
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = combined
                .stage2_mut()?
                .inspect_semantic_for::<
                    Stage2Regime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(target_ipa, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.access_flag {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyDisabled => {
            let updates = context.enable_stage2_hardware_updates(false)?;
            let fault = vmsa_test_harness::expect_matching_fault(
                combined.write_u64(ADDRESS, VALUE),
                FaultMatcher::new(ExpectedFault {
                    status: Some(FaultStatus::Permission),
                    access: Some(AccessKind::Write),
                    stage: Some(FaultStage::Stage2),
                    level: Some(leaf_level),
                })
                .with_class(FaultClass::DataAbort)
                .at_address(ADDRESS)
                .with_ipa(Some(target_ipa)),
            );
            drop(updates);
            if !matches!(fault, TestResult::Pass) {
                return fault;
            }
            let after = combined
                .stage2_mut()?
                .inspect_semantic_for::<
                    Stage2Regime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(target_ipa, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.dirty_state == DirtyState::Clean {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
        UpdateObservation::DirtyEnabled => {
            let updates = context.enable_stage2_hardware_updates(true)?;
            let access = vmsa_test_harness::expect_completed(combined.write_u64(ADDRESS, VALUE));
            drop(updates);
            if !matches!(access, TestResult::Pass) {
                return access;
            }
            let after = combined
                .stage2_mut()?
                .inspect_semantic_for::<
                    Stage2Regime,
                    aarch64_vmsa::descriptor::Vmsa128,
                    aarch64_vmsa::address::Granule4KiB,
                    VmsaAttributeCodec,
                    _,
                >(target_ipa, &config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if after.controls.dirty_state == DirtyState::Dirty {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
    };
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    combined.restore()?;
    TestResult::Pass
}

macro_rules! stage2_update_case {
    ($name:ident, $observation:ident) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            d128_stage2_update_case(context, UpdateObservation::$observation)
        }
    };
}

stage2_update_case!(d128_stage2_af_disabled, AccessFlagDisabled);
stage2_update_case!(d128_stage2_af_enabled, AccessFlagEnabled);
stage2_update_case!(d128_stage2_dirty_disabled, DirtyDisabled);
stage2_update_case!(d128_stage2_dirty_enabled, DirtyEnabled);
