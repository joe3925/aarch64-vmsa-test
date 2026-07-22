use crate::{
    CurrentEnvironment, CurrentPas, CurrentRegime, CurrentTablePas, LowerRegime, Stage2Regime,
};
use vmsa_test_harness::{TestContext, TestResult};

pub fn lpa2_stage1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_stage1_case(
        context,
        crate::current_pas(),
        crate::current_table_pas(),
        true,
    )
}

pub fn lpa2_stage1_alternate_leaf_pas(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let Some(pas) = crate::alternate_current_pas() else {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    };
    lpa2_stage1_case(context, pas, crate::current_table_pas(), false)
}

pub fn lpa2_stage1_alternate_table_pas(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let Some(pas) = crate::alternate_current_table_pas() else {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    };
    lpa2_stage1_case(context, crate::current_pas(), pas, false)
}

fn lpa2_stage1_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf_pas: CurrentPas,
    table_pas: CurrentTablePas,
    expect_access: bool,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissionLimits, SoftwareMetadata,
        Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64Lpa2;
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    // Keep the semantic probe in a distinct level -1 branch from the low
    // payload text, stacks, vectors, and reporting state. A 4 KiB VMSA64
    // LPA2 walk uses bits [51:48] at level -1, so an address in the ordinary
    // 48-bit range would share the root descriptor with that infrastructure.
    // Table-PAS tests deliberately make the probe's walk inaccessible and
    // must leave the exception path under a different root descriptor.
    const ADDRESS: u64 = 0x1_0000_1000_0000;
    const VALUE: u64 = 0x4c50_4132_5345_4d41;
    let page = context.allocate_page()?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let config = LiveVmsaConfig {
        mair: 0x44,
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
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas: leaf_pas,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
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
        pas: table_pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let final_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    let offline;
    let sandbox;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<CurrentRegime, Granule4KiB, Vmsa64Lpa2>(
                &mut root,
                Level::new(-1),
                52,
                52,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::EnvironmentDetail(0x10))?;
        mapper
            .map_semantic_leaf::<VmsaAttributeCodec, _>(
                &config,
                ADDRESS,
                page.phys_addr(),
                final_level,
                leaf,
                table,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::EnvironmentDetail(0x11))?;
        offline = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(ADDRESS, &config)
            .map_err(|_| vmsa_test_harness::HarnessError::EnvironmentDetail(0x12))?
            .ok_or(vmsa_test_harness::HarnessError::EnvironmentDetail(0x16))?;
        if offline != leaf {
            return vmsa_test_harness::HarnessError::EnvironmentDetail(0x13).into();
        }
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            lpa2_stage1_case as *const () as u64,
            false,
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context
        .install_owned_in_sandbox(
            root,
            TranslationSetup {
                root: root_address,
                stage: TranslationStage::Stage1,
                granule: Granule::Size4KiB,
                format: TranslationFormat::Vmsa64Lpa2,
                input_bits: bits,
                output_bits: bits,
                start_level: Some(start),
                asid: None,
                vmid: None,
                controls: vmsa_test_harness::lpa2_current_stage1_controls_4k(bits, bits)
                    .ok_or(vmsa_test_harness::HarnessError::EnvironmentDetail(0x18))?,
                stage1_memory: vmsa_test_harness::Stage1MemoryControls::empty().with_raw_attribute(
                    vmsa_test_harness::MemoryAttributeSlot::new(0)
                        .ok_or(vmsa_test_harness::HarnessError::EnvironmentDetail(0x19))?,
                    0x44,
                ),
                regime: crate::current_regime_attributes(),
            },
            &sandbox,
        )
        .map_err(|_| vmsa_test_harness::HarnessError::EnvironmentDetail(0x1c))?;
    let live = translation
        .inspect_semantic_for::<CurrentRegime, Vmsa64Lpa2, Granule4KiB, VmsaAttributeCodec, _>(
            ADDRESS, &config,
        )
        .map_err(|_| vmsa_test_harness::HarnessError::EnvironmentDetail(0x14))?
        .ok_or(vmsa_test_harness::HarnessError::EnvironmentDetail(0x17))?;
    if live != offline {
        return vmsa_test_harness::HarnessError::EnvironmentDetail(0x15).into();
    }
    let result = if expect_access {
        vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
    } else {
        vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            crate::alternate_stage1_pas_fault(ADDRESS),
        )
    };
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::EnvironmentDetail(0x1a).into();
    }
    result
}

pub fn d128_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DirtyState, LiveVmsaConfig, MemoryAttributes,
        SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        SemanticVmsa128Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2MemoryAttributes,
        Stage2MemoryMode, Stage2Permission, Stage2PermissionRegisters, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::{Vmsa64Lpa2, Vmsa128};
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const ADDRESS: u64 = 0x5200_0000;
    const VALUE: u64 = 0x4431_3238_5332_5041;
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let block = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let page = context.allocate_page()?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let mut stage1_root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root()?;
    // A 4 KiB D128 walk consumes eight input bits per table level. An L1
    // block therefore covers 2^(12 + 2*8) = 256 MiB, rather than the 1 GiB
    // covered by an L1 block in the 64-bit descriptor format.
    const D128_L1_BYTES: u64 = 1 << 28;
    let physical_region = stage1_root.phys_addr() & !(D128_L1_BYTES - 1);
    let target_region = physical_region ^ D128_L1_BYTES;
    let target_ipa = target_region | (page.phys_addr() - physical_region);
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<LowerRegime, Granule4KiB, Vmsa64Lpa2>(
                &mut stage1_root,
                Level::NEG1,
                52,
                52,
            )?;
        mapper.map_leaf(ADDRESS, target_ipa, leaf, MappingAttributes::READ_WRITE)?;
    }
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
    let semantic = SemanticStage2LeafAttrs {
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
            access_flag: true,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let offline;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<Stage2Regime, Granule4KiB, Vmsa128>(
                &mut stage2_root,
                Level::NEG1,
                52,
                52,
            )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_stage2_leaf(physical_region, physical_region, block, recovery)?;
        mapper.map_stage2_leaf(0, 0, block, recovery)?;
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            target_ipa,
            page.phys_addr(),
            leaf,
            semantic,
            SemanticVmsa128Stage2TableAttrs::default(),
        )?;
        offline = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(target_ipa, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: bits,
        output_bits: bits,
        start_level: Some(stage1_start),
        asid: Some(Asid(0x61)),
        vmid: None,
        controls: vmsa_test_harness::lpa2_el1_stage1_controls_4k(bits, bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
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
        vmid: Some(Vmid(0x62)),
        controls: vmsa_test_harness::d128_stage2_controls_4k(bits, bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: crate::current_regime_attributes(),
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let installed = combined
        .stage2_mut()?
        .inspect_semantic_for::<Stage2Regime, Vmsa128, Granule4KiB, VmsaAttributeCodec, _>(
            target_ipa, &config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed != offline {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    vmsa_test_harness::expect_value(combined.read_u64(ADDRESS), VALUE)
}

pub fn lpa2_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage2LeafAttrs, SemanticVmsa64Stage2LeafControls,
        SemanticVmsa64Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2LeafPermissions,
        Stage2MemoryAttributes, Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64Lpa2;
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const ADDRESS: u64 = 0x5300_0000;
    const VALUE: u64 = 0x4c50_4132_5332_5041;
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let block = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let page = context.allocate_page()?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let mut stage1_root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root()?;
    let physical_region = stage1_root.phys_addr() & !0x3fff_ffff;
    let target_region = physical_region ^ 0x4000_0000;
    let target_ipa = target_region | (page.phys_addr() - physical_region);
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<LowerRegime, Granule4KiB, Vmsa64Lpa2>(
                &mut stage1_root,
                Level::NEG1,
                52,
                52,
            )?;
        mapper.map_leaf(ADDRESS, target_ipa, leaf, MappingAttributes::READ_WRITE)?;
    }
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: crate::stage2_pas(),
    };
    let semantic = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        }),
        permissions: Stage2LeafPermissions {
            data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: crate::stage2_pas(),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let offline;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<Stage2Regime, Granule4KiB, Vmsa64Lpa2>(
                &mut stage2_root,
                Level::NEG1,
                52,
                52,
            )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_leaf(physical_region, physical_region, block, recovery)?;
        mapper.map_leaf(0, 0, block, recovery)?;
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            target_ipa,
            page.phys_addr(),
            leaf,
            semantic,
            SemanticVmsa64Stage2TableAttrs::default(),
        )?;
        offline = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(target_ipa, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: bits,
        output_bits: bits,
        start_level: Some(start),
        asid: Some(Asid(0x63)),
        vmid: None,
        controls: vmsa_test_harness::lpa2_el1_stage1_controls_4k(bits, bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: crate::lower_regime_attributes(),
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: bits,
        output_bits: bits,
        start_level: Some(start),
        asid: None,
        vmid: Some(Vmid(0x64)),
        controls: vmsa_test_harness::lpa2_stage2_controls_4k(bits, bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: crate::current_regime_attributes(),
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let installed = combined
        .stage2_mut()?
        .inspect_semantic_for::<Stage2Regime, Vmsa64Lpa2, Granule4KiB, VmsaAttributeCodec, _>(
            target_ipa, &config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed != offline {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    vmsa_test_harness::expect_value(combined.read_u64(ADDRESS), VALUE)
}
