use crate::{CurrentEnvironment, CurrentRegime, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
pub(crate) struct ActiveGeometry {
    pub(crate) granule: vmsa_test_harness::Granule,
    pub(crate) format: vmsa_test_harness::TranslationFormat,
    pub(crate) start_level: aarch64_vmsa::address::Level,
    pub(crate) input_width: u8,
    pub(crate) output_width: u8,
    pub(crate) controls: vmsa_test_harness::TranslationControls,
}

#[derive(Clone, Copy)]
pub(crate) enum Stage1Observation {
    Access,
    AddressTranslation,
}

pub(crate) fn active_stage1_leaf_case<F, G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    geometry: ActiveGeometry,
    leaf_level: aarch64_vmsa::address::Level,
    input_hint: u64,
    observation: Stage1Observation,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    F: vmsa_test_harness::adapter::TestFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>
        + aarch64_vmsa::regime::HasRegimeLayout<CurrentRegime, G>,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<CurrentRegime, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                G,
                LeafFields = crate::LeafFieldsOf<
                    aarch64_vmsa::config::format::Vmsa64,
                    CurrentRegime,
                    G,
                >,
                TableFields = crate::TableFieldsOf<
                    aarch64_vmsa::config::format::Vmsa64,
                    CurrentRegime,
                    G,
                >,
            >,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>: Copy + PartialEq,
    F: vmsa_test_harness::AttributeCodecCompat<
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::CurrentPas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::Stage1Permissions,
                crate::CurrentPas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            RawLeaf = crate::LeafFieldsOf<F, CurrentRegime, G>,
            RawTable = crate::TableFieldsOf<F, CurrentRegime, G>,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, MappingAttributes, PhysicalAddress};

    const VALUE: u64 = 0x4c45_4146_4341_5345;
    let page = context.allocate_granule(geometry.granule)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64 + 8, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let input_bits = AddressBits::new(geometry.input_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(geometry.output_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let covered_size =
        aarch64_vmsa::table::TableGeometry::<F, G>::offset_at_level_raw(u64::MAX, leaf_level)
            .and_then(|mask| mask.checked_add(1))
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let target_physical = page
        .phys_addr()
        .checked_add(8)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_base = target_physical & !(covered_size - 1);
    let offset = target_physical - output_base;
    if offset == 0 || output_base.checked_add(offset) != Some(target_physical) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let input_base = input_hint & !(covered_size - 1);
    let access_address = input_base
        .checked_add(offset)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(geometry.start_level.as_i8())
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(leaf_level.as_i8())
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<CurrentRegime, G, F>(
            &mut root,
            geometry.start_level,
            input_bits.get(),
            output_bits.get(),
        )?;
        mapper
            .map_attributes_leaf_exact(
                input_base,
                output_base,
                leaf_level.as_i8(),
                MappingAttributes::READ_WRITE,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            active_stage1_leaf_case::<F, G> as *const () as u64,
            false,
        )?;
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
            start_level: Some(start),
            asid: None,
            vmid: None,
            controls: geometry.controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::current_regime_attributes(),
        },
        &sandbox,
    )?;
    let result = match observation {
        Stage1Observation::Access => {
            vmsa_test_harness::expect_value(context.read_u64(access_address), VALUE)
        }
        Stage1Observation::AddressTranslation => match context.translate_current_stage1(
            access_address,
            vmsa_test_harness::TranslationQueryAccess::Read,
        ) {
            vmsa_test_harness::TranslationQueryResult::Success {
                physical_address, ..
            } if physical_address == target_physical => TestResult::Pass,
            vmsa_test_harness::TranslationQueryResult::Success {
                physical_address, ..
            } => TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongValue,
                expected: target_physical,
                actual: physical_address,
            }),
            _ => vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into(),
        },
    };
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::Cleanup.into();
    }
    result
}

pub(crate) fn active_granule<F, G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    geometry: ActiveGeometry,
    malformed_terminal: bool,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    F: vmsa_test_harness::adapter::TestFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>
        + aarch64_vmsa::regime::HasRegimeLayout<CurrentRegime, G>,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<CurrentRegime, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                G,
                LeafFields = crate::LeafFieldsOf<
                    aarch64_vmsa::config::format::Vmsa64,
                    CurrentRegime,
                    G,
                >,
                TableFields = crate::TableFieldsOf<
                    aarch64_vmsa::config::format::Vmsa64,
                    CurrentRegime,
                    G,
                >,
            >,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>: Copy + PartialEq,
    F: vmsa_test_harness::AttributeCodecCompat<
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::CurrentPas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::Stage1Permissions,
                crate::CurrentPas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::SinglePrivilegeTableRestrictions,
                crate::CurrentTablePas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
            >,
            RawLeaf = crate::LeafFieldsOf<F, CurrentRegime, G>,
            RawTable = crate::TableFieldsOf<F, CurrentRegime, G>,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, PhysicalAddress};

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
    let memory = aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    };
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: crate::current_config_pas(),
    };
    let semantic_leaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
        memory,
        permissions: aarch64_vmsa::attrs::Stage1Permissions::new(
            aarch64_vmsa::attrs::DataRights::ReadWrite,
            aarch64_vmsa::attrs::DataRights::None,
            false,
            false,
            false,
            false,
        ),
        pas: crate::current_pas(),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls {
            shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            ),
            contiguous: false,
            guarded: false,
            software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
        },
    };
    let semantic_table = aarch64_vmsa::attrs::SemanticStage1TableAttrs {
        restrictions: aarch64_vmsa::attrs::SinglePrivilegeTableRestrictions {
            data_limit: aarch64_vmsa::attrs::DataRights::ReadWrite,
            execute_limit: true,
        },
        pas: crate::current_table_pas(),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls::default(),
    };
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<CurrentRegime, G, F>(
            &mut root,
            geometry.start_level,
            input_bits.get(),
            output_bits.get(),
        )?;
        mapper.map_semantic_leaf::<_>(
            &semantic_config,
            ADDRESS,
            page.phys_addr(),
            leaf_level,
            semantic_leaf,
            semantic_table,
        )?;
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            active_granule::<F, G> as *const () as u64,
            false,
        )?;
        if malformed_terminal {
            let mut replacement = mapper
                .inspect_walk(ADDRESS)?
                .leaf()
                .and_then(|leaf| leaf.raw)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            replacement.low &= !0b10;
            mapper
                .isolated_malformed_table()
                .replace_terminal_descriptor(ADDRESS, replacement)?;
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
            regime: crate::current_regime_attributes(),
        },
        &sandbox,
    )?;
    if !translation.transition_sandbox_active(&sandbox) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        drop(translation);
        if !context.transition_sandbox_restored(&sandbox) {
            return vmsa_test_harness::HarnessError::Cleanup.into();
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
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    translation.protect::<F, G>(ADDRESS, vmsa_test_harness::MappingAttributes::READ_ONLY)?;
    let write_fault = vmsa_test_harness::expect_matching_fault(
        context.write_u64(ADDRESS, VALUE.wrapping_add(1)),
        vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault::permission_write())
            .at_address(ADDRESS),
    );
    if !matches!(write_fault, TestResult::Pass) {
        return write_fault;
    }
    translation.protect::<F, G>(ADDRESS, vmsa_test_harness::MappingAttributes::READ_WRITE)?;
    let restored = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::Cleanup.into();
    }
    restored
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
    active_granule::<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule16KiB,
    >(
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
    active_granule::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
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
    active_granule::<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule64KiB,
    >(
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
    let controls = vmsa_test_harness::lpa2_current_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_granule::<
        aarch64_vmsa::config::format::Vmsa64Lpa2,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(
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

fn vmsa64_stage1_leaf<G: vmsa_test_harness::adapter::TestGranule>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    root: vmsa_test_harness::RootTableMemory,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    input_hint: u64,
    observation: Stage1Observation,
) -> TestResult
where
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>: Copy + PartialEq,
    aarch64_vmsa::config::format::Vmsa64: vmsa_test_harness::AttributeCodecCompat<
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::CurrentPas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::Stage1Permissions,
                crate::CurrentPas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            RawLeaf = crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>,
            RawTable = crate::TableFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>,
        >,
{
    let bits = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(granule, bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_stage1_leaf_case::<aarch64_vmsa::config::format::Vmsa64, G>(
        context,
        root,
        ActiveGeometry {
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level,
            input_width: 48,
            output_width: 48,
            controls,
        },
        leaf_level,
        input_hint,
        observation,
    )
}

fn vmsa64_4k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root()?;
    vmsa64_stage1_leaf::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::L0,
        leaf,
        1u64 << 46,
        observation,
    )
}

fn vmsa64_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    vmsa64_stage1_leaf::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size16KiB,
        aarch64_vmsa::address::Level::L0,
        leaf,
        1u64 << 46,
        observation,
    )
}

fn vmsa64_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_64k()?;
    vmsa64_stage1_leaf::<aarch64_vmsa::config::granule::Granule64KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size64KiB,
        aarch64_vmsa::address::Level::L1,
        leaf,
        1u64 << 46,
        observation,
    )
}

macro_rules! stage1_observation_pair {
    ($access:ident, $at:ident, $helper:ident, $level:expr) => {
        pub(super) fn $access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(context, $level, Stage1Observation::Access)
        }
        pub(super) fn $at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(context, $level, Stage1Observation::AddressTranslation)
        }
    };
}

stage1_observation_pair!(
    active_vmsa64_4k_l1,
    active_vmsa64_4k_l1_at,
    vmsa64_4k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_vmsa64_4k_l2,
    active_vmsa64_4k_l2_at,
    vmsa64_4k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_vmsa64_4k_l3,
    active_vmsa64_4k_l3_at,
    vmsa64_4k_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_vmsa64_16k_l2,
    active_vmsa64_16k_l2_at,
    vmsa64_16k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_vmsa64_16k_l3,
    active_vmsa64_16k_l3_at,
    vmsa64_16k_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_vmsa64_64k_l2,
    active_vmsa64_64k_l2_at,
    vmsa64_64k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_vmsa64_64k_l3,
    active_vmsa64_64k_l3_at,
    vmsa64_64k_leaf,
    aarch64_vmsa::address::Level::L3
);

fn lpa2_4k_stage1_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf_level: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_current_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
    active_stage1_leaf_case::<
        aarch64_vmsa::config::format::Vmsa64Lpa2,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(
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
        leaf_level,
        1u64 << 50,
        observation,
    )
}

fn lpa2_stage1_leaf<G: vmsa_test_harness::adapter::TestGranule>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    root: vmsa_test_harness::RootTableMemory,
    granule: vmsa_test_harness::Granule,
    leaf_level: aarch64_vmsa::address::Level,
    input_hint: u64,
    observation: Stage1Observation,
) -> TestResult
where
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    aarch64_vmsa::config::format::Vmsa64Lpa2: aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>
        + aarch64_vmsa::regime::HasRegimeLayout<CurrentRegime, G>,
    <aarch64_vmsa::config::format::Vmsa64Lpa2 as aarch64_vmsa::regime::HasRegimeLayout<
        CurrentRegime,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            G,
            LeafFields = crate::LeafFieldsOf<
                aarch64_vmsa::config::format::Vmsa64,
                CurrentRegime,
                G,
            >,
            TableFields = crate::TableFieldsOf<
                aarch64_vmsa::config::format::Vmsa64,
                CurrentRegime,
                G,
            >,
        >,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, CurrentRegime, G>: Copy + PartialEq,
    aarch64_vmsa::config::format::Vmsa64Lpa2: vmsa_test_harness::AttributeCodecCompat<
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::CurrentPas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::Stage1Permissions,
                crate::CurrentPas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            RawLeaf = crate::LeafFieldsOf<
                aarch64_vmsa::config::format::Vmsa64Lpa2,
                CurrentRegime,
                G,
            >,
            RawTable = crate::TableFieldsOf<
                aarch64_vmsa::config::format::Vmsa64Lpa2,
                CurrentRegime,
                G,
            >,
        >,
{
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_current_stage1_controls(granule, bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = match granule {
        vmsa_test_harness::Granule::Size4KiB => aarch64_vmsa::address::Level::NEG1,
        vmsa_test_harness::Granule::Size16KiB => aarch64_vmsa::address::Level::L0,
        vmsa_test_harness::Granule::Size64KiB => aarch64_vmsa::address::Level::L1,
    };
    active_stage1_leaf_case::<aarch64_vmsa::config::format::Vmsa64Lpa2, G>(
        context,
        root,
        ActiveGeometry {
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
            start_level,
            input_width: 52,
            output_width: 52,
            controls,
        },
        leaf_level,
        input_hint,
        observation,
    )
}

fn lpa2_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    lpa2_stage1_leaf::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size16KiB,
        leaf,
        1u64 << 50,
        observation,
    )
}

fn lpa2_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_64k()?;
    lpa2_stage1_leaf::<aarch64_vmsa::config::granule::Granule64KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size64KiB,
        leaf,
        1u64 << 50,
        observation,
    )
}

stage1_observation_pair!(
    active_lpa2_4k_l0,
    active_lpa2_4k_l0_at,
    lpa2_4k_stage1_leaf,
    aarch64_vmsa::address::Level::L0
);
stage1_observation_pair!(
    active_lpa2_4k_l1,
    active_lpa2_4k_l1_at,
    lpa2_4k_stage1_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_lpa2_4k_l2,
    active_lpa2_4k_l2_at,
    lpa2_4k_stage1_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_lpa2_4k_l3,
    active_lpa2_4k_l3_at,
    lpa2_4k_stage1_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_lpa2_16k_l1,
    active_lpa2_16k_l1_at,
    lpa2_16k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_lpa2_16k_l2,
    active_lpa2_16k_l2_at,
    lpa2_16k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_lpa2_16k_l3,
    active_lpa2_16k_l3_at,
    lpa2_16k_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_lpa2_64k_l1,
    active_lpa2_64k_l1_at,
    lpa2_64k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_lpa2_64k_l2,
    active_lpa2_64k_l2_at,
    lpa2_64k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_lpa2_64k_l3,
    active_lpa2_64k_l3_at,
    lpa2_64k_leaf,
    aarch64_vmsa::address::Level::L3
);

fn active_d128_stage1_leaf<G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
    maximum_skl: bool,
    skl_attributes: Option<vmsa_test_harness::D128HardwareManagedAttributes>,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    LowerRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa128:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::config::format::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            G,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, PhysicalAddress};

    const VALUE: u64 = 0x4431_3238_424c_4f43;
    let page = context.allocate_granule(granule)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64 + 8, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let covered_size =
        aarch64_vmsa::table::TableGeometry::<aarch64_vmsa::config::format::Vmsa128, G>::offset_at_level_raw(
            u64::MAX,
            leaf_level,
        )
        .and_then(|mask| mask.checked_add(1))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let target_physical = page
        .phys_addr()
        .checked_add(8)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_base = target_physical & !(covered_size - 1);
    let offset = target_physical - output_base;
    if offset == 0 || output_base.checked_add(offset) != Some(target_physical) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let input_base = (1u64 << 50) & !(covered_size - 1);
    let access_address = input_base
        .checked_add(offset)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            G,
            aarch64_vmsa::config::format::Vmsa128,
        >(
            &mut root,
            start_level,
            bits.get(),
            bits.get(),
        )?;
        if maximum_skl {
            if let Some(attributes) = skl_attributes {
                mapper
                    .map_d128_hardware_managed_leaf_maximum_skl_exact(
                        input_base,
                        output_base,
                        LookupLevel::new(leaf_level.as_i8())
                            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                        attributes,
                    )
                    .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
            } else {
                mapper
                    .map_d128_leaf_maximum_skl_exact(
                        input_base,
                        output_base,
                        LookupLevel::new(leaf_level.as_i8())
                            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                    )
                    .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
            }
        } else {
            mapper
                .map_hardware_managed_leaf_exact(
                    input_base,
                    output_base,
                    leaf_level.as_i8(),
                    vmsa_test_harness::D128HardwareManagedAttributes {
                        permissions: vmsa_test_harness::D128MappingPermissions::ReadWrite,
                        access_flag: true,
                        dirty: true,
                    },
                )
                .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        }
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let controls = vmsa_test_harness::d128_el1_stage1_controls(granule, bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut translation = context.install_lower_owned(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa128,
            input_bits: bits,
            output_bits: bits,
            start_level: LookupLevel::new(start_level.as_i8()),
            asid: None,
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::lower_regime_attributes(),
        },
    )?;
    let result = if let Some(attributes) = skl_attributes {
        let expected = if !attributes.access_flag {
            vmsa_test_harness::ExpectedFault {
                status: Some(vmsa_test_harness::FaultStatus::AccessFlag),
                access: Some(vmsa_test_harness::AccessKind::Read),
                stage: Some(vmsa_test_harness::FaultStage::Stage1),
                level: LookupLevel::new(leaf_level.as_i8()),
            }
        } else {
            vmsa_test_harness::ExpectedFault {
                status: Some(vmsa_test_harness::FaultStatus::Permission),
                access: Some(vmsa_test_harness::AccessKind::Write),
                stage: Some(vmsa_test_harness::FaultStage::Stage1),
                level: LookupLevel::new(leaf_level.as_i8()),
            }
        };
        let access = if attributes.access_flag {
            context.lower_write_u64(access_address, VALUE.wrapping_add(1))
        } else {
            context.lower_read_u64(access_address)
        };
        vmsa_test_harness::expect_fault(access, expected)
    } else {
        match observation {
            Stage1Observation::Access => {
                vmsa_test_harness::expect_value(context.lower_read_u64(access_address), VALUE)
            }
            Stage1Observation::AddressTranslation => match context
                .translate_lower_stage1_d128_raw(
                    access_address,
                    vmsa_test_harness::TranslationQueryAccess::Read,
                )
                .map(|(low, high)| {
                    vmsa_test_harness::TranslationQueryResult::from_raw_par128_for_test(
                        access_address,
                        low,
                        high,
                    )
                }) {
                Some(vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address,
                    ..
                }) if physical_address == target_physical => TestResult::Pass,
                Some(vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address,
                    ..
                }) => TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target_physical,
                    actual: physical_address,
                }),
                Some(vmsa_test_harness::TranslationQueryResult::Fault { raw, .. }) => {
                    TestResult::Fail(vmsa_test_harness::TestFailure {
                        kind: vmsa_test_harness::FailureKind::WrongValue,
                        expected: target_physical,
                        actual: raw,
                    })
                }
                Some(vmsa_test_harness::TranslationQueryResult::Unsupported) | None => {
                    vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into()
                }
            },
        }
    };
    drop(translation);
    result
}

fn d128_4k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::NEG1,
        leaf,
        observation,
        false,
        None,
    )
}

fn d128_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size16KiB,
        aarch64_vmsa::address::Level::L0,
        leaf,
        observation,
        false,
        None,
    )
}

fn d128_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Stage1Observation,
) -> TestResult {
    let root = context.allocate_root_64k()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule64KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size64KiB,
        aarch64_vmsa::address::Level::L1,
        leaf,
        observation,
        false,
        None,
    )
}

pub(super) fn active_d128_4k_max_skl(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::NEG1,
        aarch64_vmsa::address::Level::L3,
        Stage1Observation::Access,
        true,
        None,
    )
}

pub(super) fn active_d128_4k_skl1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::NEG1,
        aarch64_vmsa::address::Level::L1,
        Stage1Observation::Access,
        true,
        None,
    )
}

pub(super) fn active_d128_4k_skl2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::NEG1,
        aarch64_vmsa::address::Level::L2,
        Stage1Observation::Access,
        true,
        None,
    )
}

pub(super) fn active_d128_16k_max_skl(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size16KiB,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L3,
        Stage1Observation::Access,
        true,
        None,
    )
}

pub(super) fn active_d128_16k_skl1(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size16KiB,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L2,
        Stage1Observation::Access,
        true,
        None,
    )
}

fn d128_skl1_fault<G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    root: vmsa_test_harness::RootTableMemory,
    start: aarch64_vmsa::address::Level,
    leaf: aarch64_vmsa::address::Level,
    attributes: vmsa_test_harness::D128HardwareManagedAttributes,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    LowerRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa128:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::config::format::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            G,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    active_d128_stage1_leaf::<G>(
        context,
        root,
        granule,
        start,
        leaf,
        Stage1Observation::Access,
        true,
        Some(attributes),
    )
}

pub(super) fn active_d128_4k_skl1_af_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    d128_skl1_fault::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        root,
        aarch64_vmsa::address::Level::NEG1,
        aarch64_vmsa::address::Level::L1,
        vmsa_test_harness::D128HardwareManagedAttributes {
            permissions: vmsa_test_harness::D128MappingPermissions::ReadWrite,
            access_flag: false,
            dirty: true,
        },
    )
}

pub(super) fn active_d128_16k_skl1_af_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    d128_skl1_fault::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        vmsa_test_harness::Granule::Size16KiB,
        root,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L2,
        vmsa_test_harness::D128HardwareManagedAttributes {
            permissions: vmsa_test_harness::D128MappingPermissions::ReadWrite,
            access_flag: false,
            dirty: true,
        },
    )
}

pub(super) fn active_d128_4k_skl1_permission_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    d128_skl1_fault::<aarch64_vmsa::config::granule::Granule4KiB>(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        root,
        aarch64_vmsa::address::Level::NEG1,
        aarch64_vmsa::address::Level::L1,
        vmsa_test_harness::D128HardwareManagedAttributes {
            permissions: vmsa_test_harness::D128MappingPermissions::ReadExecute,
            access_flag: true,
            dirty: true,
        },
    )
}

pub(super) fn active_d128_16k_skl1_permission_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_16k()?;
    d128_skl1_fault::<aarch64_vmsa::config::granule::Granule16KiB>(
        context,
        vmsa_test_harness::Granule::Size16KiB,
        root,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L2,
        vmsa_test_harness::D128HardwareManagedAttributes {
            permissions: vmsa_test_harness::D128MappingPermissions::ReadExecute,
            access_flag: true,
            dirty: true,
        },
    )
}

pub(super) fn active_d128_64k_max_skl(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root_64k()?;
    active_d128_stage1_leaf::<aarch64_vmsa::config::granule::Granule64KiB>(
        context,
        root,
        vmsa_test_harness::Granule::Size64KiB,
        aarch64_vmsa::address::Level::L1,
        aarch64_vmsa::address::Level::L3,
        Stage1Observation::Access,
        true,
        None,
    )
}

stage1_observation_pair!(
    active_d128_4k_l0,
    active_d128_4k_l0_at,
    d128_4k_leaf,
    aarch64_vmsa::address::Level::L0
);
stage1_observation_pair!(
    active_d128_4k_l1,
    active_d128_4k_l1_at,
    d128_4k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_d128_4k_l2,
    active_d128_4k_l2_at,
    d128_4k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_d128_4k_l3,
    active_d128_4k_l3_at,
    d128_4k_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_d128_16k_l1,
    active_d128_16k_l1_at,
    d128_16k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_d128_16k_l2,
    active_d128_16k_l2_at,
    d128_16k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_d128_16k_l3,
    active_d128_16k_l3_at,
    d128_16k_leaf,
    aarch64_vmsa::address::Level::L3
);
stage1_observation_pair!(
    active_d128_64k_l1,
    active_d128_64k_l1_at,
    d128_64k_leaf,
    aarch64_vmsa::address::Level::L1
);
stage1_observation_pair!(
    active_d128_64k_l2,
    active_d128_64k_l2_at,
    d128_64k_leaf,
    aarch64_vmsa::address::Level::L2
);
stage1_observation_pair!(
    active_d128_64k_l3,
    active_d128_64k_l3_at,
    d128_64k_leaf,
    aarch64_vmsa::address::Level::L3
);

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
    let mair2_memory = aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    };
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_00ff,
        mair2: Some(0x44),
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings {
            base: aarch64_vmsa::attrs::Stage1BasePermissions::Indirect(
                aarch64_vmsa::attrs::Stage1PermissionRegisters {
                    privileged: 0xcccc_cccc_cccc_ccca,
                    unprivileged: Some(0xcccc_cccc_cccc_ccca),
                    gcs_implemented: false,
                },
            ),
            overlays: aarch64_vmsa::attrs::Stage1PermissionOverlays::default(),
        },
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::NonShareable,
        output_pas: crate::lower_pas(),
    };
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::empty()
        .with_raw_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            0xff,
        )
        .with_raw_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(8)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            0x44,
        );
    let mut root = context.allocate_root()?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            crate::LowerRegime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa128,
        >(
            &mut root,
            aarch64_vmsa::address::Level::new(start.get()),
            bits.get(),
            bits.get(),
        )?;
        mapper.map_hardware_managed_page(
            ADDRESS,
            page.phys_addr(),
            D128HardwareManagedAttributes {
                permissions: D128MappingPermissions::ReadWrite,
                access_flag: false,
                dirty: false,
            },
        )?;
        mapper.map_semantic_leaf::<_>(
            &semantic_config,
            MAIR2_ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
                memory: mair2_memory,
                permissions: aarch64_vmsa::attrs::Stage1Permissions::new(
                    aarch64_vmsa::attrs::DataRights::ReadWrite,
                    aarch64_vmsa::attrs::DataRights::ReadWrite,
                    false,
                    false,
                    false,
                    false,
                ),
                pas: crate::lower_pas(),
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
            aarch64_vmsa::attrs::SemanticVmsa128Stage1TableAttrs {
                table_nt: false,
                access_flag: false,
                disch: false,
                protected: false,
                pas: crate::lower_pas(),
                software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
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
            controls,
            stage1_memory,
            regime: crate::lower_regime_attributes(),
        },
    )?;
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(MAIR2_ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let result = vmsa_test_harness::expect_matching_fault(
        context.lower_read_u64(ADDRESS),
        FaultMatcher::new(ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::AccessFlag),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: LookupLevel::new(3),
        })
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(ADDRESS),
    );
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let updates = context.enable_lower_el1_hardware_updates(true)?;
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let result = vmsa_test_harness::expect_completed(context.lower_write_u64(ADDRESS, VALUE));
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    drop(updates);
    let result = vmsa_test_harness::expect_completed(context.lower_write_u64(ADDRESS, VALUE));
    if !matches!(result, TestResult::Pass) {
        return result;
    }
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
    translation.unmap_for::<
        LowerRegime,
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(ADDRESS)?;
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
    let stage1_start = LookupLevel::new(0).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let d128_start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let block = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls = lpa2_el1_stage1_controls(Granule::Size16KiB, stage1_input, stage1_output)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = d128_stage2_controls_4k(d128_bits, d128_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings {
            base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
                aarch64_vmsa::attrs::Stage2PermissionRegisters {
                    s2pir_el2: 0x0000_0000_0000_fb8c,
                },
            ),
            s2por_el1: None,
        },
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: crate::stage2_pas(),
    };

    let page = context.allocate_granule(Granule::Size16KiB)?;
    let replacement = context.allocate_granule(Granule::Size16KiB)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, DATA_VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let replacement_value = DATA_VALUE ^ u64::MAX;
    if !matches!(
        context.write_u64(replacement.virtual_address() as u64, replacement_value),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let mut stage1_root = context.allocate_root_16k()?;
    let mut stage2_root = context.allocate_root()?;
    let physical_region = stage1_root.phys_addr() & !0x3fff_ffff;
    let target_region = physical_region ^ 0x4000_0000;
    let target_ipa = target_region | (page.phys_addr() - physical_region);
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::config::granule::Granule16KiB,
            aarch64_vmsa::config::format::Vmsa64Lpa2,
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
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa128,
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
        let memory = aarch64_vmsa::attrs::MemoryAttributes::Normal {
            inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
            outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        };
        mapper.map_semantic_leaf::<_>(
            &semantic_config,
            target_ipa,
            page.phys_addr(),
            leaf,
            aarch64_vmsa::attrs::SemanticStage2LeafAttrs {
                memory: aarch64_vmsa::attrs::Stage2MemoryAttributes::Combined(memory),
                permissions: aarch64_vmsa::attrs::Stage2Permissions::read_write(
                    aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
                ),
                output_address_space: crate::stage2_pas(),
                controls: aarch64_vmsa::attrs::SemanticVmsa128Stage2LeafControls {
                    bbm_nt: false,
                    dirty_state: aarch64_vmsa::attrs::DirtyState::Clean,
                    shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
                    access_flag: true,
                    force_no_xs: false,
                    contiguous: false,
                    assured_only: false,
                    software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
                },
            },
            aarch64_vmsa::attrs::SemanticVmsa128Stage2TableAttrs::default(),
        )?;
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
        regime: crate::lower_regime_attributes(),
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
        regime: crate::current_regime_attributes(),
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let result = vmsa_test_harness::expect_value(combined.read_u64(VIRTUAL_ADDRESS), DATA_VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
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
    combined.stage2_mut()?.unmap_for::<
        Stage2Regime,
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(target_ipa)?;
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
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}
