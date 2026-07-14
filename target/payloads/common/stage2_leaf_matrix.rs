use crate::{CurrentEnvironment, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
enum Observation {
    Access,
    AddressTranslation,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are the explicit architectural matrix coordinates"
)]
fn active_standard_leaf<F, G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    format: vmsa_test_harness::TranslationFormat,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    input_bits: u8,
    output_bits: u8,
    input_hint: u64,
    controls: vmsa_test_harness::TranslationControls,
    observation: Observation,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    Stage2Regime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    F: vmsa_test_harness::adapter::TestFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage2, G>,
    aarch64_vmsa::descriptor::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage2, G>,
    <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage2, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::translation::Stage2,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    Stage2Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    Stage2Regime,
                    G,
                >,
            >,
    aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, Stage2Regime, G>: Copy,
    aarch64_vmsa::attrs::VmsaAttributeCodec: aarch64_vmsa::attrs::AttributeCodec<
            F,
            Stage2Regime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<()>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage2LeafAttrs<
                aarch64_vmsa::attrs::Stage2LeafPermissions,
                (),
                aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls,
            >,
            RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, Stage2Regime, G>,
            RawTable = aarch64_vmsa::regime::TableFieldsOf<F, Stage2Regime, G>,
        >,
{
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const VA_BASE: u64 = 0x5240_0000;
    const VALUE: u64 = 0x5332_344b_4c45_4146;
    let page = context.allocate_page()?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64 + 8, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let covered_size =
        aarch64_vmsa::table::TableGeometry::<F, G>::offset_at_level_raw(u64::MAX, leaf_level)
            .and_then(|mask| mask.checked_add(1))
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let target_pa = page
        .phys_addr()
        .checked_add(8)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_base = target_pa & !(covered_size - 1);
    let output_offset = target_pa - output_base;
    if output_offset == 0 || output_base.checked_add(output_offset) != Some(target_pa) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let input_base = input_hint & !(covered_size - 1);
    let target_ipa = input_base
        .checked_add(target_pa - output_base)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if !crate::formats_live::active_geometry_matches::<F, G>(
        granule,
        start_level,
        leaf_level,
        target_ipa,
        covered_size,
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let stage1_bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_input =
        AddressBits::new(input_bits).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_output =
        AddressBits::new(output_bits).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    let stage1_controls = vmsa_test_harness::lpa2_el1_stage1_controls_4k(stage1_bits, stage1_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut stage1_root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root_in(context.native_pas(), granule)?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(
            &mut stage1_root,
            aarch64_vmsa::address::Level::NEG1,
            52,
            52,
        )?;
        mapper
            .map_attributes_leaf_exact(
                VA_BASE,
                target_ipa & !0xfff,
                3,
                MappingAttributes::READ_WRITE,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    }
    let offline_walk;
    let offline_semantic;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<Stage2Regime, G, F>(
            &mut stage2_root,
            start_level,
            input_bits,
            output_bits,
        )?;
        let outcome = mapper
            .map_attributes_leaf_exact(
                input_base,
                output_base,
                leaf_level.as_i8(),
                MappingAttributes::READ_WRITE,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        let expected_kind = if leaf_level == aarch64_vmsa::address::Level::L3 {
            vmsa_test_harness::WalkDescriptorKind::Page
        } else {
            vmsa_test_harness::WalkDescriptorKind::Block
        };
        let expected_tables = usize::try_from(leaf_level.as_i8() - start_level.as_i8())
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        if outcome.level != LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")
            || outcome.kind != expected_kind
            || outcome.covered_size != covered_size
            || usize::from(outcome.tables_allocated) != expected_tables
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let walk = mapper.inspect_walk(target_ipa)?;
        if walk.steps().len() != expected_tables + 1 {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        for (index, step) in walk.steps().iter().enumerate() {
            let step = step.ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let level = aarch64_vmsa::address::Level::new(start_level.as_i8() + index as i8);
            let expected_index =
                aarch64_vmsa::table::TableGeometry::<F, G>::index_at_level_raw(target_ipa, level)
                    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if step.level != LookupLevel::new(level.as_i8()).expect("valid walk level")
                || step.entry_index != expected_index
                || step.raw.is_none()
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            if index == expected_tables {
                if step.kind != expected_kind
                    || step.next_table.is_some()
                    || step.output != Some(target_pa)
                {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
            } else if step.kind != vmsa_test_harness::WalkDescriptorKind::Table
                || step.next_table.is_none()
                || step.output.is_some()
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        offline_walk = walk;
        offline_semantic = mapper
            .inspect_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
                target_ipa,
                &semantic_config,
            )?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        let recovery_level = match granule {
            Granule::Size4KiB => aarch64_vmsa::address::Level::L1,
            Granule::Size16KiB | Granule::Size64KiB => aarch64_vmsa::address::Level::L2,
        };
        let recovery_size = aarch64_vmsa::table::TableGeometry::<F, G>::offset_at_level_raw(
            u64::MAX,
            recovery_level,
        )
        .and_then(|mask| mask.checked_add(1))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let physical_region = stage1_root.phys_addr() & !(recovery_size - 1);
        mapper
            .map_attributes_leaf_exact(
                physical_region,
                physical_region,
                recovery_level.as_i8(),
                recovery,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        if physical_region != 0 {
            mapper
                .map_attributes_leaf_exact(0, 0, recovery_level.as_i8(), recovery)
                .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        }
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: stage1_bits,
        output_bits: stage1_bits,
        start_level: LookupLevel::new(-1),
        asid: Some(Asid(0x54)),
        vmid: None,
        controls: stage1_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule,
        format,
        input_bits: stage2_input,
        output_bits: stage2_output,
        start_level: LookupLevel::new(start_level.as_i8()),
        asid: None,
        vmid: Some(Vmid(0x55)),
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let installed = combined
        .stage2_mut()?
        .inspect_walk_for::<Stage2Regime, F, G>(target_ipa)?;
    if installed != offline_walk {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let installed_semantic = combined
        .stage2_mut()?
        .inspect_semantic_for::<Stage2Regime, F, G, aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            target_ipa,
            &semantic_config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed_semantic != offline_semantic {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let installed_leaf = installed
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed_leaf.level != LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")
        || installed_leaf.output != Some(target_pa)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    match observation {
        Observation::Access => {
            vmsa_test_harness::expect_value(combined.read_u64(VA_BASE + 8), VALUE)
        }
        Observation::AddressTranslation => {
            match combined.translate(VA_BASE + 8, vmsa_test_harness::TranslationQueryAccess::Read) {
                vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address, ..
                } if physical_address == target_pa => TestResult::Pass,
                vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address, ..
                } => TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target_pa,
                    actual: physical_address,
                }),
                _ => vmsa_test_harness::HarnessError::InvalidState.into(),
            }
        }
    }
}

fn vmsa64_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_stage2_controls_4k(
        bits,
        bits,
        vmsa_test_harness::LookupLevel::new(0)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L0,
        leaf,
        48,
        48,
        1u64 << 42,
        controls,
        observation,
    )
}

fn lpa2_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_stage2_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule4KiB>(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
        aarch64_vmsa::address::Level::NEG1,
        leaf,
        52,
        52,
        1u64 << 50,
        controls,
        observation,
    )
}

pub(super) fn vmsa64_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::Access,
    )
}
pub(super) fn vmsa64_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::Access,
    )
}
pub(super) fn vmsa64_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::Access,
    )
}
pub(super) fn lpa2_l0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L0,
        Observation::Access,
    )
}
pub(super) fn lpa2_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::Access,
    )
}
pub(super) fn lpa2_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::Access,
    )
}
pub(super) fn lpa2_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::Access,
    )
}
pub(super) fn vmsa64_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::AddressTranslation,
    )
}
pub(super) fn vmsa64_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::AddressTranslation,
    )
}
pub(super) fn vmsa64_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::AddressTranslation,
    )
}
pub(super) fn lpa2_l0_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L0,
        Observation::AddressTranslation,
    )
}
pub(super) fn lpa2_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::AddressTranslation,
    )
}
pub(super) fn lpa2_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::AddressTranslation,
    )
}
pub(super) fn lpa2_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lpa2_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::AddressTranslation,
    )
}

fn vmsa64_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(47)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = vmsa_test_harness::LookupLevel::new(1)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_stage2_controls(
        vmsa_test_harness::Granule::Size16KiB,
        bits,
        output,
        start,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule16KiB>(
        context,
        vmsa_test_harness::Granule::Size16KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L1,
        leaf,
        47,
        48,
        1u64 << 42,
        controls,
        observation,
    )
}

fn vmsa64_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = vmsa_test_harness::LookupLevel::new(1)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_stage2_controls(
        vmsa_test_harness::Granule::Size64KiB,
        bits,
        bits,
        start,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule64KiB>(
        context,
        vmsa_test_harness::Granule::Size64KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L1,
        leaf,
        48,
        48,
        1u64 << 42,
        controls,
        observation,
    )
}

fn lpa2_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = vmsa_test_harness::LookupLevel::new(0)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_stage2_controls(
        vmsa_test_harness::Granule::Size16KiB,
        bits,
        bits,
        start,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule16KiB>(
        context,
        vmsa_test_harness::Granule::Size16KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
        aarch64_vmsa::address::Level::L0,
        leaf,
        52,
        52,
        1u64 << 50,
        controls,
        observation,
    )
}

fn lpa2_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = vmsa_test_harness::LookupLevel::new(1)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_stage2_controls(
        vmsa_test_harness::Granule::Size64KiB,
        bits,
        bits,
        start,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule64KiB>(
        context,
        vmsa_test_harness::Granule::Size64KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
        aarch64_vmsa::address::Level::L1,
        leaf,
        52,
        52,
        1u64 << 50,
        controls,
        observation,
    )
}

macro_rules! two_leaf_observations {
    ($access_l2:ident, $access_l3:ident, $at_l2:ident, $at_l3:ident, $helper:ident) => {
        pub(super) fn $access_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L2,
                Observation::Access,
            )
        }
        pub(super) fn $access_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L3,
                Observation::Access,
            )
        }
        pub(super) fn $at_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L2,
                Observation::AddressTranslation,
            )
        }
        pub(super) fn $at_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L3,
                Observation::AddressTranslation,
            )
        }
    };
}

two_leaf_observations!(
    vmsa64_16k_l2,
    vmsa64_16k_l3,
    vmsa64_16k_l2_at,
    vmsa64_16k_l3_at,
    vmsa64_16k_leaf
);
two_leaf_observations!(
    vmsa64_64k_l2,
    vmsa64_64k_l3,
    vmsa64_64k_l2_at,
    vmsa64_64k_l3_at,
    vmsa64_64k_leaf
);

macro_rules! three_leaf_observations {
    ($access_l1:ident, $access_l2:ident, $access_l3:ident, $at_l1:ident, $at_l2:ident, $at_l3:ident, $helper:ident) => {
        pub(super) fn $access_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L1,
                Observation::Access,
            )
        }
        two_leaf_observations!($access_l2, $access_l3, $at_l2, $at_l3, $helper);
        pub(super) fn $at_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(
                context,
                aarch64_vmsa::address::Level::L1,
                Observation::AddressTranslation,
            )
        }
    };
}

three_leaf_observations!(
    lpa2_16k_l1,
    lpa2_16k_l2,
    lpa2_16k_l3,
    lpa2_16k_l1_at,
    lpa2_16k_l2_at,
    lpa2_16k_l3_at,
    lpa2_16k_leaf
);
three_leaf_observations!(
    lpa2_64k_l1,
    lpa2_64k_l2,
    lpa2_64k_l3,
    lpa2_64k_l1_at,
    lpa2_64k_l2_at,
    lpa2_64k_l3_at,
    lpa2_64k_leaf
);

fn d128_leaf<G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    input_hint: u64,
    observation: Observation,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    Stage2Regime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::descriptor::Vmsa128:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage2, G>,
    <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage2,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::translation::Stage2,
            G,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2TableAttrs,
        >,
{
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const VA_BASE: u64 = 0x5250_0000;
    const VALUE: u64 = 0x5332_4431_3238_4c46;
    let page = context.allocate_granule(granule)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64 + 8, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let covered_size = aarch64_vmsa::table::TableGeometry::<
        aarch64_vmsa::descriptor::Vmsa128,
        G,
    >::offset_at_level_raw(u64::MAX, leaf_level)
    .and_then(|mask| mask.checked_add(1))
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let target_pa = page
        .phys_addr()
        .checked_add(8)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_base = target_pa & !(covered_size - 1);
    let output_offset = target_pa - output_base;
    if output_offset == 0 || output_base.checked_add(output_offset) != Some(target_pa) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let input_base = input_hint & !(covered_size - 1);
    let target_ipa = input_base
        .checked_add(target_pa - output_base)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if !crate::formats_live::active_geometry_matches::<aarch64_vmsa::descriptor::Vmsa128, G>(
        granule,
        start_level,
        leaf_level,
        target_ipa,
        covered_size,
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls = vmsa_test_harness::lpa2_el1_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = vmsa_test_harness::d128_stage2_controls(granule, bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
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
    let mut stage1_root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root_in(context.native_pas(), granule)?;
    let offline_walk;
    let offline_semantic;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(
            &mut stage1_root,
            aarch64_vmsa::address::Level::NEG1,
            52,
            52,
        )?;
        mapper
            .map_attributes_leaf_exact(
                VA_BASE,
                target_ipa & !0xfff,
                3,
                MappingAttributes::READ_WRITE,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    }
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            Stage2Regime,
            G,
            aarch64_vmsa::descriptor::Vmsa128,
        >(&mut stage2_root, start_level, 52, 52)?;
        let leaf = LookupLevel::new(leaf_level.as_i8())
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let outcome = mapper
            .map_stage2_leaf_exact(input_base, output_base, leaf, MappingAttributes::READ_WRITE)
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        let expected_kind = if leaf_level == aarch64_vmsa::address::Level::L3 {
            vmsa_test_harness::WalkDescriptorKind::Page
        } else {
            vmsa_test_harness::WalkDescriptorKind::Block
        };
        let expected_tables = usize::try_from(leaf_level.as_i8() - start_level.as_i8())
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        if outcome.level != leaf
            || outcome.kind != expected_kind
            || outcome.covered_size != covered_size
            || usize::from(outcome.tables_allocated) != expected_tables
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let walk = mapper.inspect_walk(target_ipa)?;
        if walk.steps().len() != expected_tables + 1 {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        for (index, step) in walk.steps().iter().enumerate() {
            let step = step.ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let level = aarch64_vmsa::address::Level::new(start_level.as_i8() + index as i8);
            let expected_index = aarch64_vmsa::table::TableGeometry::<
                aarch64_vmsa::descriptor::Vmsa128,
                G,
            >::index_at_level_raw(target_ipa, level)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if step.level != LookupLevel::new(level.as_i8()).expect("valid walk level")
                || step.entry_index != expected_index
                || step.raw.is_none()
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            if index == expected_tables {
                if step.kind != expected_kind
                    || step.next_table.is_some()
                    || step.output != Some(target_pa)
                {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
            } else if step.kind != vmsa_test_harness::WalkDescriptorKind::Table
                || step.next_table.is_none()
                || step.output.is_some()
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        offline_walk = walk;
        offline_semantic = mapper
            .inspect_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
                target_ipa,
                &semantic_config,
            )?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        let recovery_size = aarch64_vmsa::table::TableGeometry::<
            aarch64_vmsa::descriptor::Vmsa128,
            G,
        >::offset_at_level_raw(
            u64::MAX, aarch64_vmsa::address::Level::L1
        )
        .and_then(|mask| mask.checked_add(1))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let physical_region = stage1_root.phys_addr() & !(recovery_size - 1);
        mapper.map_stage2_leaf(
            physical_region,
            physical_region,
            LookupLevel::new(1).expect("level 1 is valid"),
            recovery,
        )?;
        if physical_region != 0 {
            mapper.map_stage2_leaf(
                0,
                0,
                LookupLevel::new(1).expect("level 1 is valid"),
                recovery,
            )?;
        }
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(stage1_root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64Lpa2,
        input_bits: bits,
        output_bits: bits,
        start_level: LookupLevel::new(-1),
        asid: Some(Asid(0x56)),
        vmid: None,
        controls: stage1_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule,
        format: TranslationFormat::Vmsa128,
        input_bits: bits,
        output_bits: bits,
        start_level: LookupLevel::new(start_level.as_i8()),
        asid: None,
        vmid: Some(Vmid(0x57)),
        controls: stage2_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let installed = combined
        .stage2_mut()?
        .inspect_walk_for::<Stage2Regime, aarch64_vmsa::descriptor::Vmsa128, G>(target_ipa)?;
    if installed != offline_walk {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let installed_semantic = combined
        .stage2_mut()?
        .inspect_semantic_for::<
            Stage2Regime,
            aarch64_vmsa::descriptor::Vmsa128,
            G,
            aarch64_vmsa::attrs::VmsaAttributeCodec,
            _,
        >(target_ipa, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed_semantic != offline_semantic {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let installed_leaf = installed
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed_leaf.level != LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")
        || installed_leaf.output != Some(target_pa)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    match observation {
        Observation::Access => {
            vmsa_test_harness::expect_value(combined.read_u64(VA_BASE + 8), VALUE)
        }
        Observation::AddressTranslation => {
            match combined.translate(VA_BASE + 8, vmsa_test_harness::TranslationQueryAccess::Read) {
                vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address, ..
                } if physical_address == target_pa => TestResult::Pass,
                vmsa_test_harness::TranslationQueryResult::Success {
                    physical_address, ..
                } => TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target_pa,
                    actual: physical_address,
                }),
                _ => vmsa_test_harness::HarnessError::InvalidState.into(),
            }
        }
    }
}

fn d128_4k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    d128_leaf::<aarch64_vmsa::address::Granule4KiB>(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        aarch64_vmsa::address::Level::NEG1,
        leaf,
        1u64 << 50,
        observation,
    )
}

fn d128_16k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    d128_leaf::<aarch64_vmsa::address::Granule16KiB>(
        context,
        vmsa_test_harness::Granule::Size16KiB,
        aarch64_vmsa::address::Level::L0,
        leaf,
        1u64 << 50,
        observation,
    )
}

fn d128_64k_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    d128_leaf::<aarch64_vmsa::address::Granule64KiB>(
        context,
        vmsa_test_harness::Granule::Size64KiB,
        aarch64_vmsa::address::Level::L1,
        leaf,
        1u64 << 50,
        observation,
    )
}

pub(super) fn d128_l0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L0,
        Observation::Access,
    )
}
pub(super) fn d128_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::Access,
    )
}
pub(super) fn d128_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::Access,
    )
}
pub(super) fn d128_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::Access,
    )
}
pub(super) fn d128_l0_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L0,
        Observation::AddressTranslation,
    )
}
pub(super) fn d128_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L1,
        Observation::AddressTranslation,
    )
}
pub(super) fn d128_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L2,
        Observation::AddressTranslation,
    )
}
pub(super) fn d128_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_4k_leaf(
        context,
        aarch64_vmsa::address::Level::L3,
        Observation::AddressTranslation,
    )
}

three_leaf_observations!(
    d128_16k_l1,
    d128_16k_l2,
    d128_16k_l3,
    d128_16k_l1_at,
    d128_16k_l2_at,
    d128_16k_l3_at,
    d128_16k_leaf
);
three_leaf_observations!(
    d128_64k_l1,
    d128_64k_l2,
    d128_64k_l3,
    d128_64k_l1_at,
    d128_64k_l2_at,
    d128_64k_l3_at,
    d128_64k_leaf
);
