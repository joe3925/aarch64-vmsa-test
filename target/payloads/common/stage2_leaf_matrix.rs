use crate::{CurrentEnvironment, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
enum Observation {
    Access,
    AddressTranslation,
}

#[derive(Clone, Copy)]
enum ActivePermissionOperation {
    Read,
    Write,
    Execute,
    ExecuteEl0,
}

fn active_geometry_matches<F, G>(
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    input: u64,
    covered_size: u64,
) -> bool
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: vmsa_test_harness::adapter::TestGranule,
{
    use aarch64_vmsa::table::TableGeometry;
    let entries = TableGeometry::<F, G>::entries();
    let index_bits = TableGeometry::<F, G>::index_bits();
    let index_mask = TableGeometry::<F, G>::index_mask();
    if G::GRANULE != granule
        || G::SIZE != granule.bytes()
        || G::MASK + 1 != G::SIZE
        || G::align_down(input) != input & !G::MASK
        || G::page_offset(aarch64_vmsa::address::VirtAddr(input)) != input & G::MASK
        || entries != 1usize.checked_shl(u32::from(index_bits)).unwrap_or(0)
        || index_mask.checked_add(1) != u64::try_from(entries).ok()
        || leaf_level.distance_from(start_level)
            != u8::try_from(leaf_level.as_i8() - start_level.as_i8()).ok()
        || !leaf_level.is_between_inclusive(start_level, F::FINAL_LEVEL)
        || TableGeometry::<F, G>::offset_at_level_raw(u64::MAX, leaf_level)
            .and_then(|mask| mask.checked_add(1))
            != Some(covered_size)
        || input & (covered_size - 1)
            != TableGeometry::<F, G>::offset_at_level_raw(input, leaf_level).unwrap_or(u64::MAX)
    {
        return false;
    }
    for raw_level in start_level.as_i8()..=leaf_level.as_i8() {
        let level = aarch64_vmsa::address::Level::new(raw_level);
        let Some(shift) = TableGeometry::<F, G>::checked_level_shift(level) else {
            return false;
        };
        let Some(index) = TableGeometry::<F, G>::index_at_level_raw(input, level) else {
            return false;
        };
        if index != ((input >> shift) & index_mask) as usize
            || level.distance_from(start_level)
                != u8::try_from(raw_level - start_level.as_i8()).ok()
        {
            return false;
        }
    }
    true
}

#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are the explicit architectural matrix coordinates"
)]
fn active_standard_leaf_case<F, G, R>(
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
    permissions: aarch64_vmsa::attrs::Stage2LeafPermissions,
    operation: ActivePermissionOperation,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    R: vmsa_test_harness::adapter::TestRegimeFor<G>,
    R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<Stage = aarch64_vmsa::translation::Stage2>,
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
                    R,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    G,
                >,
            >,
    aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    aarch64_vmsa::attrs::VmsaAttributeCodec: aarch64_vmsa::attrs::AttributeCodec<
            F,
            R,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::Stage2Pas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage2LeafAttrs<
                aarch64_vmsa::attrs::Stage2LeafPermissions,
                crate::Stage2Pas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticVmsa64Stage2TableAttrs,
            RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
            RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
        >,
{
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const VA_BASE: u64 = 0x5240_0000;
    const VALUE: u64 = 0x5332_344b_4c45_4146;
    let page = context.allocate_page()?;
    let backing = page.virtual_address() as u64 + 8;
    if matches!(
        operation,
        ActivePermissionOperation::Execute | ActivePermissionOperation::ExecuteEl0
    ) {
        for (offset, instruction) in [(0, 0xd280_0020), (4, 0xd65f_03c0)] {
            if !matches!(
                context.write_u32(backing + offset, instruction),
                vmsa_test_harness::AccessResult::Completed { .. }
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        context.maintain_cache(
            vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
                address: backing,
                bytes: 8,
            },
        )?;
    } else if !matches!(
        context.write_u64(backing, VALUE),
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
    if !active_geometry_matches::<F, G>(granule, start_level, leaf_level, target_ipa, covered_size)
    {
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
        output_pas: crate::stage2_pas(),
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
                MappingAttributes {
                    writable: true,
                    executable: matches!(
                        operation,
                        ActivePermissionOperation::Execute | ActivePermissionOperation::ExecuteEl0
                    ),
                    user_accessible: matches!(operation, ActivePermissionOperation::ExecuteEl0),
                },
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    }
    let offline_walk;
    let offline_semantic;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<R, G, F>(
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
        let removed = mapper
            .unmap_exact(input_base)
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        if removed.output != output_base
            || removed.level != LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let memory = aarch64_vmsa::attrs::MemoryAttributes::Normal {
            inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
            outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        };
        mapper.map_semantic_leaf::<aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
            &semantic_config,
            input_base,
            output_base,
            LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level"),
            aarch64_vmsa::attrs::SemanticStage2LeafAttrs {
                memory: aarch64_vmsa::attrs::Stage2MemoryAttributes::Combined(memory),
                permissions,
                output_address_space: crate::stage2_pas(),
                controls: aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls {
                    shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
                    access_flag: true,
                    dirty_management: aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
                    contiguous: false,
                    software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
                },
            },
            aarch64_vmsa::attrs::SemanticVmsa64Stage2TableAttrs::default(),
        )?;
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
        regime: crate::lower_regime_attributes(),
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
        regime: crate::current_regime_attributes(),
    };
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
    let installed = combined
        .stage2_mut()?
        .inspect_walk_for::<R, F, G>(target_ipa)?;
    if installed != offline_walk {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let installed_semantic = combined
        .stage2_mut()?
        .inspect_semantic_for::<R, F, G, aarch64_vmsa::attrs::VmsaAttributeCodec, _>(
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
        Observation::Access => match operation {
            ActivePermissionOperation::Read
                if permissions.data != aarch64_vmsa::attrs::DataAccess::None =>
            {
                vmsa_test_harness::expect_value(combined.read_u64(VA_BASE + 8), VALUE)
            }
            ActivePermissionOperation::Write
                if permissions.data == aarch64_vmsa::attrs::DataAccess::ReadWrite =>
            {
                vmsa_test_harness::expect_completed(combined.write_u64(VA_BASE + 8, VALUE + 1))
            }
            ActivePermissionOperation::Execute if permissions.privileged_execute => {
                vmsa_test_harness::expect_value(combined.execute(VA_BASE + 8), 1)
            }
            ActivePermissionOperation::ExecuteEl0 if permissions.unprivileged_execute => {
                vmsa_test_harness::expect_value(combined.el0_execute(VA_BASE + 8), 1)
            }
            ActivePermissionOperation::Read => vmsa_test_harness::expect_matching_fault(
                combined.read_u64(VA_BASE + 8),
                vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
                    status: Some(vmsa_test_harness::FaultStatus::Permission),
                    access: Some(vmsa_test_harness::AccessKind::Read),
                    stage: Some(vmsa_test_harness::FaultStage::Stage2),
                    level: Some(LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")),
                })
                .with_class(vmsa_test_harness::FaultClass::DataAbort)
                .at_address(VA_BASE + 8),
            ),
            ActivePermissionOperation::Write => vmsa_test_harness::expect_matching_fault(
                combined.write_u64(VA_BASE + 8, VALUE + 1),
                vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
                    status: Some(vmsa_test_harness::FaultStatus::Permission),
                    access: Some(vmsa_test_harness::AccessKind::Write),
                    stage: Some(vmsa_test_harness::FaultStage::Stage2),
                    level: Some(LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level")),
                })
                .with_class(vmsa_test_harness::FaultClass::DataAbort)
                .at_address(VA_BASE + 8),
            ),
            ActivePermissionOperation::Execute | ActivePermissionOperation::ExecuteEl0 => {
                let observed = if matches!(operation, ActivePermissionOperation::ExecuteEl0) {
                    combined.el0_execute(VA_BASE + 8)
                } else {
                    combined.execute(VA_BASE + 8)
                };
                vmsa_test_harness::expect_matching_fault(
                    observed,
                    vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
                        status: Some(vmsa_test_harness::FaultStatus::Permission),
                        access: Some(vmsa_test_harness::AccessKind::Execute),
                        stage: Some(vmsa_test_harness::FaultStage::Stage2),
                        level: Some(
                            LookupLevel::new(leaf_level.as_i8()).expect("valid leaf level"),
                        ),
                    })
                    .with_class(vmsa_test_harness::FaultClass::InstructionAbort)
                    .at_address(VA_BASE + 8),
                )
            }
        },
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

#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are the explicit architectural matrix coordinates"
)]
fn active_standard_leaf<F, G, R>(
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
    R: vmsa_test_harness::adapter::TestRegimeFor<G>,
    R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
            Stage = aarch64_vmsa::translation::Stage2,
        >,
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
                    R,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    R,
                    G,
                >,
            >,
    aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    aarch64_vmsa::attrs::VmsaAttributeCodec: aarch64_vmsa::attrs::AttributeCodec<
            F,
            R,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<crate::Stage2Pas>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage2LeafAttrs<
                aarch64_vmsa::attrs::Stage2LeafPermissions,
                crate::Stage2Pas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticVmsa64Stage2TableAttrs,
            RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
            RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
        >,
{
    active_standard_leaf_case::<F, G, R>(
        context,
        granule,
        format,
        start_level,
        leaf_level,
        input_bits,
        output_bits,
        input_hint,
        controls,
        observation,
        aarch64_vmsa::attrs::Stage2LeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        ActivePermissionOperation::Read,
    )
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
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB, Stage2Regime>(
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

fn vmsa64_permission_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    data: aarch64_vmsa::attrs::DataAccess,
    execute: bool,
    operation: ActivePermissionOperation,
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
    active_standard_leaf_case::<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        Stage2Regime,
    >(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L3,
        48,
        48,
        1u64 << 42,
        controls,
        Observation::Access,
        aarch64_vmsa::attrs::Stage2LeafPermissions {
            data,
            privileged_execute: execute,
            unprivileged_execute: execute,
        },
        operation,
    )
}

macro_rules! stage2_permission_cases {
    ($($name:ident, $data:ident, $execute:literal, $operation:ident);+ $(;)?) => {
        $(
            pub(super) fn $name(
                context: &mut TestContext<'_, CurrentEnvironment>,
            ) -> TestResult {
                vmsa64_permission_case(
                    context,
                    aarch64_vmsa::attrs::DataAccess::$data,
                    $execute,
                    ActivePermissionOperation::$operation,
                )
            }
        )+
    };
}

stage2_permission_cases!(
    permission_none_read, None, false, Read;
    permission_none_write, None, false, Write;
    permission_ro_read, ReadOnly, false, Read;
    permission_ro_write, ReadOnly, false, Write;
    permission_rw_read, ReadWrite, false, Read;
    permission_rw_write, ReadWrite, false, Write;
    permission_x_execute, ReadOnly, true, Execute;
    permission_xn_execute, ReadOnly, false, Execute;
);

fn vmsa64_xnx_permission_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    privileged_execute: bool,
    unprivileged_execute: bool,
    operation: ActivePermissionOperation,
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
    active_standard_leaf_case::<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        crate::Stage2XnxRegime,
    >(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L3,
        48,
        48,
        1u64 << 42,
        controls,
        Observation::Access,
        aarch64_vmsa::attrs::Stage2LeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadOnly,
            privileged_execute,
            unprivileged_execute,
        },
        operation,
    )
}

macro_rules! stage2_xnx_cases {
    ($($name:ident, $px:literal, $ux:literal, $operation:ident);+ $(;)?) => {
        $(
            pub(super) fn $name(
                context: &mut TestContext<'_, CurrentEnvironment>,
            ) -> TestResult {
                vmsa64_xnx_permission_case(
                    context,
                    $px,
                    $ux,
                    ActivePermissionOperation::$operation,
                )
            }
        )+
    };
}

stage2_xnx_cases!(
    permission_px_uxn_priv_execute, true, false, Execute;
    permission_px_uxn_unpriv_execute, true, false, ExecuteEl0;
    permission_pxn_ux_priv_execute, false, true, Execute;
    permission_pxn_ux_unpriv_execute, false, true, ExecuteEl0;
);

fn lpa2_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf: aarch64_vmsa::address::Level,
    observation: Observation,
) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(52)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_stage2_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule4KiB, Stage2Regime>(
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
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule16KiB, Stage2Regime>(
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
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule64KiB, Stage2Regime>(
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
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule16KiB, Stage2Regime>(
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
    active_standard_leaf::<aarch64_vmsa::descriptor::Vmsa64Lpa2, aarch64_vmsa::address::Granule64KiB, Stage2Regime>(
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
    if !active_geometry_matches::<aarch64_vmsa::descriptor::Vmsa128, G>(
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
        output_pas: crate::stage2_pas(),
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
        regime: crate::lower_regime_attributes(),
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
        regime: crate::current_regime_attributes(),
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

macro_rules! alternate_leaf_pair {
    (
        $access:ident,
        $at:ident,
        $granule:ty,
        $granule_value:expr,
        $start:expr,
        $leaf:expr,
        $input:expr,
        $hint:expr
    ) => {
        pub(super) fn $access(
            context: &mut TestContext<'_, CurrentEnvironment>,
        ) -> TestResult {
            let input = vmsa_test_harness::AddressBits::new($input)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let output = vmsa_test_harness::AddressBits::new(48)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let start = vmsa_test_harness::LookupLevel::new($start.as_i8())
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let controls = vmsa_test_harness::vmsa64_stage2_controls(
                $granule_value,
                input,
                output,
                start,
            )
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            active_standard_leaf::<
                aarch64_vmsa::descriptor::Vmsa64,
                $granule,
                crate::AlternateStage2Regime,
            >(
                context,
                $granule_value,
                vmsa_test_harness::TranslationFormat::Vmsa64,
                $start,
                $leaf,
                $input,
                48,
                $hint,
                controls,
                Observation::Access,
            )
        }

        pub(super) fn $at(
            context: &mut TestContext<'_, CurrentEnvironment>,
        ) -> TestResult {
            let input = vmsa_test_harness::AddressBits::new($input)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let output = vmsa_test_harness::AddressBits::new(48)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let start = vmsa_test_harness::LookupLevel::new($start.as_i8())
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let controls = vmsa_test_harness::vmsa64_stage2_controls(
                $granule_value,
                input,
                output,
                start,
            )
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            active_standard_leaf::<
                aarch64_vmsa::descriptor::Vmsa64,
                $granule,
                crate::AlternateStage2Regime,
            >(
                context,
                $granule_value,
                vmsa_test_harness::TranslationFormat::Vmsa64,
                $start,
                $leaf,
                $input,
                48,
                $hint,
                controls,
                Observation::AddressTranslation,
            )
        }
    };
}

alternate_leaf_pair!(
    alternate_vmsa64_4k_l1,
    alternate_vmsa64_4k_l1_at,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L1,
    48,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_4k_l2,
    alternate_vmsa64_4k_l2_at,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L2,
    48,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_4k_l3,
    alternate_vmsa64_4k_l3_at,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L3,
    48,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_16k_l2,
    alternate_vmsa64_16k_l2_at,
    aarch64_vmsa::address::Granule16KiB,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L2,
    47,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_16k_l3,
    alternate_vmsa64_16k_l3_at,
    aarch64_vmsa::address::Granule16KiB,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L3,
    47,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_64k_l2,
    alternate_vmsa64_64k_l2_at,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L2,
    48,
    1u64 << 42
);
alternate_leaf_pair!(
    alternate_vmsa64_64k_l3,
    alternate_vmsa64_64k_l3_at,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L3,
    48,
    1u64 << 42
);

fn alternate_vmsa64_permission_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    data: aarch64_vmsa::attrs::DataAccess,
    execute: bool,
    operation: ActivePermissionOperation,
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
    active_standard_leaf_case::<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        crate::AlternateStage2Regime,
    >(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L3,
        48,
        48,
        1u64 << 42,
        controls,
        Observation::Access,
        aarch64_vmsa::attrs::Stage2LeafPermissions {
            data,
            privileged_execute: execute,
            unprivileged_execute: execute,
        },
        operation,
    )
}

macro_rules! alternate_permission_cases {
    ($($name:ident, $data:ident, $execute:literal, $operation:ident);+ $(;)?) => {
        $(
            pub(super) fn $name(
                context: &mut TestContext<'_, CurrentEnvironment>,
            ) -> TestResult {
                alternate_vmsa64_permission_case(
                    context,
                    aarch64_vmsa::attrs::DataAccess::$data,
                    $execute,
                    ActivePermissionOperation::$operation,
                )
            }
        )+
    };
}

alternate_permission_cases!(
    alternate_permission_none_read, None, false, Read;
    alternate_permission_none_write, None, false, Write;
    alternate_permission_ro_read, ReadOnly, false, Read;
    alternate_permission_ro_write, ReadOnly, false, Write;
    alternate_permission_rw_read, ReadWrite, false, Read;
    alternate_permission_rw_write, ReadWrite, false, Write;
    alternate_permission_x_execute, ReadOnly, true, Execute;
    alternate_permission_xn_execute, ReadOnly, false, Execute;
);

fn alternate_vmsa64_xnx_permission_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    privileged_execute: bool,
    unprivileged_execute: bool,
    operation: ActivePermissionOperation,
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
    active_standard_leaf_case::<
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        crate::AlternateStage2XnxRegime,
    >(
        context,
        vmsa_test_harness::Granule::Size4KiB,
        vmsa_test_harness::TranslationFormat::Vmsa64,
        aarch64_vmsa::address::Level::L0,
        aarch64_vmsa::address::Level::L3,
        48,
        48,
        1u64 << 42,
        controls,
        Observation::Access,
        aarch64_vmsa::attrs::Stage2LeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadOnly,
            privileged_execute,
            unprivileged_execute,
        },
        operation,
    )
}

macro_rules! alternate_xnx_cases {
    ($($name:ident, $px:literal, $ux:literal, $operation:ident);+ $(;)?) => {
        $(
            pub(super) fn $name(
                context: &mut TestContext<'_, CurrentEnvironment>,
            ) -> TestResult {
                alternate_vmsa64_xnx_permission_case(
                    context,
                    $px,
                    $ux,
                    ActivePermissionOperation::$operation,
                )
            }
        )+
    };
}

alternate_xnx_cases!(
    alternate_permission_px_uxn_priv_execute, true, false, Execute;
    alternate_permission_px_uxn_unpriv_execute, true, false, ExecuteEl0;
    alternate_permission_pxn_ux_priv_execute, false, true, Execute;
    alternate_permission_pxn_ux_unpriv_execute, false, true, ExecuteEl0;
);
