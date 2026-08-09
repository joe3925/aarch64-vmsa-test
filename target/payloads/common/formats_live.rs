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

pub(crate) fn active_geometry_matches<F, G>(
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
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::translation::Stage1,
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
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
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
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: crate::current_config_pas(),
    };
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
    if !active_geometry_matches::<F, G>(
        geometry.granule,
        geometry.start_level,
        leaf_level,
        access_address,
        covered_size,
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let start = LookupLevel::new(geometry.start_level.as_i8())
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(leaf_level.as_i8())
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let sandbox;
    let offline_walk;
    let offline_semantic;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<CurrentRegime, G, F>(
            &mut root,
            geometry.start_level,
            input_bits.get(),
            output_bits.get(),
        )?;
        let outcome = mapper
            .map_attributes_leaf_exact(
                input_base,
                output_base,
                leaf_level.as_i8(),
                MappingAttributes::READ_WRITE,
            )
            .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let expected_kind = if leaf_level == aarch64_vmsa::address::Level::L3 {
            vmsa_test_harness::WalkDescriptorKind::Page
        } else {
            vmsa_test_harness::WalkDescriptorKind::Block
        };
        let expected_tables = usize::try_from(leaf_level.as_i8() - geometry.start_level.as_i8())
            .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        if outcome.level != leaf
            || outcome.kind != expected_kind
            || outcome.covered_size != covered_size
            || usize::from(outcome.tables_allocated) != expected_tables
        {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        let walk = mapper.inspect_walk(access_address)?;
        let expected_length = usize::try_from(
            i16::from(leaf_level.as_i8()) - i16::from(geometry.start_level.as_i8()) + 1,
        )
        .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
        if walk.steps().len() != expected_length {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        for (index, step) in walk.steps().iter().enumerate() {
            let Some(step) = step else {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            };
            let level =
                aarch64_vmsa::address::Level::new(geometry.start_level.as_i8() + index as i8);
            let expected_index = aarch64_vmsa::table::TableGeometry::<F, G>::index_at_level_raw(
                access_address,
                level,
            )
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if step.level != LookupLevel::new(level.as_i8()).expect("walk level is valid")
                || step.entry_index != expected_index
                || step.raw.is_none()
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
            if index + 1 == expected_length {
                if step.kind != expected_kind
                    || step.next_table.is_some()
                    || step.output != Some(target_physical)
                {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            } else if step.kind != vmsa_test_harness::WalkDescriptorKind::Table
                || step.next_table.is_none()
                || step.output.is_some()
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
        }
        offline_walk = walk;
        offline_semantic = mapper
            .inspect_semantic_leaf::<_>(access_address, &semantic_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
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
    let live_walk = translation.inspect_walk::<F, G>(access_address)?;
    if live_walk != offline_walk {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let live_semantic = translation
        .inspect_semantic_for::<CurrentRegime, F, G, _>(access_address, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_semantic != offline_semantic
        || live_semantic.permissions.data != aarch64_vmsa::attrs::DataAccess::ReadWrite
        || live_semantic.permissions.execute
        || !live_semantic.controls.access_flag
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let live = live_walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live.level != leaf || live.output != Some(target_physical) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
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
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::translation::Stage1,
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
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
                crate::CurrentPas,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits,
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
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: crate::current_config_pas(),
    };
    let semantic_leaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
        memory,
        permissions: aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute: false,
        },
        pas: crate::current_pas(),
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
    let semantic_table = aarch64_vmsa::attrs::SemanticStage1TableAttrs {
        permission_limits: aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits {
            data_limit: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: crate::current_table_pas(),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls::default(),
    };
    let offline_semantic;
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
        let walk = mapper.inspect_walk(ADDRESS)?;
        let Some(leaf) = walk.leaf() else {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        };
        if walk.steps().len() < 2
            || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
            || leaf.raw.is_none()
            || leaf.next_table.is_some()
            || leaf.output != Some(page.phys_addr())
        {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        offline_semantic = mapper
            .inspect_semantic_leaf::<_>(ADDRESS, &semantic_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if malformed_terminal {
            let Some(mut replacement) = leaf.raw else {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            };
            replacement.low &= !0b10;
            let original = mapper
                .isolated_malformed_table()
                .replace_terminal_descriptor(ADDRESS, replacement)?;
            if original != leaf.raw.unwrap_or(replacement) {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
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
    let live_walk = translation.inspect_walk::<F, G>(ADDRESS)?;
    let Some(live_leaf) = live_walk.leaf() else {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    };
    if live_walk.steps().len() < 2
        || live_leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || live_leaf.output != Some(page.phys_addr())
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let semantic = translation
        .inspect_semantic_for::<CurrentRegime, F, G, _>(ADDRESS, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if semantic != offline_semantic
        || semantic.memory != memory
        || semantic.permissions.data != aarch64_vmsa::attrs::DataAccess::ReadWrite
    {
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
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
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
    aarch64_vmsa::config::format::Vmsa64Lpa2:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::config::format::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::translation::Stage1,
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
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
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
            aarch64_vmsa::translation::Stage1,
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
    let permission_pair = aarch64_vmsa::attrs::Stage1PermissionRegisterPair {
        base: 0xcccc_cccc_cccc_ccca,
        overlay: None,
    };
    let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x44,
        mair2: Some(0),
        stage1_permissions: Some(aarch64_vmsa::attrs::Stage1PermissionRegisters {
            privileged: permission_pair,
            unprivileged: Some(permission_pair),
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::NonShareable,
        output_pas: crate::lower_pas(),
    };
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
    if !active_geometry_matches::<aarch64_vmsa::config::format::Vmsa128, G>(
        granule,
        start_level,
        leaf_level,
        access_address,
        covered_size,
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let offline_walk;
    let offline_semantic;
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
        let outcome = mapper
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
            .map_err(|_| vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let expected_kind = if leaf_level == aarch64_vmsa::address::Level::L3 {
            vmsa_test_harness::WalkDescriptorKind::Page
        } else {
            vmsa_test_harness::WalkDescriptorKind::Block
        };
        let expected_tables =
            usize::try_from(leaf_level.as_i8() - start_level.as_i8()).map_err(|_| {
                vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
            })?;
        if outcome.level
            != LookupLevel::new(leaf_level.as_i8()).expect("leaf level is architectural")
            || outcome.kind != expected_kind
            || outcome.covered_size != covered_size
            || usize::from(outcome.tables_allocated) != expected_tables
        {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        let walk = mapper.inspect_walk(access_address)?;
        if walk.steps().len() != expected_tables + 1 {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        for (index, step) in walk.steps().iter().enumerate() {
            let step = step.ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let level = aarch64_vmsa::address::Level::new(start_level.as_i8() + index as i8);
            let expected_index = aarch64_vmsa::table::TableGeometry::<
                aarch64_vmsa::config::format::Vmsa128,
                G,
            >::index_at_level_raw(access_address, level)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if step.level != LookupLevel::new(level.as_i8()).expect("walk level is valid")
                || step.entry_index != expected_index
                || step.raw.is_none()
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
            if index == expected_tables {
                if step.kind != expected_kind
                    || step.next_table.is_some()
                    || step.output != Some(target_physical)
                {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            } else if step.kind != vmsa_test_harness::WalkDescriptorKind::Table
                || step.next_table.is_none()
                || step.output.is_some()
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
        }
        offline_walk = walk;
        offline_semantic = mapper
            .inspect_semantic_leaf::<_>(access_address, &semantic_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
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
    let live_walk = translation
        .inspect_walk_for::<LowerRegime, aarch64_vmsa::config::format::Vmsa128, G>(
            access_address,
        )?;
    if live_walk != offline_walk {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let live_semantic = translation
        .inspect_semantic_for::<LowerRegime, aarch64_vmsa::config::format::Vmsa128, G, _>(
            access_address,
            &semantic_config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_semantic != offline_semantic {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let live = live_walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live.output != Some(target_physical) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = match observation {
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
                physical_address, ..
            }) if physical_address == target_physical => TestResult::Pass,
            Some(vmsa_test_harness::TranslationQueryResult::Success {
                physical_address, ..
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
                regime: crate::lower_regime_attributes(),
            },
        ),
        Err(vmsa_test_harness::HarnessError::InvalidState)
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
        mair: 0x0000_00ff,
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
                permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions {
                    privileged_data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
                    unprivileged_data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
                    privileged_execute: false,
                    unprivileged_execute: false,
                    privileged_gcs: false,
                    unprivileged_gcs: false,
                },
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
    let walk = translation.inspect_walk_for::<
        LowerRegime,
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(ADDRESS)?;
    if walk.leaf().and_then(|leaf| leaf.output) != Some(page.phys_addr()) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let d128_semantic = translation
        .inspect_semantic_for::<
            LowerRegime,
            aarch64_vmsa::config::format::Vmsa128,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(ADDRESS, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if d128_semantic.controls.access_flag
        || d128_semantic.controls.dirty_state != aarch64_vmsa::attrs::DirtyState::Clean
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let mair2_semantic = translation
        .inspect_semantic_for::<
            LowerRegime,
            aarch64_vmsa::config::format::Vmsa128,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(MAIR2_ADDRESS, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if mair2_semantic.memory != mair2_memory {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(MAIR2_ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let initial = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if initial.access_flag || initial.dirty {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let updates = context.enable_lower_el1_hardware_updates(true)?;
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let after_read = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if !after_read.access_flag || after_read.dirty {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = vmsa_test_harness::expect_completed(context.lower_write_u64(ADDRESS, VALUE));
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let after_write = translation.inspect_d128_hardware_updates_for::<LowerRegime>(ADDRESS)?;
    if !after_write.access_flag || !after_write.dirty {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(ADDRESS)?;
    if removed.output != replacement.phys_addr() {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
                regime: crate::lower_regime_attributes(),
            },
        ),
        Err(vmsa_test_harness::HarnessError::InvalidState)
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

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
    let offline_semantic;
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
                permissions: aarch64_vmsa::attrs::Stage2Permission::ReadWrite {
                    privileged_execute: false,
                    unprivileged_execute: false,
                },
                output_address_space: crate::stage2_pas(),
                controls: aarch64_vmsa::attrs::SemanticVmsa128Stage2LeafControls {
                    bbm_nt: false,
                    dirty_state: aarch64_vmsa::attrs::DirtyState::Clean,
                    shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
                    access_flag: true,
                    force_no_execute: false,
                    contiguous: false,
                    assured_only: false,
                    software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
                },
            },
            aarch64_vmsa::attrs::SemanticVmsa128Stage2TableAttrs::default(),
        )?;
        offline_semantic = mapper
            .inspect_semantic_leaf::<_>(target_ipa, &semantic_config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
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
    let walk = combined.stage2_mut()?.inspect_walk_for::<
        Stage2Regime,
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(target_ipa)?;
    if walk.leaf().and_then(|entry| entry.output) != Some(page.phys_addr()) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let installed_semantic = combined
        .stage2_mut()?
        .inspect_semantic_for::<
            Stage2Regime,
            aarch64_vmsa::config::format::Vmsa128,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(target_ipa, &semantic_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed_semantic != offline_semantic {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >(target_ipa)?;
    if removed.output != replacement.phys_addr() {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}
