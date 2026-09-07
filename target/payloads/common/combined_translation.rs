use crate::{CurrentEnvironment, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
pub(super) enum Stage2InvalidationCase {
    Ipa,
    RangeFirst,
    RangeLast,
    Full,
    LocalIpa,
}

pub(super) fn stage2_invalidation_effect(
    context: &mut TestContext<'_, CurrentEnvironment>,
    case: Stage2InvalidationCase,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, CombinedTlbiOperation, Granule, LookupLevel, MappingAttributes,
        PhysicalAddress, TlbiOperation, TlbiScope, TranslationFormat, TranslationSetup,
        TranslationStage, Vmid, expect_value, vmsa64_el1_stage1_controls_4k,
        vmsa64_stage2_controls_4k,
    };

    const RANGE_START: u64 = 0x1_4000_0000;
    const PAGE_SIZE: u64 = 4096;
    const VALUES: [u64; 2] = [0x544c_4249_4f4c_4431, 0x544c_4249_4e45_5732];
    let target_ipa = match case {
        Stage2InvalidationCase::RangeLast => RANGE_START + PAGE_SIZE,
        _ => RANGE_START,
    };
    let virtual_address = 0x5000_0000;
    let input_bits = AddressBits::new(39).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(context.capabilities().pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let pages = [context.allocate_page()?, context.allocate_page()?];
    for (page, value) in pages.iter().zip(VALUES) {
        let result = context.write_u64(page.virtual_address() as u64, value);
        if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(result);
        }
    }

    let mut stage1_root = context.allocate_root()?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(&mut stage1_root, aarch64_vmsa::address::Level::L1, 39, output_bits.get())?;
        mapper.map_leaf(
            virtual_address,
            target_ipa,
            leaf_level,
            MappingAttributes::READ_WRITE,
        )?;
    }

    let mut stage2_roots = [
        Some(context.allocate_root()?),
        Some(context.allocate_root()?),
    ];
    let recovery_base = stage1_root.phys_addr() & !((1u64 << 30) - 1);
    for (root, page) in stage2_roots.iter_mut().zip(pages.iter()) {
        let root = root
            .as_mut()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            Stage2Regime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(root, aarch64_vmsa::address::Level::L1, 39, output_bits.get())?;
        mapper.map_leaf(
            target_ipa,
            page.phys_addr(),
            leaf_level,
            MappingAttributes::READ_WRITE,
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        for (index, candidate) in [0, recovery_base, 0x8000_0000].into_iter().enumerate() {
            if [0, recovery_base, 0x8000_0000][..index].contains(&candidate)
                || candidate == (target_ipa & !((1u64 << 30) - 1))
            {
                continue;
            }
            mapper.map_leaf(candidate, candidate, start_level, recovery)?;
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
        asid: Some(Asid(0x51)),
        vmid: None,
        controls: vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT.with_raw_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            0xff,
        ),
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(
            stage2_roots[0]
                .as_ref()
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
                .phys_addr(),
        ),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: Some(start_level),
        asid: None,
        vmid: Some(Vmid(0x52)),
        controls: vmsa64_stage2_controls_4k(input_bits, output_bits, start_level)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let first_root = stage2_roots[0]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let replacement_root = stage2_roots[1]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut combined =
        context.install_combined_owned(stage1_root, stage1_setup, first_root, stage2_setup)?;
    let initial = expect_value(combined.read_u64(virtual_address), VALUES[0]);
    if !matches!(initial, TestResult::Pass) {
        return initial;
    }
    combined
        .stage2_mut()?
        .adopt_and_switch_stage2_root(replacement_root, Vmid(0x52))?;
    let (scope, operation) = match case {
        Stage2InvalidationCase::Ipa => (
            TlbiScope::InnerShareable,
            TlbiOperation::IntermediatePhysicalAddress(target_ipa),
        ),
        Stage2InvalidationCase::RangeFirst | Stage2InvalidationCase::RangeLast => (
            TlbiScope::InnerShareable,
            TlbiOperation::IntermediatePhysicalRange {
                start: RANGE_START,
                pages: 2,
            },
        ),
        Stage2InvalidationCase::Full => (TlbiScope::InnerShareable, TlbiOperation::All),
        Stage2InvalidationCase::LocalIpa => (
            TlbiScope::Local,
            TlbiOperation::IntermediatePhysicalAddress(target_ipa),
        ),
    };
    combined.tlbi(scope, CombinedTlbiOperation::Stage2(operation))?;
    expect_value(combined.read_u64(virtual_address), VALUES[1])
}

pub(super) fn combined_invalidation_order(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, CombinedTlbiOperation, Granule, LookupLevel, MappingAttributes,
        PhysicalAddress, TlbiScope, TranslationFormat, TranslationSetup, TranslationStage, Vmid,
        expect_value, vmsa64_el1_stage1_controls_4k, vmsa64_stage2_controls_4k,
    };

    const ADDRESS: u64 = 0x5100_0000;
    const IPA: [u64; 2] = [0x1_5100_0000, 0x1_5200_0000];
    const VALUES: [u64; 2] = [0x5331_5332_4f4c_4431, 0x5331_5332_4e45_5732];
    let bits = AddressBits::new(39).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = AddressBits::new(context.capabilities().pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let pages = [context.allocate_page()?, context.allocate_page()?];
    for (page, value) in pages.iter().zip(VALUES) {
        let initialized = vmsa_test_harness::expect_completed(
            context.write_u64(page.virtual_address() as u64, value),
        );
        if !matches!(initialized, TestResult::Pass) {
            return initialized;
        }
    }
    let mut stage1_roots = [
        Some(context.allocate_root()?),
        Some(context.allocate_root()?),
    ];
    for (root, ipa) in stage1_roots.iter_mut().zip(IPA) {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(
            root.as_mut().ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::address::Level::L1,
            bits.get(),
            output.get(),
        )?;
        mapper.map_leaf(ADDRESS, ipa, leaf, MappingAttributes::READ_WRITE)?;
    }
    let mut stage2_roots = [
        Some(context.allocate_root()?),
        Some(context.allocate_root()?),
    ];
    for (index, root) in stage2_roots.iter_mut().enumerate() {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            Stage2Regime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(
            root.as_mut().ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::address::Level::L1,
            bits.get(),
            output.get(),
        )?;
        mapper.map_leaf(
            IPA[index],
            pages[index].phys_addr(),
            leaf,
            MappingAttributes::READ_WRITE,
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        let recovery_regions = [
            0,
            0x8000_0000,
            stage1_roots[0]
                .as_ref()
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
                .phys_addr()
                & !((1u64 << 30) - 1),
            stage1_roots[1]
                .as_ref()
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
                .phys_addr()
                & !((1u64 << 30) - 1),
        ];
        for (candidate_index, candidate) in recovery_regions.into_iter().enumerate() {
            if candidate != (IPA[index] & !((1u64 << 30) - 1))
                && !recovery_regions[..candidate_index].contains(&candidate)
            {
                mapper.map_leaf(candidate, candidate, start, recovery)?;
            }
        }
    }
    let stage1_setup = TranslationSetup {
        root: PhysicalAddress::new(
            stage1_roots[0]
                .as_ref()
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
                .phys_addr(),
        ),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64,
        input_bits: bits,
        output_bits: output,
        start_level: Some(start),
        asid: Some(Asid(0x61)),
        vmid: None,
        controls: vmsa64_el1_stage1_controls_4k(bits, output)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT.with_raw_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            0xff,
        ),
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(
            stage2_roots[0]
                .as_ref()
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
                .phys_addr(),
        ),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64,
        input_bits: bits,
        output_bits: output,
        start_level: Some(start),
        asid: None,
        vmid: Some(Vmid(0x62)),
        controls: vmsa64_stage2_controls_4k(bits, output, start)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let mut combined = context.install_combined_owned(
        stage1_roots[0]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage1_setup,
        stage2_roots[0]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_setup,
    )?;
    let initial = expect_value(combined.read_u64(ADDRESS), VALUES[0]);
    if !matches!(initial, TestResult::Pass) {
        return initial;
    }
    combined.stage1_mut()?.adopt_and_switch_lower_stage1_root(
        stage1_roots[1]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        Asid(0x61),
    )?;
    combined.stage2_mut()?.adopt_and_switch_stage2_root(
        stage2_roots[1]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        Vmid(0x62),
    )?;
    combined.tlbi(TlbiScope::InnerShareable, CombinedTlbiOperation::All)?;
    expect_value(combined.read_u64(ADDRESS), VALUES[1])
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
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT.with_raw_attribute(
        vmsa_test_harness::MemoryAttributeSlot::new(0)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        0xff,
    );

    // This registered row exercises the successfully mapped combined regime.
    // Fault coordinates are independently registered in the fault matrix.
    for mode in 1u16..2 {
        let omit_target = mode == 2;
        let data_page = context.allocate_page()?;
        let replacement_page = context.allocate_page()?;
        const DATA_VALUE: u64 = 0x434f_4d42_494e_4544;
        const REPLACEMENT_VALUE: u64 = 0x5245_504c_4143_4544;
        if !matches!(
            context.write_u64(data_page.virtual_address() as u64, DATA_VALUE),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        if !matches!(
            context.write_u64(replacement_page.virtual_address() as u64, REPLACEMENT_VALUE),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        let mut stage1_root = context.allocate_root()?;
        let mut stage2_root = context.allocate_root()?;
        let table_walk_region = stage1_root.phys_addr() & !0x3fff_ffff;
        let target_region = table_walk_region ^ 0x4000_0000;
        let target_ipa = target_region | (data_page.phys_addr() - table_walk_region);
        let replacement_ipa = target_region | (replacement_page.phys_addr() - table_walk_region);
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                LowerRegime,
                aarch64_vmsa::config::granule::Granule4KiB,
                aarch64_vmsa::config::format::Vmsa64,
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
        }
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                Stage2Regime,
                aarch64_vmsa::config::granule::Granule4KiB,
                aarch64_vmsa::config::format::Vmsa64,
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
                    target_ipa,
                    data_page.phys_addr(),
                    level3,
                    MappingAttributes::READ_WRITE,
                )?;
                mapper.map_leaf(
                    replacement_ipa,
                    replacement_page.phys_addr(),
                    level3,
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
        let mut combined =
            context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
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
        let query = combined.translate(VIRTUAL_ADDRESS, TranslationQueryAccess::Read);
        if omit_target {
            match query {
                TranslationQueryResult::Fault { stage2: true, .. } => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
        } else {
            match query {
                TranslationQueryResult::Success {
                    physical_address, ..
                } if physical_address == data_page.phys_addr() => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            let original_pair = match combined.read_pair_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::CompletedPair { first, second } => (first, second),
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
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
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
            match combined.execute(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.access == vmsa_test_harness::AccessKind::Execute => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
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
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
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
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(target_ipa, MappingAttributes::READ_ONLY)?;
            match combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 4) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            }
            combined.stage2_mut()?.protect_for::<
                Stage2Regime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(target_ipa, MappingAttributes::READ_WRITE)?;
            if !matches!(
                combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }

            combined.stage1_mut()?.remap_for::<
                LowerRegime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(VIRTUAL_ADDRESS, replacement_ipa, MappingAttributes {
                writable: true,
                executable: false,
                user_accessible: true,
            })?;
            combined.tlbi(
                vmsa_test_harness::TlbiScope::InnerShareable,
                vmsa_test_harness::CombinedTlbiOperation::Stage1(
                    vmsa_test_harness::TlbiOperation::VirtualAddress(VIRTUAL_ADDRESS),
                ),
            )?;
            if !matches!(combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == REPLACEMENT_VALUE)
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }

            combined.stage1_mut()?.unmap_for::<
                LowerRegime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(VIRTUAL_ADDRESS)?;
            combined.tlbi(
                vmsa_test_harness::TlbiScope::InnerShareable,
                vmsa_test_harness::CombinedTlbiOperation::Stage1(
                    vmsa_test_harness::TlbiOperation::VirtualAddress(VIRTUAL_ADDRESS),
                ),
            )?;
            let stage1_fault = vmsa_test_harness::expect_matching_fault(
                combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::FaultMatcher::new(
                    vmsa_test_harness::ExpectedFault::translation_read_stage1(),
                )
                .at_address(VIRTUAL_ADDRESS),
            );
            if !matches!(stage1_fault, TestResult::Pass) {
                return stage1_fault;
            }
            combined.stage1_mut()?.map_for::<
                LowerRegime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(VIRTUAL_ADDRESS, replacement_ipa, level3, MappingAttributes {
                writable: true,
                executable: false,
                user_accessible: true,
            })?;

            combined.stage2_mut()?.remap_for::<
                Stage2Regime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(replacement_ipa, data_page.phys_addr(), MappingAttributes::READ_WRITE)?;
            combined.tlbi(
                vmsa_test_harness::TlbiScope::InnerShareable,
                vmsa_test_harness::CombinedTlbiOperation::Stage2(
                    vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(replacement_ipa),
                ),
            )?;
            if !matches!(combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE)
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
            combined.stage2_mut()?.unmap_for::<
                Stage2Regime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(replacement_ipa)?;
            combined.tlbi(
                vmsa_test_harness::TlbiScope::InnerShareable,
                vmsa_test_harness::CombinedTlbiOperation::Stage2(
                    vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(replacement_ipa),
                ),
            )?;
            let stage2_fault = vmsa_test_harness::expect_matching_fault(
                combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::FaultMatcher::new(
                    vmsa_test_harness::ExpectedFault::translation_read_stage2(),
                )
                .at_address(VIRTUAL_ADDRESS),
            );
            if !matches!(stage2_fault, TestResult::Pass) {
                return stage2_fault;
            }
            combined.stage2_mut()?.map_for::<
                Stage2Regime,
                aarch64_vmsa::config::format::Vmsa64,
                aarch64_vmsa::config::granule::Granule4KiB,
            >(replacement_ipa, replacement_page.phys_addr(), level3, MappingAttributes::READ_WRITE)?;
            combined.tlbi(
                vmsa_test_harness::TlbiScope::InnerShareable,
                vmsa_test_harness::CombinedTlbiOperation::Stage2(
                    vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(replacement_ipa),
                ),
            )?;
            if !matches!(combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == REPLACEMENT_VALUE)
            {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
        }
        combined.restore()?;
    }
    TestResult::Pass
}
