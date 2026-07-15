use vmsa_test_harness::{
    AddressBits, ExpectedFault, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TestContext, TestResult, TranslationControls, TranslationSetup,
    TranslationStage, expect_fault, expect_value,
};

pub fn live_range_mapping<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x661f_f000;
    const PAGES: u64 = 3;
    let pages = context.allocate_contiguous(PAGES as usize)?;
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
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    let injected_range =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Map, 0, || {
            translation
                .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    pages.phys_addr(),
                    PAGES * 4096,
                    LookupLevel::new(3).expect("level 3 is valid"),
                    MappingAttributes::READ_WRITE,
                )
        });
    if !matches!(
        injected_range,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for index in 0..PAGES {
        if translation
            .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS + index * 4096,
            )?
            .is_some()
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let outcome = translation
        .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
            pages.phys_addr(),
            PAGES * 4096,
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    let expected_tables = 2;
    if outcome.mappings_created != PAGES
        || outcome.bytes_mapped != PAGES * 4096
        || outcome.tables_allocated != expected_tables
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let final_mapping = translation
        .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS + (PAGES - 1) * 4096,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if final_mapping.output != pages.phys_addr() + (PAGES - 1) * 4096
        || final_mapping.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS + (PAGES - 1) * 4096,
        )?;
    let first_walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?;
    let steps = walk.steps();
    let first_steps = first_walk.steps();
    let effective_start = translation
        .setup()
        .start_level
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .get();
    let expected_length = usize::try_from(4 - i16::from(effective_start))
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if steps.len() != expected_length || first_steps.len() != expected_length {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let first_leaf_table = first_steps
        .get(expected_length - 2)
        .and_then(|step| *step)
        .and_then(|step| step.next_table);
    let final_leaf_table = steps
        .get(expected_length - 2)
        .and_then(|step| *step)
        .and_then(|step| step.next_table);
    if first_leaf_table.is_none()
        || final_leaf_table.is_none()
        || first_leaf_table == final_leaf_table
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for (index, expected_level) in (effective_start..3).enumerate() {
        let Some(step) = steps[index] else {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        };
        if step.level != LookupLevel::new(expected_level).expect("walk level is valid")
            || step.kind != vmsa_test_harness::WalkDescriptorKind::Table
            || step.raw.is_none()
            || step.next_table.is_none()
            || step.output.is_some()
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let Some(leaf) = walk.leaf() else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    if leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.raw.is_none()
        || leaf.next_table.is_some()
        || leaf.output != Some(pages.phys_addr() + (PAGES - 1) * 4096)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for index in 0..PAGES {
        let address = ADDRESS + index * 4096;
        let value = 0x5241_4e47_4500_0000 | index;
        let written = vmsa_test_harness::expect_completed(context.write_u64(address, value));
        if !matches!(written, TestResult::Pass) {
            return written;
        }
        let read = expect_value(context.read_u64(address), value);
        if !matches!(read, TestResult::Pass) {
            return read;
        }
    }
    for index in 0..PAGES {
        let removed = translation
            .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS + index * 4096,
            )?;
        if removed.output != pages.phys_addr() + index * 4096 {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    for index in 0..PAGES {
        let fault = expect_fault(
            context.read_u64(ADDRESS + index * 4096),
            ExpectedFault::translation_read_stage1(),
        );
        if !matches!(fault, TestResult::Pass) {
            return fault;
        }
    }
    TestResult::Pass
}

pub fn zero_range_outcome(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(u64::MAX, u64::MAX, 0, 3, MappingAttributes::READ_WRITE)
        != Ok(vmsa_test_harness::MapRangeResult {
            mappings_created: 0,
            bytes_mapped: 0,
            tables_allocated: 0,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn single_range_outcome(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(0, 0, 4096, 3, MappingAttributes::READ_WRITE)
        != Ok(vmsa_test_harness::MapRangeResult {
            mappings_created: 1,
            bytes_mapped: 4096,
            tables_allocated: 3,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn invalid_range_length(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(0, 0, 4097, 3, MappingAttributes::READ_WRITE)
        != Err(
            vmsa_test_harness::MapperOperationError::LengthNotMappingMultiple {
                length: 4097,
                mapping_size: 4096,
            },
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn unaligned_range_input(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(1, 0, 4096, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::UnalignedInput {
            address: 1,
            align: 4096,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn unaligned_range_output(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(0, 1, 4096, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::UnalignedOutput {
            address: 1,
            align: 4096,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn input_range_end_out_of_range(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_range_exact(0xffff_f000, 0, 8192, 3, MappingAttributes::READ_WRITE)
        != Err(
            vmsa_test_harness::MapperOperationError::InputAddressOutOfRange {
                address: 0x1_0000_0fff,
                address_bits: 32,
            },
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn input_range_arithmetic_overflow(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::NEG1, 57, 48)?;
    if mapper.map_range_exact(u64::MAX - 4095, 0, 8192, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::AddressOverflow)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn output_range_arithmetic_overflow(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(&mut root, aarch64_vmsa::address::Level::L0, 32, 48)?;
    if mapper.map_range_exact(0, u64::MAX - 4095, 8192, 3, MappingAttributes::READ_WRITE)
        != Err(
            vmsa_test_harness::MapperOperationError::OutputAddressOverflow {
                base: u64::MAX - 4095,
                offset: 8191,
            },
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn frame_provider_error(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(
        &mut root,
        aarch64_vmsa::address::Level::L0,
        32,
        32,
    )?;
    let result = context.with_table_allocation_failure(0, || {
        mapper.map_attributes_leaf_exact(0, 0, 3, MappingAttributes::READ_WRITE)
    })?;
    if result
        != Err(vmsa_test_harness::MapperOperationError::FrameProvider(
            vmsa_test_harness::MemoryError::InjectedFailure,
        ))
        || mapper.translate(0)?.is_some()
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    mapper
        .map_attributes_leaf_exact(0, 0, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if mapper.translate(0)?.is_none() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

macro_rules! provider_probe_case {
    ($name:ident, $method:ident) => {
        pub fn $name(
            context: &mut TestContext<'_, crate::CurrentEnvironment>,
        ) -> TestResult {
            if context.$method() {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::InvalidState.into()
            }
        }
    };
}

provider_probe_case!(table_access_provider_error, verify_mapper_table_access_error);
provider_probe_case!(descriptor_write_provider_error, verify_mapper_descriptor_write_error);
provider_probe_case!(frame_allocate_provider_error, verify_mapper_frame_allocate_error);
provider_probe_case!(frame_free_provider_error, verify_mapper_frame_free_error);

pub fn break_before_make_ordering(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(
        &mut root,
        aarch64_vmsa::address::Level::L0,
        32,
        32,
    )?;
    if mapper.verify_break_before_make_ordering() {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}

pub fn range_partial_prefix_postcondition(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    const PAGE: u64 = 4096;
    const START: u64 = 2 * 1024 * 1024 - PAGE;
    let output = context.allocate_contiguous(3)?;
    let mut root = context.allocate_root()?;
    let baseline_allocations = context.arena_allocation_count();
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(
        &mut root,
        aarch64_vmsa::address::Level::L0,
        32,
        32,
    )?;
    let failed = context.with_table_allocation_failure(3, || {
        mapper.map_range_exact(
            START,
            output.phys_addr(),
            3 * PAGE,
            3,
            MappingAttributes::READ_WRITE,
        )
    })?;
    if failed
        != Err(vmsa_test_harness::MapperOperationError::FrameProvider(
            vmsa_test_harness::MemoryError::InjectedFailure,
        ))
        || mapper.translate(START)?.map(|mapping| mapping.output) != Some(output.phys_addr())
        || mapper.translate(START + PAGE)?.is_some()
        || mapper.translate(START + 2 * PAGE)?.is_some()
        || context.arena_allocation_count() != baseline_allocations + 3
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let completed = mapper
        .map_range_exact(
            START + PAGE,
            output.phys_addr() + PAGE,
            2 * PAGE,
            3,
            MappingAttributes::READ_WRITE,
        )
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if completed.mappings_created != 2
        || completed.bytes_mapped != 2 * PAGE
        || completed.tables_allocated != 1
        || context.arena_allocation_count() != baseline_allocations + 4
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let third = mapper
        .unmap_reclaim_exact(START + 2 * PAGE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let second = mapper
        .unmap_reclaim_exact(START + PAGE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let first = mapper
        .unmap_reclaim_exact(START)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if third.tables_freed != 0
        || third.root_now_empty
        || second.tables_freed != 1
        || second.root_now_empty
        || first.tables_freed != 3
        || !first.root_now_empty
        || context.arena_allocation_count() != baseline_allocations
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn mapper_lpa2<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::descriptor::Vmsa64Lpa2: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::regime::StageOf<E::Regime>,
        aarch64_vmsa::address::Granule4KiB,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
            LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                E::Regime,
                aarch64_vmsa::address::Granule4KiB,
            >,
            TableFields = aarch64_vmsa::regime::TableFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                E::Regime,
                aarch64_vmsa::address::Granule4KiB,
            >,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let Some(start_level) = LookupLevel::new(-1) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(address_bits) = AddressBits::new(52) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let mut mapper =
        context.offline_mapper_lpa2_4k(&mut root, start_level, address_bits, address_bits)?;
    mapper.map_page(
        page.virtual_address() as u64,
        page.phys_addr(),
        MappingAttributes::READ_WRITE,
    )?;
    TestResult::Pass
}

pub fn mapper_d128<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::regime::StageOf<E::Regime>,
        aarch64_vmsa::address::Granule4KiB,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let Some(start_level) = LookupLevel::new(-2) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(address_bits) = AddressBits::new(52) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let mut mapper =
        context.offline_mapper_d128_4k(&mut root, start_level, address_bits, address_bits)?;
    mapper.map_page(page.virtual_address() as u64, page.phys_addr())?;
    TestResult::Pass
}

pub fn mapper_16k<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule16KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule16KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule16KiB,
    >: Copy,
{
    let mut root = context.allocate_root_16k()?;
    let output = context.allocate_root_16k()?;
    let mut mapper = context.offline_mapper_16k(&mut root)?;
    const ADDRESS: u64 = 0x4000_0000;
    mapper.map_attributes_leaf(
        ADDRESS,
        output.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(ADDRESS)?;
    let leaf = walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() < 2
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.output != Some(output.phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn mapper_64k<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule64KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule64KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule64KiB,
    >: Copy,
{
    let mut root = context.allocate_root_64k()?;
    let output = context.allocate_root_64k()?;
    let mut mapper = context.offline_mapper_64k(&mut root)?;
    const ADDRESS: u64 = 0x8000_0000;
    mapper.map_attributes_leaf(
        ADDRESS,
        output.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(ADDRESS)?;
    let leaf = walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() < 2
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.output != Some(output.phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn exact_block_outcome(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    let outcome = mapper.map_attributes_leaf_exact(0, 0, 2, MappingAttributes::READ_WRITE);
    let translated = mapper.translate(0x1234)?;
    if outcome
        != Ok(vmsa_test_harness::MapLeafResult {
            tables_allocated: 2,
            level: LookupLevel::new(2).expect("level 2 is valid"),
            kind: vmsa_test_harness::WalkDescriptorKind::Block,
            covered_size: 2 * 1024 * 1024,
        })
        || translated
            != Some(vmsa_test_harness::MappingInspection {
                output: 0x1234,
                level: LookupLevel::new(2).expect("level 2 is valid"),
            })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn exact_page_outcome(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    let outcome = mapper.map_attributes_leaf_exact(0, 0, 3, MappingAttributes::READ_WRITE);
    if outcome
        != Ok(vmsa_test_harness::MapLeafResult {
            tables_allocated: 3,
            level: LookupLevel::new(3).expect("level 3 is valid"),
            kind: vmsa_test_harness::WalkDescriptorKind::Page,
            covered_size: 4096,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn block_page_boundary(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    let block = mapper
        .map_attributes_leaf_exact(0, 0, 2, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let page = mapper
        .map_attributes_leaf_exact(
            2 * 1024 * 1024,
            4 * 1024 * 1024,
            3,
            MappingAttributes::READ_WRITE,
        )
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if block.kind != vmsa_test_harness::WalkDescriptorKind::Block
        || block.covered_size != 2 * 1024 * 1024
        || page.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || page.covered_size != 4096
        || page.tables_allocated != 1
        || mapper
            .translate(2 * 1024 * 1024 - 1)?
            .map(|mapping| mapping.output)
            != Some(2 * 1024 * 1024 - 1)
        || mapper
            .translate(2 * 1024 * 1024)?
            .map(|mapping| mapping.output)
            != Some(4 * 1024 * 1024)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn terminal_table_growth_boundary(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    const LAST_IN_TABLE: u64 = 2 * 1024 * 1024 - 4096;
    const FIRST_NEXT_TABLE: u64 = 2 * 1024 * 1024;
    let last = mapper
        .map_attributes_leaf_exact(LAST_IN_TABLE, 0x4000, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let next = mapper
        .map_attributes_leaf_exact(FIRST_NEXT_TABLE, 0x8000, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if last.tables_allocated != 3
        || next.tables_allocated != 1
        || mapper
            .translate(LAST_IN_TABLE)?
            .map(|mapping| mapping.output)
            != Some(0x4000)
        || mapper
            .translate(FIRST_NEXT_TABLE)?
            .map(|mapping| mapping.output)
            != Some(0x8000)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn maximum_input_page(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    match mapper.map_attributes_leaf_exact(0xffff_f000, 0, 3, MappingAttributes::READ_WRITE) {
        Ok(_) => TestResult::Pass,
        Err(_) => vmsa_test_harness::HarnessError::InvalidState.into(),
    }
}

pub fn one_past_input_page(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    let actual =
        mapper.map_attributes_leaf_exact(0x1_0000_0000, 0, 3, MappingAttributes::READ_WRITE);
    if actual
        != Err(
            vmsa_test_harness::MapperOperationError::InputAddressOutOfRange {
                address: 0x1_0000_0000,
                address_bits: 32,
            },
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn maximum_output_page(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    match mapper.map_attributes_leaf_exact(0, 0xffff_f000, 3, MappingAttributes::READ_WRITE) {
        Ok(_) => TestResult::Pass,
        Err(_) => vmsa_test_harness::HarnessError::InvalidState.into(),
    }
}

pub fn one_past_output_page(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    let actual =
        mapper.map_attributes_leaf_exact(0, 0x1_0000_0000, 3, MappingAttributes::READ_WRITE);
    if actual
        != Err(
            vmsa_test_harness::MapperOperationError::OutputAddressOutOfRange {
                address: 0x1_0000_0000,
                output_address_bits: 32,
            },
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn unaligned_leaf_input(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_attributes_leaf_exact(1, 0, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::UnalignedInput {
            address: 1,
            align: 4096,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn unaligned_leaf_output(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_attributes_leaf_exact(0, 1, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::UnalignedOutput {
            address: 1,
            align: 4096,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

fn invalid_leaf_level(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
    level: i8,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    if mapper.map_attributes_leaf_exact(0, 0, level, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::InvalidLeafLevel {
            level,
            root_level: 0,
            final_level: 3,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn leaf_level_below_root(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    invalid_leaf_level(context, -1)
}

pub fn leaf_level_past_final(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    invalid_leaf_level(context, 4)
}

pub fn already_mapped_leaf(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa64,
    >(&mut root, aarch64_vmsa::address::Level::L0, 32, 32)?;
    mapper
        .map_attributes_leaf_exact(0, 0, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if mapper.map_attributes_leaf_exact(0, 0x1000, 3, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::AlreadyMapped {
            input: 0,
            level: 3,
            entry_index: 0,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn already_mapped_table(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    mapper
        .map_attributes_leaf_exact(0, 0, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if mapper.map_attributes_leaf_exact(0, 0, 2, MappingAttributes::READ_WRITE)
        != Err(vmsa_test_harness::MapperOperationError::AlreadyMapped {
            input: 0,
            level: 2,
            entry_index: 0,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn not_mapped_translate(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    if mapper.translate(0)?.is_some() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn not_mapped_unmap(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    if mapper.unmap_exact(0) != Err(vmsa_test_harness::MapperOperationError::NotMapped { input: 0 })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn not_mapped_reclaim(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    if mapper.unmap_reclaim_exact(0)
        != Err(vmsa_test_harness::MapperOperationError::NotMapped { input: 0 })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn non_leaf_base_unmap(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    mapper
        .map_attributes_leaf_exact(0, 0, 2, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if mapper.unmap_exact(0x1000)
        != Err(vmsa_test_harness::MapperOperationError::InputNotLeafBase {
            input: 0x1000,
            covered_input_base: 0,
            covered_size: 2 * 1024 * 1024,
            level: 2,
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn reclaim_sibling_lifecycle(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper_for_format_with_geometry::<crate::CurrentRegime, aarch64_vmsa::address::Granule4KiB, aarch64_vmsa::descriptor::Vmsa64>(
        &mut root, aarch64_vmsa::address::Level::L0, 32, 32,
    )?;
    mapper
        .map_attributes_leaf_exact(0, 0x2000, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    mapper
        .map_attributes_leaf_exact(0x1000, 0x3000, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    let first = mapper
        .unmap_reclaim_exact(0)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if first
        != (vmsa_test_harness::UnmapResult {
            mapping: vmsa_test_harness::MappingInspection {
                output: 0x2000,
                level: LookupLevel::new(3).expect("level 3 is valid"),
            },
            tables_freed: 0,
            root_now_empty: false,
        })
        || mapper.translate(0x1000)?
            != Some(vmsa_test_harness::MappingInspection {
                output: 0x3000,
                level: LookupLevel::new(3).expect("level 3 is valid"),
            })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let last = mapper
        .unmap_reclaim_exact(0x1000)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if last.tables_freed != 3 || !last.root_now_empty || mapper.translate(0x1000)?.is_some() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    mapper
        .map_attributes_leaf_exact(0, 0x4000, 3, MappingAttributes::READ_WRITE)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if mapper.translate(0)?
        != Some(vmsa_test_harness::MappingInspection {
            output: 0x4000,
            level: LookupLevel::new(3).expect("level 3 is valid"),
        })
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn live_reclaim_outcome<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x6620_0000;
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
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let written =
        vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x5245_434c_4149_4d45));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    let outcome = translation
        .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?;
    if outcome.mapping.output != page.phys_addr() {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: page.phys_addr(),
            actual: outcome.mapping.output,
        });
    }
    if outcome.mapping.level != LookupLevel::new(3).expect("level 3 is valid") {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 3,
            actual: outcome.mapping.level.get() as u64,
        });
    }
    if outcome.tables_freed != 1 {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 1,
            actual: outcome.tables_freed as u64,
        });
    }
    if outcome.root_now_empty {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0,
            actual: 1,
        });
    }
    TestResult::Pass
}

pub fn live_reclaim_post_fault<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x6620_0000;
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
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    translation
        .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?;
    expect_fault(
        context.read_u64(ADDRESS),
        ExpectedFault::translation_read_stage1(),
    )
}
