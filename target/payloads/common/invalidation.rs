use vmsa_test_harness::{
    AddressBits, Asid, ExpectedFault, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TestContext, TestResult, TranslationControls, TranslationSetup,
    TranslationStage, Vmid, expect_fault, expect_value, vmsa64_stage2_controls_4k,
};

pub fn stage1_translation_cycle<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
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
    const LIVE_ADDRESS: u64 = 0x6000_0000;
    const LIVE_VALUE: u64 = 0x4c49_5645_4d41_5050;
    const RANGE_ADDRESS: u64 = 0x6200_0000;
    const BLOCK_ADDRESS: u64 = 0x7000_0000;
    const BLOCK_OUTPUT: u64 = 0x8000_0000;
    const BLOCK_OFFSET: u64 = 0x1234;

    let page = context.allocate_page()?;
    let range = context.allocate_contiguous(2)?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let Some(input_bits) = AddressBits::new(capabilities.va_bits.min(48)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(output_bits) = AddressBits::new(capabilities.pa_bits.min(48)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let setup = TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
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
    };
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        LIVE_ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let mapping = translation
        .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if mapping.output != page.phys_addr()
        || mapping.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        BLOCK_ADDRESS,
        BLOCK_OUTPUT,
        LookupLevel::new(2).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let block_walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            BLOCK_ADDRESS + BLOCK_OFFSET,
        )?;
    let block_leaf = block_walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if block_leaf.kind != vmsa_test_harness::WalkDescriptorKind::Block
        || block_leaf.level != LookupLevel::new(2).expect("level 2 is valid")
        || block_leaf.output != Some(BLOCK_OUTPUT + BLOCK_OFFSET)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    match context.translate_current_stage1(
        BLOCK_ADDRESS + BLOCK_OFFSET,
        vmsa_test_harness::TranslationQueryAccess::Read,
    ) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == BLOCK_OUTPUT + BLOCK_OFFSET => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    let removed_block = translation
        .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            BLOCK_ADDRESS,
        )?;
    if removed_block.output != BLOCK_OUTPUT
        || removed_block.level != LookupLevel::new(2).expect("level 2 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let range_outcome = translation
        .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            RANGE_ADDRESS,
            range.phys_addr(),
            8192,
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    if range_outcome.mappings_created != 2 || range_outcome.bytes_mapped != 8192 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if translation.tlbi(vmsa_test_harness::TlbiOperation::Address(LIVE_ADDRESS + 1))
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.tlbi_scoped(
        vmsa_test_harness::TlbiScope::Local,
        vmsa_test_harness::TlbiOperation::VirtualAddress(LIVE_ADDRESS),
    )?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(
        LIVE_ADDRESS,
    ))?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualRange {
        start: RANGE_ADDRESS,
        pages: 2,
    })?;
    if translation.tlbi(vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(LIVE_ADDRESS))
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.tlbi(vmsa_test_harness::TlbiOperation::All)?;
    let write = context.write_u64(LIVE_ADDRESS, LIVE_VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let value_result = expect_value(context.read_u64(LIVE_ADDRESS), LIVE_VALUE);
    if !matches!(value_result, TestResult::Pass) {
        return value_result;
    }
    for (offset, value) in [(0, LIVE_VALUE + 3), (4096, LIVE_VALUE + 4)] {
        let write = context.write_u64(RANGE_ADDRESS + offset, value);
        if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(write);
        }
        let read = expect_value(context.read_u64(RANGE_ADDRESS + offset), value);
        if !matches!(read, TestResult::Pass) {
            return read;
        }
    }
    for address in [RANGE_ADDRESS, RANGE_ADDRESS + 4096] {
        translation
            .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                address,
            )?;
    }
    for address in [RANGE_ADDRESS, RANGE_ADDRESS + 4096] {
        let result = expect_fault(
            context.read_u64(address),
            ExpectedFault::translation_read_stage1(),
        );
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    let rejected_remap = translation
        .remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
            page.phys_addr() + 1,
            MappingAttributes::READ_WRITE,
        );
    if rejected_remap != Err(vmsa_test_harness::HarnessError::InvalidState) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = expect_value(context.read_u64(LIVE_ADDRESS), LIVE_VALUE);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    let protected = translation
        .protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
            MappingAttributes::READ_ONLY,
        )?;
    if protected.output != page.phys_addr()
        || protected.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let read_only = expect_fault(
        context.write_u64(LIVE_ADDRESS, LIVE_VALUE.wrapping_add(1)),
        ExpectedFault::permission_write(),
    );
    if !matches!(read_only, TestResult::Pass) {
        return read_only;
    }
    translation.protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        LIVE_ADDRESS,
        MappingAttributes::READ_WRITE,
    )?;
    let remap_value = LIVE_VALUE.wrapping_add(2);
    let remapped_write = context.write_u64(LIVE_ADDRESS, remap_value);
    if !matches!(
        remapped_write,
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::expect_completed(remapped_write);
    }
    let remapped_read = expect_value(context.read_u64(LIVE_ADDRESS), remap_value);
    if !matches!(remapped_read, TestResult::Pass) {
        return remapped_read;
    }
    let reclaimed = translation
        .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
        )?;
    if reclaimed.tables_freed == 0 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let final_fault = expect_fault(
        context.read_u64(LIVE_ADDRESS),
        ExpectedFault::translation_read_stage1(),
    );
    if !matches!(final_fault, TestResult::Pass) {
        return final_fault;
    }
    translation.restore()?;
    TestResult::Pass
}

pub fn lower_stage1_asid_isolation<E, R>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    R: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        R,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x6600_0000;
    let first_page = context.allocate_page()?;
    let second_page = context.allocate_page()?;
    let first_root = context.allocate_root()?;
    let second_root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT.with_raw_attribute(
        vmsa_test_harness::MemoryAttributeSlot::new(0)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        0xff,
    );
    let mut first_effective_setup = None;
    let mut roots = [Some(first_root), Some(second_root)];
    for (index, page, asid) in [(0, first_page, Asid(11)), (1, second_page, Asid(12))] {
        let root = roots[index]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let setup = TranslationSetup {
            root: PhysicalAddress::new(root.phys_addr()),
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: Some(asid),
            vmid: None,
            controls,
            stage1_memory,
            regime,
        };
        let mut translation = context.install_lower_owned(root, setup)?;
        translation
            .map_for::<R, aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
                page.phys_addr(),
                LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                MappingAttributes {
                    writable: true,
                    executable: false,
                    user_accessible: true,
                },
            )?;
        if index == 0 {
            if !matches!(
                context.write_u64(page.virtual_address() as u64, 7),
                vmsa_test_harness::AccessResult::Completed { .. }
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            for execution_context in [
                vmsa_test_harness::ExecutionContext::El1,
                vmsa_test_harness::ExecutionContext::El0UnderEl1,
            ] {
                let mut execution = context.execution(execution_context)?;
                let atomic = execution.atomic_swap_u64(ADDRESS, 11);
                if !matches!(
                    atomic,
                    vmsa_test_harness::AccessResult::Completed { value: 7 }
                ) || !matches!(
                    execution.exclusive_add_u64(ADDRESS, 5),
                    vmsa_test_harness::AccessResult::Completed { value: 11 }
                ) {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
                execution.finish()?;
                if !matches!(
                    context.write_u64(page.virtual_address() as u64, 7),
                    vmsa_test_harness::AccessResult::Completed { .. }
                ) {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
            }
        }
        if asid == Asid(11) {
            first_effective_setup = Some(translation.setup());
        }
        translation.tlbi(vmsa_test_harness::TlbiOperation::Asid(asid))?;
        translation.tlbi_scoped(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::TlbiOperation::Asid(asid),
        )?;
        if translation.tlbi(vmsa_test_harness::TlbiOperation::Asid(Asid(asid.0 + 1)))
            != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        match context
            .translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read)
        {
            vmsa_test_harness::TranslationQueryResult::Success {
                physical_address, ..
            } if physical_address == page.phys_addr() => {}
            _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
        }
        roots[index] = Some(translation.restore_owned()?);
    }
    let setup = first_effective_setup.ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let first_root = roots[0]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let second_root = roots[1]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut translation = context.install_lower_owned(first_root, setup)?;
    let first_root = translation.initial_root()?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == first_page.phys_addr() => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    translation.adopt_and_switch_lower_stage1_root(second_root, Asid(12))?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == second_page.phys_addr() => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    translation.switch_lower_stage1_root(first_root, Asid(11))?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == first_page.phys_addr() => TestResult::Pass,
        _ => vmsa_test_harness::HarnessError::InvalidState.into(),
    }
}

pub fn stage2_translation_cycle<E, R>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    R: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        R,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    let page = match context.allocate_page() {
        Ok(page) => page,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let mut root = match context.allocate_root() {
        Ok(root) => root,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let Some(input_bits) = AddressBits::new(context.capabilities().pa_bits.min(39)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(output_bits) = AddressBits::new(context.capabilities().pa_bits.min(48)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(start_level) = LookupLevel::new(1) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    {
        let mut mapper = match context.offline_mapper_for_format_with_geometry::<
            R,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            &mut root,
            aarch64_vmsa::address::Level::new(start_level.get() as i8),
            input_bits.get(),
            output_bits.get(),
        ) {
            Ok(mapper) => mapper,
            Err(error) => return TestResult::Fail(error.into()),
        };
        if let Err(error) =
            mapper.map_block(0x4000_0000, page.phys_addr(), MappingAttributes::READ_WRITE)
        {
            return TestResult::Fail(error.into());
        }
    }
    let Some(controls) = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let setup = TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: Some(start_level),
        asid: None,
        vmid: Some(Vmid(1)),
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime,
    };
    let mut translation = context.install_owned(root, setup)?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(0x4000_0000))?;
    translation.tlbi(
        vmsa_test_harness::TlbiOperation::IntermediatePhysicalRange {
            start: 0x4000_0000,
            pages: 2,
        },
    )?;
    translation.tlbi_scoped(
        vmsa_test_harness::TlbiScope::Local,
        vmsa_test_harness::TlbiOperation::IntermediatePhysicalRange {
            start: 0x4000_0000,
            pages: 2,
        },
    )?;
    for rejected in [
        vmsa_test_harness::TlbiOperation::VirtualAddress(0x4000_0000),
        vmsa_test_harness::TlbiOperation::VirtualRange {
            start: 0x4000_0000,
            pages: 2,
        },
        vmsa_test_harness::TlbiOperation::IntermediatePhysicalRange {
            start: 0x4000_0000,
            pages: 0,
        },
        vmsa_test_harness::TlbiOperation::IntermediatePhysicalRange {
            start: 0x4000_0001,
            pages: 1,
        },
    ] {
        if translation.tlbi(rejected) != Err(vmsa_test_harness::HarnessError::InvalidState) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    translation.restore()?;
    TestResult::Pass
}

pub fn stage2_vmid_isolation<E, R>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    R: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        R,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x4000_0000;
    let Some(input_bits) = AddressBits::new(39) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let output_width = context.capabilities().pa_bits.min(48);
    let Some(output_bits) = AddressBits::new(output_width) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let Some(start_level) = LookupLevel::new(1) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let Some(controls) = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let pages = [context.allocate_page()?, context.allocate_page()?];
    let mut roots = [
        Some(context.allocate_root()?),
        Some(context.allocate_root()?),
    ];
    for (index, root) in roots.iter_mut().enumerate() {
        let root = root
            .as_mut()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            R,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            root,
            aarch64_vmsa::address::Level::L1,
            input_bits.get(),
            output_bits.get(),
        )?;
        mapper.map_leaf(
            ADDRESS,
            pages[index].phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    }
    for (index, vmid) in [Vmid(0x15), Vmid(0x2a)].into_iter().enumerate() {
        let root = roots[index]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let root_address = PhysicalAddress::new(root.phys_addr());
        let mut translation = context.install_owned(
            root,
            TranslationSetup {
                root: root_address,
                stage: TranslationStage::Stage2,
                granule: Granule::Size4KiB,
                format: vmsa_test_harness::TranslationFormat::Vmsa64,
                input_bits,
                output_bits,
                start_level: Some(start_level),
                asid: None,
                vmid: Some(vmid),
                controls,
                stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
                regime,
            },
        )?;
        if translation.setup().vmid != Some(vmid) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        if translation
            .inspect_for::<R, aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
            )?
            .map(|mapping| mapping.output)
            != Some(pages[index].phys_addr())
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        translation.tlbi(vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(ADDRESS))?;
        translation.tlbi_scoped(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::TlbiOperation::Vmid(vmid),
        )?;
        translation.tlbi(vmsa_test_harness::TlbiOperation::Vmid(vmid))?;
        if translation.tlbi(vmsa_test_harness::TlbiOperation::Vmid(Vmid(vmid.0 + 1)))
            != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        roots[index] = Some(translation.restore_owned()?);
    }
    let root = roots[0]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut reused = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage2,
            granule: Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start_level),
            asid: None,
            vmid: Some(Vmid(0x15)),
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    if reused
        .inspect_for::<R, aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?
        .map(|mapping| mapping.output)
        != Some(pages[0].phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    reused.restore()?;
    TestResult::Pass
}
