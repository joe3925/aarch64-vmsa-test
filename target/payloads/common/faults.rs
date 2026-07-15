use vmsa_test_harness::{ExpectedFault, TestContext, TestResult, expect_fault};

pub fn stage1_address_size(context: &mut TestContext<'_, crate::CurrentEnvironment>) -> TestResult {
    const ADDRESS: u64 = 0x6f00_0000;
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            crate::CurrentRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            &mut root,
            aarch64_vmsa::address::Level::L1,
            32,
            32,
        )?;
        mapper.map_attributes_leaf(
            ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            vmsa_test_harness::MappingAttributes::READ_WRITE,
        )?;
        let leaf = mapper
            .inspect_walk(ADDRESS)?
            .leaf()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut malformed = leaf
            .raw
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        malformed.low |= 1 << 32;
        mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ADDRESS, malformed)?;
        sandbox = context
            .prepare_transition_runtime(&mut mapper, stage1_address_size as *const () as u64)?;
    }
    let bits = vmsa_test_harness::AddressBits::new(32)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size4KiB,
        bits,
        bits,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = vmsa_test_harness::PhysicalAddress::new(root.phys_addr());
    let translation = context.install_owned_in_sandbox(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits: bits,
            output_bits: bits,
            start_level: vmsa_test_harness::LookupLevel::new(1),
            asid: None,
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
        &sandbox,
    )?;
    let result = vmsa_test_harness::expect_matching_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::AddressSize),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: vmsa_test_harness::LookupLevel::new(3),
        })
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(ADDRESS)
        .with_ipa(None),
    );
    translation.restore()?;
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let sentinel = context.allocate_page()?;
    let address = sentinel.virtual_address() as u64;
    let write =
        vmsa_test_harness::expect_completed(context.write_u64(address, 0x4144_4452_5349_5a45));
    if !matches!(write, TestResult::Pass) {
        return write;
    }
    vmsa_test_harness::expect_value(context.read_u64(address), 0x4144_4452_5349_5a45)
}

pub fn current_fault<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    current_fault_expected(context, ExpectedFault::translation_read_stage1())
}

pub fn unexpected_exception_destructive(
    _: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    vmsa_test_architecture::trigger_unexpected_exception();
    vmsa_test_harness::HarnessError::InvalidState.into()
}

pub fn stage2_malformed_walk(
    context: &mut TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const VA: u64 = 0x5f00_0000;
    let input_bits = AddressBits::new(39).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(context.capabilities().pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let leaf_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let page = context.allocate_page()?;
    let mut stage1_root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root()?;
    let table_walk_region = stage1_root.phys_addr() & !0x3fff_ffff;
    let target_region = table_walk_region ^ 0x4000_0000;
    let ipa = target_region | (page.phys_addr() - table_walk_region);
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            aarch64_vmsa::regime::NonSecureEl1Stage1,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            &mut stage1_root,
            aarch64_vmsa::address::Level::L1,
            input_bits.get(),
            output_bits.get(),
        )?;
        mapper.map_leaf(VA, ipa, leaf_level, MappingAttributes::READ_WRITE)?;
    }
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            aarch64_vmsa::regime::NonSecureEl2Stage2,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            &mut stage2_root,
            aarch64_vmsa::address::Level::L1,
            input_bits.get(),
            output_bits.get(),
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_leaf(table_walk_region, table_walk_region, start, recovery)?;
        mapper.map_leaf(0, 0, start, recovery)?;
        mapper.map_leaf(
            ipa,
            page.phys_addr(),
            leaf_level,
            MappingAttributes::READ_WRITE,
        )?;
        let leaf = mapper
            .inspect_walk(ipa)?
            .leaf()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut malformed = leaf
            .raw
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        malformed.low &= !0b10;
        mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ipa, malformed)?;
    }
    let stage1_controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls =
        vmsa_test_harness::vmsa64_stage2_controls_4k(input_bits, output_bits, start)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_address = PhysicalAddress::new(stage1_root.phys_addr());
    let stage2_address = PhysicalAddress::new(stage2_root.phys_addr());
    let mut combined = context.install_combined_owned(
        stage1_root,
        TranslationSetup {
            root: stage1_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start),
            asid: Some(Asid(0x71)),
            vmid: None,
            controls: stage1_controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
        stage2_root,
        TranslationSetup {
            root: stage2_address,
            stage: TranslationStage::Stage2,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start),
            asid: None,
            vmid: Some(Vmid(0x72)),
            controls: stage2_controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    let result = vmsa_test_harness::expect_matching_fault(
        combined.read_u64(VA),
        vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Translation),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage2),
            level: Some(leaf_level),
        })
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(VA)
        .with_ipa(Some(ipa)),
    );
    combined.restore()?;
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let sentinel = context.allocate_page()?;
    let address = sentinel.virtual_address() as u64;
    let write =
        vmsa_test_harness::expect_completed(context.write_u64(address, 0x5332_4d41_4c46_4f52));
    if !matches!(write, TestResult::Pass) {
        return write;
    }
    vmsa_test_harness::expect_value(context.read_u64(address), 0x5332_4d41_4c46_4f52)
}

pub fn current_fault_expected<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
    expected: ExpectedFault,
) -> TestResult {
    expect_fault(
        context.read_u64(crate::runtime_support::invalid_virtual_address(context)),
        expected,
    )
}

pub fn lower_fault_expected<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
    expected: ExpectedFault,
) -> TestResult {
    expect_fault(
        context.lower_read_u64(crate::runtime_support::invalid_virtual_address(context)),
        expected,
    )
}
