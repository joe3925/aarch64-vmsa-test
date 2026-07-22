use vmsa_test_harness::{
    AddressBits, ExpectedFault, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TestContext, TestResult, TranslationControls, TranslationSetup,
    TranslationStage, expect_fault, expect_value,
};

pub fn current_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let native_pas = context.native_pas();
    if context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::FirmwareShared)
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let page = context.allocate_page_in(native_pas)?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::CurrentEl)?;
    let write = execution.write_u64(address, 0x564d_5341_5445_5354);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x564d_5341_5445_5354);
    execution.finish()?;
    result
}

pub fn access_widths<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let pages = context.allocate_contiguous(2)?;
    let base = pages.virtual_address() as u64;
    for result in [
        context.write_u8(base, 0xa5),
        context.write_u16(base + 2, 0xb6c7),
        context.write_u32(base + 4, 0xd8e9_f001),
        context.write_u64(base + 8, 0x1234_5678_9abc_def0),
    ] {
        if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(result);
        }
    }
    for (result, expected) in [
        (context.read_u8(base), 0xa5),
        (context.read_u16(base + 2), 0xb6c7),
        (context.read_u32(base + 4), 0xd8e9_f001),
        (context.read_u64(base + 8), 0x1234_5678_9abc_def0),
    ] {
        let checked = expect_value(result, expected);
        if !matches!(checked, TestResult::Pass) {
            return checked;
        }
    }
    for address in [base + 9, base + 4092] {
        let checked = vmsa_test_harness::expect_matching_fault(
            context.write_u64(address, 0x0fed_cba9_8765_4321),
            vmsa_test_harness::FaultMatcher::new(ExpectedFault {
                status: Some(vmsa_test_harness::FaultStatus::Alignment),
                access: Some(vmsa_test_harness::AccessKind::Write),
                stage: Some(vmsa_test_harness::FaultStage::Stage1),
                level: None,
            })
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(address)
            .with_ipa(None),
        );
        if !matches!(checked, TestResult::Pass) {
            return checked;
        }
    }
    TestResult::Pass
}

pub fn pair_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let first = 0x0123_4567_89ab_cdef;
    let second = 0xfedc_ba98_7654_3210;
    match context.write_pair_u64(address, first, second) {
        vmsa_test_harness::AccessResult::CompletedPair { .. } => {}
        result => return vmsa_test_harness::expect_completed(result),
    }
    match context.read_pair_u64(address) {
        vmsa_test_harness::AccessResult::CompletedPair {
            first: observed_first,
            second: observed_second,
        } if observed_first == first && observed_second == second => {}
        _ => return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into(),
    }
    let fault = expect_fault(
        context.read_pair_u64(address + 1),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Alignment),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
        vmsa_test_harness::ExecutionContext::El0UnderEl2,
    ] {
        let mut execution = context.execution(execution_context)?;
        if !matches!(
            execution.write_pair_u64(address, first, second),
            vmsa_test_harness::AccessResult::CompletedPair { .. }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        match execution.read_pair_u64(address) {
            vmsa_test_harness::AccessResult::CompletedPair {
                first: observed_first,
                second: observed_second,
            } if observed_first == first && observed_second == second => {}
            _ => return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into(),
        }
        execution.finish()?;
    }
    TestResult::Pass
}

pub fn ordered_atomic_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let released = context.write_release_u64(address, 7);
    if !matches!(released, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(released);
    }
    let acquired = expect_value(context.read_acquire_u64(address), 7);
    if !matches!(acquired, TestResult::Pass) {
        return acquired;
    }
    let swapped = expect_value(context.atomic_swap_u64(address, 11), 7);
    if !matches!(swapped, TestResult::Pass) {
        return swapped;
    }
    let exclusive = expect_value(context.exclusive_add_u64(address, 5), 11);
    if !matches!(exclusive, TestResult::Pass) {
        return exclusive;
    }
    let final_value = expect_value(context.read_u64(address), 16);
    if !matches!(final_value, TestResult::Pass) {
        return final_value;
    }
    let alignment = expect_fault(
        context.atomic_swap_u64(address + 1, 0),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Alignment),
            access: None,
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(alignment, TestResult::Pass) {
        return alignment;
    }
    let fault = expect_fault(
        context.exclusive_add_u64(crate::runtime_support::invalid_virtual_address(context), 1),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Translation),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
    ] {
        if !matches!(
            context.write_u64(address, 7),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        let mut execution = context.execution(execution_context)?;
        if !matches!(
            execution.write_release_u64(address, 7),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        if !matches!(
            execution.read_acquire_u64(address),
            vmsa_test_harness::AccessResult::Completed { value: 7 }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        execution.finish()?;
        if !matches!(
            context.read_u64(address),
            vmsa_test_harness::AccessResult::Completed { value: 7 }
        ) {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
    }
    TestResult::Pass
}

pub fn lower_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = match context.allocate_page() {
        Ok(page) => page,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El1)?;
    let write = execution.write_u64(address, 0x4c4f_5745_522d_454c);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x4c4f_5745_522d_454c);
    execution.finish()?;
    result
}

pub fn el0_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl1)?;
    let write = execution.write_u64(address, 0x454c_302d_564d_5341);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x454c_302d_564d_5341);
    execution.finish()?;
    result
}

pub fn el2_el0_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    let write = execution.write_u64(address, 0x454c_3226_302d_564d);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x454c_3226_302d_564d);
    execution.finish()?;
    result
}

pub fn el2_el0_host_atomic_access<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::regime::NonSecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let baseline = el2_el0_access(context);
    if !matches!(baseline, TestResult::Pass) {
        return baseline;
    }
    const ADDRESS: u64 = 0x6a00_0000;
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
            regime: RegimeAttributes::Normal,
        },
    )?;
    translation.map_for::<
        aarch64_vmsa::regime::NonSecureEl2HostStage1,
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
    >(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes {
            writable: true,
            executable: false,
            user_accessible: true,
        },
    )?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, 7),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    if !matches!(
        execution.atomic_swap_u64(ADDRESS, 11),
        vmsa_test_harness::AccessResult::Completed { value: 7 }
    ) || !matches!(
        execution.exclusive_add_u64(ADDRESS, 5),
        vmsa_test_harness::AccessResult::Completed { value: 11 }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    execution.finish()?;
    drop(translation);
    TestResult::Pass
}
