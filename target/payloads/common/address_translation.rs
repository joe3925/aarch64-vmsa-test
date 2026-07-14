use vmsa_test_harness::{RegimeAttributes, TestContext, TestResult};

pub fn address_translation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    match context.translate_current_stage1(address, vmsa_test_harness::TranslationQueryAccess::Read)
    {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == page.phys_addr() => {}
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            return vmsa_test_harness::HarnessError::Memory.into();
        }
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
            return vmsa_test_harness::HarnessError::Environment.into();
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    match context.translate_current_stage1(
        crate::runtime_support::invalid_virtual_address(context),
        vmsa_test_harness::TranslationQueryAccess::Read,
    ) {
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            vmsa_test_harness::HarnessError::Memory.into()
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::InvalidState.into()
        }
    }
}

pub fn lower_address_translation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
    _: RegimeAttributes,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
    ] {
        let mut execution = context.execution(execution_context)?;
        let query = execution.translate(address, vmsa_test_harness::TranslationQueryAccess::Read);
        match query {
            vmsa_test_harness::TranslationQueryResult::Success { .. } => {}
            vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
                return vmsa_test_harness::HarnessError::Environment.into();
            }
            vmsa_test_harness::TranslationQueryResult::Unsupported => {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        execution.finish()?;
    }
    let mut host_el0 = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    match host_el0.translate(address, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    host_el0.finish()?;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El1)?;
    let invalid_query = execution.translate(
        1u64 << context.capabilities().va_bits.min(52),
        vmsa_test_harness::TranslationQueryAccess::Read,
    );
    let result = match invalid_query {
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            vmsa_test_harness::HarnessError::Memory.into()
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::InvalidState.into()
        }
    };
    execution.finish()?;
    result
}
