use vmsa_test_harness::{RegimeAttributes, TestContext, TestResult};

pub fn address_translation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    validate_par_decoding()?;
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
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
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
            vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into()
        }
    }
}

/// Pins the architectural PAR_EL1 layouts independently of any live AT
/// instruction. In the D128 success form, OA[55:12] is PAR[119:76], which is
/// high-word[55:12] after MRRS; attributes remain in the low word. D128=0
/// selects the ordinary 64-bit layout even when MRRS was used.
fn validate_par_decoding() -> Result<(), vmsa_test_harness::HarnessError> {
    use vmsa_test_harness::TranslationQueryResult;

    const VA: u64 = 0x0000_1234_5678_9abc;
    const ATTRS: u64 = 0xa500_0000_0000_0b80;
    const OA48: u64 = 0x0000_4321_0fed_c000;
    const OA56: u64 = 0x00ab_cdef_1234_5000;

    if TranslationQueryResult::from_raw_par_for_test(VA, OA48 | ATTRS)
        != (TranslationQueryResult::Success {
            physical_address: OA48 | (VA & 0xfff),
            attributes: ATTRS,
        })
    {
        return Err(vmsa_test_harness::HarnessError::InvalidState);
    }

    if TranslationQueryResult::from_raw_par128_for_test(VA, ATTRS, OA56 | 1)
        != (TranslationQueryResult::Success {
            physical_address: OA56 | (VA & 0xfff),
            attributes: ATTRS,
        })
    {
        return Err(vmsa_test_harness::HarnessError::InvalidState);
    }

    // High-word bit 0 is PAR_EL1.D128. If clear, the low word must be decoded
    // using the 64-bit layout and the remaining high word ignored.
    if TranslationQueryResult::from_raw_par128_for_test(VA, OA48 | ATTRS, OA56)
        != (TranslationQueryResult::Success {
            physical_address: OA48 | (VA & 0xfff),
            attributes: ATTRS,
        })
    {
        return Err(vmsa_test_harness::HarnessError::InvalidState);
    }

    const FST: u64 = 0b10_1101;
    let fault = 1 | (FST << 1) | (1 << 9);
    if TranslationQueryResult::from_raw_par_for_test(VA, fault)
        != (TranslationQueryResult::Fault {
            status: FST as u8,
            stage2: true,
            raw: fault,
        })
    {
        return Err(vmsa_test_harness::HarnessError::InvalidState);
    }

    Ok(())
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
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
        }
        execution.finish()?;
    }
    let mut host_el0 = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    match host_el0.translate(address, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => {}
        _ => {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
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
            vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into()
        }
    };
    execution.finish()?;
    result
}
