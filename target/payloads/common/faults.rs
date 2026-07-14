use vmsa_test_harness::{ExpectedFault, TestContext, TestResult, expect_fault};

pub fn current_fault<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    current_fault_expected(context, ExpectedFault::translation_read_stage1())
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
