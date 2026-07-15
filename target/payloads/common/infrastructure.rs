use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

/// Explicitly validates harness-owned register restoration. This catalog case
/// is infrastructure evidence and must not be cited for crate API coverage.
pub(super) fn d128_stage1_register_restoration(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let before_current = context
        .infrastructure_current_stage1_snapshot()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let before_lower = context
        .infrastructure_lower_d128_snapshot()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let result = crate::formats_live::active_d128(context);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    let after_current = context
        .infrastructure_current_stage1_snapshot()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let after_lower = context
        .infrastructure_lower_d128_snapshot()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if after_current != before_current || after_lower != before_lower {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

/// Independent following-test sentinel for the runner's restored environment.
pub(super) fn following_stage1_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    crate::formats_live::active_4k(context)
}
