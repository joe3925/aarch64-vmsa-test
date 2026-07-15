use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn fixed_stage1_semantic_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    crate::permission_active::rw_xn_read(context)
}

pub(super) fn fixed_stage2_semantic_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    crate::stage2_leaf_matrix::permission_ro_read(context)
}
