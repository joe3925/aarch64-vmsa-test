pub(crate) extern "C" fn execution_probe() -> u64 {
    0x5345_434f_4e44_4152
}

pub(crate) fn invalid_virtual_address<E: vmsa_test_harness::adapter::Environment>(
    context: &vmsa_test_harness::TestContext<'_, E>,
) -> u64 {
    1u64 << context.capabilities().va_bits.min(47)
}
