use vmsa_test_harness::{HarnessError, TestResult};

struct RejectTableAccess;

unsafe impl<F, G> aarch64_vmsa::table::TableAccess<F, G> for RejectTableAccess
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
{
    type Error = ();

    fn table_at<'a>(
        &'a self,
        _: aarch64_vmsa::table::TableAccessLocation<'a, F, G>,
    ) -> Result<aarch64_vmsa::table::TranslationTable<'a, F, G>, Self::Error> {
        Err(())
    }
}

fn failures_result(failures: u64) -> TestResult {
    if failures == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0,
            actual: failures,
        })
    }
}

fn output_width_acceptance<F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    root_level: aarch64_vmsa::address::Level,
    input_bits: u8,
    widths: &[u8],
) -> TestResult
where
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<crate::CurrentRegime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
{
    let root = context.allocate_root()?;
    let failures = widths
        .iter()
        .filter(|&&width| {
            context
                .validate_offline_mapper_geometry::<
                    crate::CurrentRegime,
                    aarch64_vmsa::config::granule::Granule4KiB,
                    F,
                >(&root, root_level, input_bits, width)
                .is_err()
        })
        .count() as u64;
    failures_result(failures)
}

fn output_width_rejection<F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    root_level: aarch64_vmsa::address::Level,
    input_bits: u8,
    format_max_bits: u8,
    widths: &[u8],
) -> TestResult
where
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<crate::CurrentRegime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
{
    let root = context.allocate_root()?;
    let failures = widths
        .iter()
        .filter(|&&width| {
            context.validate_offline_mapper_geometry::<
                crate::CurrentRegime,
                aarch64_vmsa::config::granule::Granule4KiB,
                F,
            >(&root, root_level, input_bits, width)
                != Err(vmsa_test_harness::MapperConstructionError::InvalidConfiguredOutputAddressBits {
                    output_address_bits: width,
                    format_max_bits,
                })
        })
        .count() as u64;
    failures_result(failures)
}

pub fn vmsa64_output_width_acceptance(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_acceptance::<aarch64_vmsa::config::format::Vmsa64>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        48,
        &[32, 36, 40, 42, 44, 48],
    )
}

pub fn lpa2_output_width_acceptance(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_acceptance::<aarch64_vmsa::config::format::Vmsa64Lpa2>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        52,
        &[32, 36, 40, 42, 44, 48, 52],
    )
}

pub fn d128_output_width_acceptance(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_acceptance::<aarch64_vmsa::config::format::Vmsa128>(
        context,
        aarch64_vmsa::address::Level::NEG2,
        56,
        &[32, 36, 40, 42, 44, 48, 52, 56],
    )
}

pub fn vmsa64_output_width_rejection(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_rejection::<aarch64_vmsa::config::format::Vmsa64>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        48,
        48,
        &[0, 31, 33, 52, 56, 64],
    )
}

pub fn lpa2_output_width_rejection(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_rejection::<aarch64_vmsa::config::format::Vmsa64Lpa2>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        52,
        52,
        &[0, 31, 33, 56, 64],
    )
}

pub fn d128_output_width_rejection(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    output_width_rejection::<aarch64_vmsa::config::format::Vmsa128>(
        context,
        aarch64_vmsa::address::Level::NEG2,
        56,
        56,
        &[0, 31, 33, 64],
    )
}

fn root_address_bit_boundaries<F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    root_level: aarch64_vmsa::address::Level,
    output_bits: u8,
) -> TestResult
where
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<crate::CurrentRegime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
{
    use aarch64_vmsa::table::TableGeometry;
    let root = context.allocate_root()?;
    let max_addr_bits =
        TableGeometry::<F, aarch64_vmsa::config::granule::Granule4KiB>::level_shift(root_level)
            + TableGeometry::<F, aarch64_vmsa::config::granule::Granule4KiB>::index_bits();
    let validate = |bits| {
        context.validate_offline_mapper_geometry::<
            crate::CurrentRegime,
            aarch64_vmsa::config::granule::Granule4KiB,
            F,
        >(&root, root_level, bits, output_bits)
    };
    let failures = u64::from(validate(1).is_err())
        + u64::from(validate(max_addr_bits).is_err())
        + u64::from(
            validate(0)
                != Err(
                    vmsa_test_harness::MapperConstructionError::InvalidRootAddressBits {
                        addr_bits: 0,
                        max_addr_bits,
                    },
                ),
        )
        + u64::from(
            validate(max_addr_bits + 1)
                != Err(
                    vmsa_test_harness::MapperConstructionError::InvalidRootAddressBits {
                        addr_bits: max_addr_bits + 1,
                        max_addr_bits,
                    },
                ),
        );
    failures_result(failures)
}

pub fn vmsa64_root_address_bit_boundaries(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    root_address_bit_boundaries::<aarch64_vmsa::config::format::Vmsa64>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        48,
    )
}

pub fn lpa2_root_address_bit_boundaries(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    root_address_bit_boundaries::<aarch64_vmsa::config::format::Vmsa64Lpa2>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        52,
    )
}

pub fn d128_root_address_bit_boundaries(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    root_address_bit_boundaries::<aarch64_vmsa::config::format::Vmsa128>(
        context,
        aarch64_vmsa::address::Level::NEG2,
        56,
    )
}

fn valid_root_levels<F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    lowest: aarch64_vmsa::address::Level,
    output_bits: u8,
) -> TestResult
where
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<crate::CurrentRegime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
{
    use aarch64_vmsa::table::TableGeometry;
    let root = context.allocate_root()?;
    let mut level = lowest;
    let mut failures = 0;
    loop {
        let input_bits =
            TableGeometry::<F, aarch64_vmsa::config::granule::Granule4KiB>::level_shift(level)
                + TableGeometry::<F, aarch64_vmsa::config::granule::Granule4KiB>::index_bits();
        if context
            .validate_offline_mapper_geometry::<
                crate::CurrentRegime,
                aarch64_vmsa::config::granule::Granule4KiB,
                F,
            >(&root, level, input_bits, output_bits)
            .is_err()
        {
            failures += 1;
        }
        if level == aarch64_vmsa::address::Level::L3 {
            break;
        }
        level = level.next();
    }
    failures_result(failures)
}

fn invalid_root_levels<F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    lowest: aarch64_vmsa::address::Level,
    output_bits: u8,
) -> TestResult
where
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<crate::CurrentRegime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
{
    let root = context.allocate_root()?;
    let final_level = aarch64_vmsa::address::Level::L3;
    let invalid = [lowest.previous(), final_level.next()];
    let failures = invalid
        .into_iter()
        .filter(|&root_level| {
            context.validate_offline_mapper_geometry::<
                crate::CurrentRegime,
                aarch64_vmsa::config::granule::Granule4KiB,
                F,
            >(&root, root_level, 1, output_bits)
                != Err(vmsa_test_harness::MapperConstructionError::InvalidRootLevel {
                    root_level: root_level.as_i8(),
                    lowest_level: lowest.as_i8(),
                    final_level: final_level.as_i8(),
                })
        })
        .count() as u64;
    failures_result(failures)
}

pub fn vmsa64_valid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    valid_root_levels::<aarch64_vmsa::config::format::Vmsa64>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        48,
    )
}

pub fn lpa2_valid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    valid_root_levels::<aarch64_vmsa::config::format::Vmsa64Lpa2>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        52,
    )
}

pub fn d128_valid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    valid_root_levels::<aarch64_vmsa::config::format::Vmsa128>(
        context,
        aarch64_vmsa::address::Level::NEG2,
        56,
    )
}

pub fn vmsa64_invalid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    invalid_root_levels::<aarch64_vmsa::config::format::Vmsa64>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        48,
    )
}

pub fn lpa2_invalid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    invalid_root_levels::<aarch64_vmsa::config::format::Vmsa64Lpa2>(
        context,
        aarch64_vmsa::address::Level::NEG1,
        52,
    )
}

pub fn d128_invalid_root_levels(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    invalid_root_levels::<aarch64_vmsa::config::format::Vmsa128>(
        context,
        aarch64_vmsa::address::Level::NEG2,
        56,
    )
}

pub fn maximum_root_address(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    match context.validate_offline_mapper_geometry_at::<
        crate::CurrentRegime,
        aarch64_vmsa::config::granule::Granule4KiB,
        aarch64_vmsa::config::format::Vmsa64,
    >(
        0xffff_f000,
        aarch64_vmsa::address::Level::L0,
        32,
        32,
    ) {
        Ok(()) => TestResult::Pass,
        Err(_) => HarnessError::CrateBehavior { expected: 1, actual: 0 }.into(),
    }
}

pub fn unaligned_root_address(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let actual = context.validate_offline_mapper_geometry_at::<
        crate::CurrentRegime,
        aarch64_vmsa::config::granule::Granule4KiB,
        aarch64_vmsa::config::format::Vmsa64,
    >(1, aarch64_vmsa::address::Level::L0, 32, 32);
    if actual
        != Err(vmsa_test_harness::MapperConstructionError::UnalignedRoot {
            address: 1,
            align: 4096,
        })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub fn root_address_out_of_range(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let actual = context.validate_offline_mapper_geometry_at::<
        crate::CurrentRegime,
        aarch64_vmsa::config::granule::Granule4KiB,
        aarch64_vmsa::config::format::Vmsa64,
    >(
        0x1_0000_0000,
        aarch64_vmsa::address::Level::L0,
        32,
        32,
    );
    if actual
        != Err(
            vmsa_test_harness::MapperConstructionError::RootAddressOutOfRange {
                address: 0x1_0000_0000,
                output_address_bits: 32,
            },
        )
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub fn value_boundaries() -> TestResult {
    use aarch64_vmsa::address::{
        GranuleError, GranuleKind, Level, PhysAddr, TranslationGranule, VirtAddr,
    };
    use aarch64_vmsa::config::format::{Vmsa64, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::table::{
        AccessError, RootTable, TableAddr, TableCursor, TableGeometry, TableShape,
        TableStrideCount, TableTransition, TableWalkPath,
    };

    for (kind, shift) in [
        (GranuleKind::Size4KiB, 12),
        (GranuleKind::Size16KiB, 14),
        (GranuleKind::Size64KiB, 16),
    ] {
        let size = 1u64 << shift;
        if kind.shift() != shift
            || kind.size() != size
            || kind.mask() != size - 1
            || kind.page_offset(VirtAddr(size + 7)) != 7
            || !kind.is_page_aligned(size)
            || kind.is_page_aligned(size + 1)
            || kind.align_down(size + 1) != size
            || kind.align_up(size + 1) != Some(size * 2)
            || kind.align_up(u64::MAX).is_some()
            || kind.validate_page_alignment(size) != Ok(())
            || kind.validate_page_alignment(size + 1) != Err(GranuleError::AddressNotAligned)
        {
            return HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
    }
    if Granule4KiB::kind() != GranuleKind::Size4KiB
        || Granule16KiB::kind() != GranuleKind::Size16KiB
        || Granule64KiB::kind() != GranuleKind::Size64KiB
        || Granule4KiB::align_up(u64::MAX).is_some()
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    if Level::NEG2.next() != Level::NEG1
        || Level::NEG1.previous() != Level::NEG2
        || !Level::NEG1.is_negative()
        || !Level::L0.is_l0()
        || !Level::L1.is_l1()
        || !Level::L2.is_l2()
        || !Level::L3.is_l3()
        || !Level::L0.is_before(Level::L3)
        || !Level::L3.is_after(Level::L0)
        || Level::L3.distance_from(Level::NEG2) != Some(5)
        || Level::NEG2.distance_from(Level::L0).is_some()
        || !Level::L1.is_between_inclusive(Level::L0, Level::L3)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    if TableGeometry::<Vmsa64, Granule4KiB>::entries() != 512
        || TableGeometry::<Vmsa64, Granule16KiB>::entries() != 2048
        || TableGeometry::<Vmsa64, Granule64KiB>::entries() != 8192
        || TableGeometry::<Vmsa128, Granule4KiB>::entries() != 256
        || TableGeometry::<Vmsa64, Granule4KiB>::index_bits() != 9
        || TableGeometry::<Vmsa64, Granule16KiB>::index_bits() != 11
        || TableGeometry::<Vmsa64, Granule64KiB>::index_bits() != 13
        || TableGeometry::<Vmsa64, Granule4KiB>::index_mask() != 0x1ff
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_entries_for_stride_count(0).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_index_mask_for_stride_count(0).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_level_shift(Level::new(4)).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_level_shift(Level::L3) != Some(12)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    if TableStrideCount::new::<Vmsa64, Granule4KiB>(0)
        != Err(AccessError::InvalidTableStrideCount { stride_count: 0 })
        || TableStrideCount::new::<Vmsa64, Granule4KiB>(1).map(|value| value.raw()) != Ok(1)
        || TableStrideCount::new::<Vmsa64, Granule4KiB>(5)
            != Err(AccessError::InvalidTableStrideCount { stride_count: 5 })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let root_shape =
        TableShape::<Vmsa64, Granule4KiB>::root(Level::L0).expect("level 0 is a valid root shape");
    let child_shape = TableShape::<Vmsa64, Granule4KiB>::new(Level::L2, 2).map_err(|_| {
        HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
    })?;
    let transition =
        TableTransition::new(root_shape, child_shape).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if transition.parent_level() != Level::L0
        || transition.child_level() != Level::L2
        || transition.level_step() != 2
        || root_shape
            .alloc_layout()
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?
            .bytes()
            != 4096
        || root_shape
            .validate_base(TableAddr::new(0x1000).expect("aligned table address"))
            .is_err()
        || TableAddr::<Granule4KiB>::new(0x1001).is_ok()
        || TableTransition::new(
            root_shape,
            TableShape::<Vmsa64, Granule4KiB>::new(Level::L2, 1).map_err(|_| {
                HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
            })?,
        )
        .is_ok()
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let address =
        TableAddr::<Granule4KiB>::new(0x4000).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if TableAddr::<Granule4KiB>::new(0x4001).is_ok() {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let root = RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
        aarch64_vmsa::table::RootTableGeometry::new_at_level(address, Level::L0, 48, 48)
            .expect("valid root geometry"),
    );
    let walker = aarch64_vmsa::translation::Walker::new(root, &RejectTableAccess)
        .expect("valid walker root");
    let cursor = walker.start().current();
    let path = TableWalkPath::<Vmsa64, Granule4KiB>::root();
    if root.addr() != address
        || root.level() != Level::L0
        || root.addr_bits() != 48
        || root.output_addr_bits() != 48
        || cursor.root_addr() != address
        || cursor.level() != Level::L0
        || !path.is_root()
        || path.len() != 0
        || path.terminal_level(Level::L0) != Ok(Level::L0)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    TestResult::Pass
}

fn level_span_failures<F, G>(expected: &[(aarch64_vmsa::address::Level, Option<u64>)]) -> u64
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
{
    let geometry = aarch64_vmsa::table::TableGeometry::<F, G>::new();
    let _clone = geometry.clone();
    expected
        .iter()
        .filter(|&&(level, span)| {
            aarch64_vmsa::table::TableGeometry::<F, G>::level_span(level) != span
        })
        .count() as u64
}

pub fn level_spans() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::config::format::{Vmsa64, Vmsa64Lpa2, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};

    let failures = level_span_failures::<Vmsa64, Granule4KiB>(&[
        (Level::NEG1, Some(1u64 << 48)),
        (Level::L0, Some(1u64 << 39)),
        (Level::L1, Some(1u64 << 30)),
        (Level::L2, Some(1u64 << 21)),
        (Level::L3, Some(1u64 << 12)),
    ]) + level_span_failures::<Vmsa64, Granule16KiB>(&[
        (Level::NEG1, Some(1u64 << 58)),
        (Level::L0, Some(1u64 << 47)),
        (Level::L2, Some(1u64 << 25)),
        (Level::L3, Some(1u64 << 14)),
    ]) + level_span_failures::<Vmsa64, Granule64KiB>(&[
        (Level::NEG1, None),
        (Level::L0, Some(1u64 << 55)),
        (Level::L2, Some(1u64 << 29)),
        (Level::L3, Some(1u64 << 16)),
    ]) + level_span_failures::<Vmsa64Lpa2, Granule4KiB>(&[
        (Level::NEG1, Some(1u64 << 48)),
        (Level::L3, Some(1u64 << 12)),
    ]) + level_span_failures::<Vmsa64Lpa2, Granule16KiB>(&[
        (Level::NEG1, Some(1u64 << 58)),
        (Level::L3, Some(1u64 << 14)),
    ]) + level_span_failures::<Vmsa64Lpa2, Granule64KiB>(&[
        (Level::NEG1, None),
        (Level::L3, Some(1u64 << 16)),
    ]) + level_span_failures::<Vmsa128, Granule4KiB>(&[
        (Level::NEG2, Some(1u64 << 52)),
        (Level::NEG1, Some(1u64 << 44)),
        (Level::L0, Some(1u64 << 36)),
        (Level::L2, Some(1u64 << 20)),
        (Level::L3, Some(1u64 << 12)),
    ]) + level_span_failures::<Vmsa128, Granule16KiB>(&[
        (Level::NEG2, None),
        (Level::NEG1, Some(1u64 << 54)),
        (Level::L0, Some(1u64 << 44)),
        (Level::L2, Some(1u64 << 24)),
        (Level::L3, Some(1u64 << 14)),
    ]) + level_span_failures::<Vmsa128, Granule64KiB>(&[
        (Level::NEG2, None),
        (Level::NEG1, None),
        (Level::L0, Some(1u64 << 52)),
        (Level::L2, Some(1u64 << 28)),
        (Level::L3, Some(1u64 << 16)),
    ]);

    failures_result(failures)
}

pub fn path_boundaries() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::table::{
        AccessError, NextTable, TableAddr, TableCursor, TableShape, TableWalkPath,
    };

    type Path = TableWalkPath<Vmsa64, Granule4KiB>;
    let root_addr = TableAddr::new(0x4000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let level1_addr = TableAddr::new(0x8000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let level3_addr = TableAddr::new(0x20_0000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l0 = TableShape::root(Level::L0).expect("level 0 is a valid root shape");
    let l1 = TableShape::new(Level::L1, 1).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l3 = TableShape::new(Level::L3, 2).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let mut path = Path::root();
    path.push(Level::L0, l0, l1, 0x12)
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    path.push(Level::L0, l1, l3, 0x101)
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let first = path.entry(Level::L0, 0).ok_or(HarnessError::InvalidState)?;
    let second = path.entry(Level::L0, 1).ok_or(HarnessError::InvalidState)?;
    if path.len() != 2
        || path.is_root()
        || first.parent() != l0
        || first.parent_level() != Level::L0
        || first.child_level() != Level::L1
        || first.index() != 0x12
        || second.parent() != l1
        || second.child_level() != Level::L3
        || second.index() != 0x101
        || path.index(0) != Some(0x12)
        || path.index(1) != Some(0x101)
        || path.index(2).is_some()
        || path.level_index(Level::L0, Level::L0) != Ok(0x12)
        || path.level_index(Level::L0, Level::L1) != Ok(0x101)
        || path.level_index(Level::L0, Level::L2)
            != Err(AccessError::TablePathLevelUnavailable {
                root_level: Level::L0,
                level: Level::L2,
                len: 2,
            })
        || path.terminal_level(Level::L0) != Ok(Level::L3)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let mut out_of_range = Path::root();
    if out_of_range.push(Level::L0, l0, l1, l0.entries())
        != Err(AccessError::TablePathIndexOutOfRange {
            index: l0.entries(),
            entries: l0.entries(),
        })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let mut wrong_terminal = path;
    if wrong_terminal.push(Level::L0, l0, l1, 0)
        != Err(AccessError::TablePathTerminalLevelMismatch {
            expected: Level::L0,
            actual: Level::L3,
        })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let root_table =
        aarch64_vmsa::table::RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
            aarch64_vmsa::table::RootTableGeometry::new_at_level(root_addr, Level::L0, 48, 48)
                .expect("valid root geometry"),
        );
    let walker = aarch64_vmsa::translation::Walker::new(root_table, &RejectTableAccess)
        .expect("valid walker root");
    let root_cursor = walker.start().current();
    let level1 = root_cursor
        .next_table(
            0x12,
            NextTable::new(level1_addr, Level::L1, 1).map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let level3 = level1
        .next_table(
            0x101,
            NextTable::new(level3_addr, Level::L3, 2).map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if level3.root_addr() != root_addr
        || level3.root_level() != Level::L0
        || level3.current() != level3_addr
        || level3.shape() != l3
        || level3.path() != path
        || level3.entry_index(0).is_err()
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub fn walk_cursor_boundaries() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::descriptor::DescriptorFormat;
    use aarch64_vmsa::table::{NextTable, RootTable, RootTableGeometry, TableAddr, TableGeometry};
    use aarch64_vmsa::translation::walk::{WalkCursorError, WalkError};
    use aarch64_vmsa::translation::{WalkInputAddr, Walker};

    let root = TableAddr::new(0x4000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let input = WalkInputAddr::new(0x1234_5678_9abc);
    let below = RootTableGeometry::<Vmsa64, Granule4KiB>::new_at_level(root, Level::NEG2, 48, 48);
    let above = RootTableGeometry::<Vmsa64, Granule4KiB>::new_at_level(root, Level::new(4), 48, 48);
    if input.raw() != 0x1234_5678_9abc
        || below.is_ok()
        || above.is_ok()
        || <Vmsa64 as DescriptorFormat>::EXTENDED_LOWEST_ROOT_LEVEL != Level::NEG1
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let root_table = RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
        RootTableGeometry::new_at_level(root, Level::L0, 48, 48).expect("valid root geometry"),
    );
    let walker = Walker::new(root_table, &RejectTableAccess).expect("valid walker root");
    let walker_geometry = walker.table_geometry();
    let _geometry_clone = walker_geometry.clone();
    if walker_geometry != TableGeometry::<Vmsa64, Granule4KiB>::new() {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let walk = walker
        .start_at(input)
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let cursor = walk.current();
    let expected_index = ((input.raw() >> 39) & 0x1ff) as usize;
    if walk.input() != input
        || cursor.root_addr() != root
        || cursor.root_level() != Level::L0
        || cursor.current() != root
        || cursor.level() != Level::L0
        || !cursor.path().is_root()
        || cursor.entry_index(input.raw()) != Ok(expected_index)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let next_addr = TableAddr::new(0x8000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let next =
        NextTable::new(next_addr, Level::L1, 1).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let child =
        cursor
            .next_table(expected_index, next)
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
    if child.root_addr() != root
        || child.current() != next_addr
        || child.level() != Level::L1
        || child.path().len() != 1
        || child.path().index(0) != Some(expected_index)
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let narrow_root = RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
        RootTableGeometry::new_at_level(root, Level::L3, 21, 48)
            .expect("valid narrow root geometry"),
    );
    let narrow_walker =
        Walker::new(narrow_root, &RejectTableAccess).expect("valid narrow walker root");
    let maximum = WalkInputAddr::new((1u64 << 21) - 1);
    let first_out_of_range = WalkInputAddr::new(1u64 << 21);
    if narrow_walker.start_at(maximum).is_err()
        || !matches!(
            narrow_walker.start_at(first_out_of_range),
            Err(WalkCursorError::InputAddressOutOfRange {
                addr,
                addr_bits: 21,
            }) if addr == first_out_of_range.raw()
        )
        || !matches!(
            narrow_walker.translate(first_out_of_range),
            Err(WalkError::Cursor(WalkCursorError::InputAddressOutOfRange {
                addr,
                addr_bits: 21,
            })) if addr == first_out_of_range.raw()
        )
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

fn table_shape_transition_failures<F, G>() -> u64
where
    F: aarch64_vmsa::descriptor::DescriptorFormat + PartialEq,
    G: aarch64_vmsa::address::TranslationGranule + PartialEq,
{
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::table::{
        AccessError, TableGeometry, TableShape, TableStrideCount, TableTransition,
    };

    let mut failures = 0;
    for stride in 1..=4 {
        let expected_entries = TableGeometry::<F, G>::checked_entries_for_stride_count(stride);
        if TableStrideCount::new::<F, G>(stride).map(|value| value.raw()) != Ok(stride)
            || expected_entries.is_none()
        {
            failures += 1;
            continue;
        }
        let shape = match TableShape::<F, G>::new(Level::L3, stride) {
            Ok(shape) => shape,
            Err(_) => {
                failures += 1;
                continue;
            }
        };
        let layout = match shape.alloc_layout() {
            Ok(layout) => layout,
            Err(_) => {
                failures += 1;
                continue;
            }
        };
        let expected_bytes =
            (expected_entries.unwrap() as u64).checked_mul(F::DESCRIPTOR_BYTES as u64);
        if shape.stride_count().raw() != stride
            || shape.entries() != expected_entries.unwrap()
            || Some(layout.bytes()) != expected_bytes
            || layout.align() != layout.bytes()
            || shape
                .validate_base(
                    aarch64_vmsa::table::TableAddr::new(layout.align())
                        .expect("aligned table address"),
                )
                .is_err()
            || aarch64_vmsa::table::TableAddr::<G>::new(layout.align() + 1).is_ok()
        {
            failures += 1;
        }
    }
    for invalid in [0, 5] {
        if TableStrideCount::new::<F, G>(invalid)
            != Err(AccessError::InvalidTableStrideCount {
                stride_count: invalid,
            })
            || TableShape::<F, G>::new(Level::L3, invalid)
                != Err(AccessError::InvalidTableStrideCount {
                    stride_count: invalid,
                })
        {
            failures += 1;
        }
    }
    if TableShape::<F, G>::new(Level::new(4), 1)
        != Err(AccessError::InvalidTableLevel {
            root_level: F::EXTENDED_LOWEST_ROOT_LEVEL,
            level: Level::new(4),
            final_level: F::FINAL_LEVEL,
        })
    {
        failures += 1;
    }

    for parent_raw in F::EXTENDED_LOWEST_ROOT_LEVEL.as_i8()..Level::L3.as_i8() {
        let parent_level = Level::new(parent_raw);
        let parent =
            TableShape::<F, G>::root(parent_level).expect("matrix uses valid table levels");
        for child_raw in (parent_raw + 1)..=Level::L3.as_i8() {
            let distance = (child_raw - parent_raw) as u8;
            if distance > 4 {
                continue;
            }
            let child_level = Level::new(child_raw);
            let child = match TableShape::<F, G>::new(child_level, distance) {
                Ok(child) => child,
                Err(_) => {
                    failures += 1;
                    continue;
                }
            };
            match TableTransition::new(parent, child) {
                Ok(transition)
                    if transition.parent() == parent
                        && transition.child() == child
                        && transition.parent_level() == parent_level
                        && transition.child_level() == child_level
                        && transition.level_step() == distance => {}
                _ => failures += 1,
            }
            let wrong_stride = if distance == 1 { 2 } else { 1 };
            let wrong = TableShape::<F, G>::new(child_level, wrong_stride).unwrap();
            if TableTransition::new(parent, wrong)
                != Err(AccessError::InvalidTableTransition {
                    parent_level,
                    child_level,
                    stride_count: wrong_stride,
                })
            {
                failures += 1;
            }
        }
        let same = TableShape::<F, G>::new(parent_level, 1).unwrap();
        if TableTransition::new(parent, same)
            != Err(AccessError::InvalidTableTransition {
                parent_level,
                child_level: parent_level,
                stride_count: 1,
            })
        {
            failures += 1;
        }
    }
    let reverse_parent =
        TableShape::<F, G>::root(Level::L1).expect("level 1 is a valid table level");
    let reverse_child = TableShape::<F, G>::new(Level::L0, 1).unwrap();
    if TableTransition::new(reverse_parent, reverse_child)
        != Err(AccessError::InvalidTableTransition {
            parent_level: Level::L1,
            child_level: Level::L0,
            stride_count: 1,
        })
    {
        failures += 1;
    }
    failures
}

pub fn table_shape_transition_matrix() -> TestResult {
    let failures = table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule4KiB,
    >() + table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule16KiB,
    >() + table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule64KiB,
    >() + table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule4KiB,
    >() + table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule16KiB,
    >() + table_shape_transition_failures::<
        aarch64_vmsa::config::format::Vmsa128,
        aarch64_vmsa::config::granule::Granule64KiB,
    >();
    failures_result(failures)
}

pub fn invalid_table_levels() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::config::format::{Vmsa64, Vmsa128};
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::descriptor::DescriptorFormat;
    use aarch64_vmsa::table::{AccessError, TableGeometry, TableShape, TableWalkPath};

    let below = Level::new(<Vmsa64 as DescriptorFormat>::EXTENDED_LOWEST_ROOT_LEVEL.as_i8() - 1);
    let above = Level::new(<Vmsa64 as DescriptorFormat>::FINAL_LEVEL.as_i8() + 1);
    let extreme = Level::new(i8::MIN);
    let expected_below = Err(AccessError::InvalidTableLevel {
        root_level: <Vmsa64 as DescriptorFormat>::EXTENDED_LOWEST_ROOT_LEVEL,
        level: below,
        final_level: <Vmsa64 as DescriptorFormat>::FINAL_LEVEL,
    });
    let expected_above = Err(AccessError::InvalidTableLevel {
        root_level: <Vmsa64 as DescriptorFormat>::EXTENDED_LOWEST_ROOT_LEVEL,
        level: above,
        final_level: <Vmsa64 as DescriptorFormat>::FINAL_LEVEL,
    });
    let expected_extreme = Err(AccessError::InvalidTableLevel {
        root_level: <Vmsa64 as DescriptorFormat>::EXTENDED_LOWEST_ROOT_LEVEL,
        level: extreme,
        final_level: <Vmsa64 as DescriptorFormat>::FINAL_LEVEL,
    });

    if TableShape::<Vmsa64, Granule4KiB>::root(below) != expected_below
        || TableShape::<Vmsa64, Granule4KiB>::new(below, 1) != expected_below
        || TableShape::<Vmsa64, Granule4KiB>::root(above) != expected_above
        || TableShape::<Vmsa64, Granule4KiB>::new(above, 1) != expected_above
        || TableShape::<Vmsa64, Granule4KiB>::root(extreme) != expected_extreme
        || TableShape::<Vmsa64, Granule4KiB>::new(extreme, 1) != expected_extreme
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_level_shift(below).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_level_shift(above).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::checked_level_shift(extreme).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::max_addr_bits(below).is_some()
        || TableGeometry::<Vmsa64, Granule4KiB>::level_span(extreme).is_some()
        || TableShape::<Vmsa64, Granule4KiB>::root(Level::NEG1).is_err()
        || TableShape::<Vmsa64, Granule4KiB>::root(Level::L3).is_err()
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    type Path = TableWalkPath<Vmsa128, Granule4KiB>;
    let mut excessive_step = Path::root();
    if excessive_step.push(
        Level::NEG2,
        TableShape::root(Level::NEG2).expect("level -2 is a valid D128 root shape"),
        TableShape::new(Level::L3, 1).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?,
        0,
    ) != Err(AccessError::InvalidTableLevelStep { step: 5 })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub fn cursor_next_table_errors() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::table::{AccessError, NextTable, RootTable, RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, Walker};

    let root = TableAddr::<Granule4KiB>::new(0x4000).map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let next_addr =
        TableAddr::<Granule4KiB>::new(0x8000).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let root_table = RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
        RootTableGeometry::new_at_level(root, Level::L0, 48, 48).expect("valid root geometry"),
    );
    let walker = Walker::new(root_table, &RejectTableAccess).expect("valid walker root");
    let cursor = walker
        .start_at(WalkInputAddr::new(0x1234_5000))
        .expect("valid addressed walk")
        .current();
    let next = NextTable::<Vmsa64, Granule4KiB>::new(next_addr, Level::L1, 1).map_err(|_| {
        HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
    })?;
    if cursor.next_table(512, next)
        != Err(AccessError::TablePathIndexOutOfRange {
            index: 512,
            entries: 512,
        })
        || NextTable::<Vmsa64, Granule4KiB>::new(next_addr, Level::L2, 2)
            != Err(AccessError::UnalignedTableAddress {
                addr: 0x8000,
                align: 2 * 1024 * 1024,
            })
        || !matches!(
            NextTable::<Vmsa64, Granule4KiB>::new(next_addr, Level::L3, 0),
            Err(AccessError::InvalidTableStrideCount { stride_count: 0 })
        )
        || !matches!(
            NextTable::<Vmsa64, Granule4KiB>::new(next_addr, Level::new(4), 1),
            Err(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: Level::L3,
            }) if root_level == Level::NEG1 && level == Level::new(4)
        )
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let final_root = RootTable::<Vmsa64, crate::CurrentRegime, Granule4KiB>::from_geometry(
        RootTableGeometry::new_at_level(root, Level::L3, 12, 48)
            .expect("valid final-level root geometry"),
    );
    let final_walker = Walker::new(final_root, &RejectTableAccess).expect("valid walker root");
    let final_cursor = final_walker.start().current();
    if final_cursor.next_table(0, next)
        != Err(AccessError::InvalidTableLevel {
            root_level: Level::L3,
            level: Level::L3,
            final_level: Level::L3,
        })
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let walk = walker
        .start_at(WalkInputAddr::new(0x1234_5000))
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if walk.current() != cursor
        || !matches!(
            walk.current().next_table(512, next),
            Err(AccessError::TablePathIndexOutOfRange {
                index: 512,
                entries: 512,
            })
        )
    {
        return HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}
