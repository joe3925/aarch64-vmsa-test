use vmsa_test_harness::{HarnessError, TestResult};

fn fields()
-> Result<aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs, vmsa_test_harness::HarnessError>
{
    use aarch64_vmsa::low_level::raw::{RawVmsa128Stage1TableAttrs, TenBit};

    Ok(RawVmsa128Stage1TableAttrs {
        table_nt: false,
        access_flag: true,
        disch: false,
        protected: false,
        ns_table: false,
        software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
    })
}

pub fn step_by_one_plan() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::mapper::{StepByOneTablePlan, TablePlanContext, TablePlanProvider};
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::TableShape;
    use aarch64_vmsa::translation::WalkInputAddr;

    let fields = fields()?;
    let input = WalkInputAddr::new(0x1234_0000);
    let extended_root = TableShape::<Vmsa128, Granule4KiB>::root(Level::NEG2);
    let mut step = StepByOneTablePlan::new(fields);
    let step_plan = <StepByOneTablePlan<_> as TablePlanProvider<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
    >>::plan_table(
        &mut step,
        TablePlanContext::new(extended_root, Level::L3, input),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    if step_plan.child_shape().level() != Level::NEG1
        || step_plan.child_shape().stride_count().raw() != 1
        || step_plan.into_fields() != fields
    {
        return HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn bounded_skl_plan() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::mapper::{BoundedSklTablePlan, TablePlanContext, TablePlanProvider};
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::TableShape;
    use aarch64_vmsa::translation::WalkInputAddr;

    let fields = fields()?;
    let mut bounded = BoundedSklTablePlan::new(fields, 1024 * 1024);
    let bounded_plan = <BoundedSklTablePlan<_> as TablePlanProvider<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
    >>::plan_table(
        &mut bounded,
        TablePlanContext::new(
            TableShape::root(Level::NEG2),
            Level::L2,
            WalkInputAddr::new(0x1234_0000),
        ),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    if bounded_plan.child_shape().level() != Level::L0
        || bounded_plan.child_shape().stride_count().raw() != 2
    {
        return HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn maximum_skl_plan() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::mapper::{MaxSklTablePlan, TablePlanContext, TablePlanProvider};
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::TableShape;
    use aarch64_vmsa::translation::WalkInputAddr;

    let fields = fields()?;
    let mut maximum = MaxSklTablePlan::new(fields);
    let maximum_plan = <MaxSklTablePlan<_> as TablePlanProvider<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
    >>::plan_table(
        &mut maximum,
        TablePlanContext::new(
            TableShape::root(Level::NEG2),
            Level::L2,
            WalkInputAddr::new(0x1234_0000),
        ),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    if maximum_plan.child_shape().level() != Level::L2
        || maximum_plan.child_shape().stride_count().raw() != 4
    {
        return HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn bounded_skl_no_plan() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::mapper::{BoundedSklTablePlan, TablePlanContext, TablePlanProvider};
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::{AccessError, TableShape};
    use aarch64_vmsa::translation::WalkInputAddr;

    let mut too_small = BoundedSklTablePlan::new(fields()?, 4095);
    if <BoundedSklTablePlan<_> as TablePlanProvider<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
    >>::plan_table(
        &mut too_small,
        TablePlanContext::new(
            TableShape::root(Level::L0),
            Level::L3,
            WalkInputAddr::new(0x1234_0000),
        ),
    ) != Err(AccessError::InvalidTableLevelStep { step: 3 })
    {
        return HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn max_skl_extended_root() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::low_level::raw::{RawVmsa128Stage1TableAttrs, TenBit};
    use aarch64_vmsa::mapper::{MaxSklTablePlan, TablePlanContext, TablePlanProvider};
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::TableShape;
    use aarch64_vmsa::translation::WalkInputAddr;

    let fields = RawVmsa128Stage1TableAttrs {
        table_nt: false,
        access_flag: true,
        disch: false,
        protected: false,
        ns_table: false,
        software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
    };
    let mut planner = MaxSklTablePlan::new(fields);
    let plan = <MaxSklTablePlan<_> as TablePlanProvider<
        Vmsa128,
        NonSecureEl2Stage1,
        Granule4KiB,
    >>::plan_table(
        &mut planner,
        TablePlanContext::new(
            TableShape::root(Level::NEG2),
            Level::L3,
            WalkInputAddr::new(0),
        ),
    );
    match plan {
        Ok(plan)
            if plan.child_shape().level() == Level::L2
                && plan.child_shape().stride_count().raw() == 4 =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 4,
            actual: 0,
        }),
    }
}

fn d128_skl_transition_failures<G>() -> Result<u64, HarnessError>
where
    G: aarch64_vmsa::address::TranslationGranule,
    aarch64_vmsa::descriptor::Vmsa128:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::translation::Stage1,
            G,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    use aarch64_vmsa::address::{GranuleKind, Level};
    use aarch64_vmsa::descriptor::{DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::mapper::{
        BoundedSklTablePlan, MaxSklTablePlan, StepByOneTablePlan, TablePlanContext,
        TablePlanProvider,
    };
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::table::{AccessError, TableShape, TableTransition};
    use aarch64_vmsa::translation::WalkInputAddr;

    type Regime = NonSecureEl2Stage1;
    let raw_fields = fields()?;
    let input = WalkInputAddr::new(0x1234_0000);
    let maximum_stride = if G::kind() == GranuleKind::Size4KiB {
        4
    } else {
        3
    };
    let mut failures = 0;

    for parent_raw in Level::NEG2.as_i8()..Level::L3.as_i8() {
        let parent_level = Level::new(parent_raw);
        let parent = TableShape::<Vmsa128, G>::root(parent_level);

        let mut step_by_one = StepByOneTablePlan::new(raw_fields);
        let step_plan =
            <StepByOneTablePlan<_> as TablePlanProvider<Vmsa128, Regime, G>>::plan_table(
                &mut step_by_one,
                TablePlanContext::new(parent, Level::L3, input),
            );
        if !matches!(
            step_plan,
            Ok(plan)
                if plan.child_shape().level() == parent_level.next()
                    && plan.child_shape().stride_count().raw() == 1
                    && plan.into_fields() == raw_fields
        ) {
            failures += 1;
        }

        for child_raw in (parent_raw + 1)..=Level::L3.as_i8() {
            let child_level = Level::new(child_raw);
            let distance = (child_raw - parent_raw) as u8;
            let child = match TableShape::<Vmsa128, G>::new(child_level, distance) {
                Ok(child) => child,
                Err(_) => {
                    if distance <= 4 {
                        failures += 1;
                    }
                    continue;
                }
            };
            let transition =
                TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
            let supported = <<Vmsa128 as HasLayout<
                aarch64_vmsa::translation::Stage1,
                G,
            >>::Layout as DescriptorLayout<
                Vmsa128,
                aarch64_vmsa::translation::Stage1,
                G,
            >>::supports_table_transition(transition);
            if supported != (distance <= maximum_stride) {
                failures += 1;
            }

            if distance > 4 {
                continue;
            }
            let expected_step = distance.min(maximum_stride);
            let mut maximum = MaxSklTablePlan::new(raw_fields);
            let maximum_plan =
                <MaxSklTablePlan<_> as TablePlanProvider<Vmsa128, Regime, G>>::plan_table(
                    &mut maximum,
                    TablePlanContext::new(parent, child_level, input),
                );
            if !matches!(
                maximum_plan,
                Ok(plan)
                    if plan.child_shape().level()
                        == Level::new(parent_raw + expected_step as i8)
                        && plan.child_shape().stride_count().raw() == expected_step
            ) {
                failures += 1;
            }

            for budget_step in 1..=expected_step {
                let budget_shape = TableShape::<Vmsa128, G>::new(
                    Level::new(parent_raw + budget_step as i8),
                    budget_step,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                let budget = budget_shape
                    .alloc_layout()
                    .map_err(|_| HarnessError::InvalidState)?
                    .bytes();
                let mut bounded = BoundedSklTablePlan::new(raw_fields, budget);
                let bounded_plan =
                    <BoundedSklTablePlan<_> as TablePlanProvider<Vmsa128, Regime, G>>::plan_table(
                        &mut bounded,
                        TablePlanContext::new(parent, child_level, input),
                    );
                if !matches!(
                    bounded_plan,
                    Ok(plan)
                        if plan.child_shape().level()
                            == Level::new(parent_raw + budget_step as i8)
                            && plan.child_shape().stride_count().raw() == budget_step
                ) {
                    failures += 1;
                }
            }

            let minimum_bytes = TableShape::<Vmsa128, G>::new(parent_level.next(), 1)
                .map_err(|_| HarnessError::InvalidState)?
                .alloc_layout()
                .map_err(|_| HarnessError::InvalidState)?
                .bytes();
            let mut no_plan = BoundedSklTablePlan::new(raw_fields, minimum_bytes - 1);
            if !matches!(
                <BoundedSklTablePlan<_> as TablePlanProvider<Vmsa128, Regime, G>>::plan_table(
                    &mut no_plan,
                    TablePlanContext::new(parent, child_level, input),
                ),
                Err(AccessError::InvalidTableLevelStep { step }) if step == distance
            ) {
                failures += 1;
            }
        }
    }
    Ok(failures)
}

pub fn d128_skl_transition_matrix() -> TestResult {
    let failures = d128_skl_transition_failures::<aarch64_vmsa::address::Granule4KiB>()?
        + d128_skl_transition_failures::<aarch64_vmsa::address::Granule16KiB>()?
        + d128_skl_transition_failures::<aarch64_vmsa::address::Granule64KiB>()?;
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

fn d128_plan_mapper<'a>(
    context: &'a vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    root: &'a mut vmsa_test_harness::RootTableMemory,
    start_level: aarch64_vmsa::address::Level,
    input_bits: u8,
) -> Result<
    vmsa_test_harness::TestMapper<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa128,
    >,
    HarnessError,
> {
    context.offline_mapper_for_format_with_geometry::<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa128,
    >(root, start_level, input_bits, 52)
}

fn verify_d128_plan_walk(
    mapper: &vmsa_test_harness::TestMapper<
        crate::CurrentRegime,
        aarch64_vmsa::address::Granule4KiB,
        aarch64_vmsa::descriptor::Vmsa128,
    >,
    expected_levels: &[i8],
) -> Result<bool, HarnessError> {
    let walk = mapper.inspect_walk(0)?;
    if walk.steps().len() != expected_levels.len() {
        return Ok(false);
    }
    for (index, expected_level) in expected_levels.iter().copied().enumerate() {
        let Some(step) = walk.steps()[index] else {
            return Ok(false);
        };
        let expected_kind = if index + 1 == expected_levels.len() {
            if expected_level == 3 {
                vmsa_test_harness::WalkDescriptorKind::Page
            } else {
                vmsa_test_harness::WalkDescriptorKind::Block
            }
        } else {
            vmsa_test_harness::WalkDescriptorKind::Table
        };
        if step.level != vmsa_test_harness::LookupLevel::new(expected_level).unwrap()
            || step.kind != expected_kind
        {
            return Ok(false);
        }
    }
    let expected_leaf = *expected_levels.last().ok_or(HarnessError::InvalidState)?;
    Ok(mapper.translate(0)?.is_some_and(|mapping| {
        mapping.output == 0
            && mapping.level == vmsa_test_harness::LookupLevel::new(expected_leaf).unwrap()
    }))
}

fn operation_error_code(error: vmsa_test_harness::MapperOperationError) -> u64 {
    match error {
        vmsa_test_harness::MapperOperationError::AccessProvider(_) => 101,
        vmsa_test_harness::MapperOperationError::FrameProvider(_) => 102,
        vmsa_test_harness::MapperOperationError::AccessLocation(_) => 103,
        vmsa_test_harness::MapperOperationError::Table(_) => 104,
        vmsa_test_harness::MapperOperationError::TableAddress(_) => 105,
        vmsa_test_harness::MapperOperationError::Descriptor(_) => 106,
        vmsa_test_harness::MapperOperationError::Cursor(_) => 107,
        vmsa_test_harness::MapperOperationError::InvalidLeafLevel { .. } => 108,
        vmsa_test_harness::MapperOperationError::InputAddressOutOfRange { .. } => 109,
        vmsa_test_harness::MapperOperationError::AddressOverflow => 110,
        vmsa_test_harness::MapperOperationError::InvalidLevel { .. } => 111,
        vmsa_test_harness::MapperOperationError::OutputAddressOverflow { .. } => 112,
        vmsa_test_harness::MapperOperationError::OutputAddressOutOfRange { .. } => 113,
        vmsa_test_harness::MapperOperationError::UnalignedInput { .. } => 114,
        vmsa_test_harness::MapperOperationError::UnalignedOutput { .. } => 115,
        vmsa_test_harness::MapperOperationError::LengthNotMappingMultiple { .. } => 116,
        vmsa_test_harness::MapperOperationError::InputNotLeafBase { .. } => 117,
        vmsa_test_harness::MapperOperationError::AlreadyMapped { .. } => 118,
        vmsa_test_harness::MapperOperationError::NotMapped { .. } => 119,
        vmsa_test_harness::MapperOperationError::Unexpected => 120,
    }
}

pub fn map_leaf_with_step_by_one(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = d128_plan_mapper(context, &mut root, aarch64_vmsa::address::Level::NEG2, 56)?;
    let outcome = mapper.map_d128_leaf_step_by_one_exact(
        0,
        0,
        vmsa_test_harness::LookupLevel::new(3).unwrap(),
    );
    if matches!(outcome, Ok(result) if result.tables_allocated == 5
        && result.level == vmsa_test_harness::LookupLevel::new(3).unwrap()
        && result.kind == vmsa_test_harness::WalkDescriptorKind::Page
        && result.covered_size == 4096)
        && verify_d128_plan_walk(&mapper, &[-2, -1, 0, 1, 2, 3])?
    {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 5,
            actual: outcome.map_or_else(operation_error_code, |result| {
                u64::from(result.tables_allocated)
            }),
        })
    }
}

pub fn map_leaf_with_bounded_skl(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = d128_plan_mapper(context, &mut root, aarch64_vmsa::address::Level::NEG2, 56)?;
    let outcome = mapper.map_d128_leaf_bounded_skl_exact(
        0,
        0,
        vmsa_test_harness::LookupLevel::new(2).unwrap(),
        4096,
    );
    if matches!(outcome, Ok(result) if result.tables_allocated == 4
        && result.level == vmsa_test_harness::LookupLevel::new(2).unwrap()
        && result.kind == vmsa_test_harness::WalkDescriptorKind::Block
        && result.covered_size == 1024 * 1024)
        && verify_d128_plan_walk(&mapper, &[-2, -1, 0, 1, 2])?
    {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 4,
            actual: outcome.map_or_else(operation_error_code, |result| {
                u64::from(result.tables_allocated)
            }),
        })
    }
}

pub fn map_leaf_with_maximum_skl(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mut mapper = d128_plan_mapper(context, &mut root, aarch64_vmsa::address::Level::L2, 28)?;
    let outcome = mapper.map_d128_leaf_maximum_skl_exact(
        0,
        0,
        vmsa_test_harness::LookupLevel::new(3).unwrap(),
    );
    if matches!(outcome, Ok(result) if result.tables_allocated == 1
        && result.level == vmsa_test_harness::LookupLevel::new(3).unwrap()
        && result.kind == vmsa_test_harness::WalkDescriptorKind::Page
        && result.covered_size == 4096)
        && verify_d128_plan_walk(&mapper, &[2, 3])?
    {
        TestResult::Pass
    } else {
        TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 1,
            actual: outcome.map_or_else(operation_error_code, |result| {
                u64::from(result.tables_allocated)
            }),
        })
    }
}

fn offline_parts_case<R, G, F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult
where
    R: aarch64_vmsa::regime::TranslationRegime,
    G: vmsa_test_harness::TestGranule,
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
{
    let mut root = context.allocate_root_in(context.native_pas(), G::GRANULE)?;
    let mapper = context.offline_mapper_for_format_with_geometry::<R, G, F>(
        &mut root,
        G::DEFAULT_START_LEVEL,
        32,
        context.capabilities().pa_bits.min(F::OUTPUT_ADDRESS_BITS),
    )?;
    if mapper.verify_offline_accessors_into_parts() {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}

fn live_parts_case<R, G, F>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult
where
    R: aarch64_vmsa::regime::TranslationRegime,
    G: vmsa_test_harness::TestGranule,
    F: aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
{
    let mut root = context.allocate_root_in(context.native_pas(), G::GRANULE)?;
    let mapper = context.offline_mapper_for_format_with_geometry::<R, G, F>(
        &mut root,
        G::DEFAULT_START_LEVEL,
        32,
        context.capabilities().pa_bits.min(F::OUTPUT_ADDRESS_BITS),
    )?;
    if mapper.verify_live_accessors_into_parts() {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}

macro_rules! offline_parts_identity {
    ($name:ident, $regime:ty, $granule:ty, $format:ty) => {
        pub fn $name(
            context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
        ) -> TestResult {
            offline_parts_case::<$regime, $granule, $format>(context)
        }
    };
}

macro_rules! live_parts_identity {
    ($name:ident, $regime:ty, $granule:ty, $format:ty) => {
        pub fn $name(
            context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
        ) -> TestResult {
            live_parts_case::<$regime, $granule, $format>(context)
        }
    };
}

offline_parts_identity!(
    offline_parts_s1_vmsa64_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s1_vmsa64_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s1_vmsa64_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s1_lpa2_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s1_lpa2_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s1_lpa2_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s1_d128_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
offline_parts_identity!(
    offline_parts_s1_d128_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
offline_parts_identity!(
    offline_parts_s1_d128_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
offline_parts_identity!(
    offline_parts_s2_vmsa64_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s2_vmsa64_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s2_vmsa64_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
offline_parts_identity!(
    offline_parts_s2_lpa2_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s2_lpa2_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s2_lpa2_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
offline_parts_identity!(
    offline_parts_s2_d128_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
offline_parts_identity!(
    offline_parts_s2_d128_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
offline_parts_identity!(
    offline_parts_s2_d128_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s1_vmsa64_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s1_vmsa64_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s1_vmsa64_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s1_lpa2_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s1_lpa2_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s1_lpa2_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s1_d128_4k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s1_d128_16k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s1_d128_64k,
    crate::CurrentRegime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s2_vmsa64_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s2_vmsa64_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s2_vmsa64_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64
);
live_parts_identity!(
    live_parts_s2_lpa2_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s2_lpa2_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s2_lpa2_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa64Lpa2
);
live_parts_identity!(
    live_parts_s2_d128_4k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule4KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s2_d128_16k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule16KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
live_parts_identity!(
    live_parts_s2_d128_64k,
    crate::Stage2Regime,
    aarch64_vmsa::address::Granule64KiB,
    aarch64_vmsa::descriptor::Vmsa128
);
