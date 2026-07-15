use crate::formats_live::{ActiveGeometry, active_granule};
use crate::{CurrentEnvironment, CurrentRegime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
enum Vmsa64MalformedLeaf {
    ReservedType,
    Res0,
    Res1,
}

pub(super) fn vmsa64_reserved_type(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    malformed_vmsa64_leaf(context, Vmsa64MalformedLeaf::ReservedType)
}

pub(super) fn vmsa64_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_vmsa64_leaf(context, Vmsa64MalformedLeaf::Res0)
}

pub(super) fn vmsa64_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_vmsa64_leaf(context, Vmsa64MalformedLeaf::Res1)
}

fn malformed_vmsa64_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mutation: Vmsa64MalformedLeaf,
) -> TestResult {
    use vmsa_test_harness::{AddressBits, LookupLevel, MappingAttributes, PhysicalAddress};

    const ADDRESS: u64 = 0x6e00_0000;
    const VALUE: u64 = 0x4d41_4c46_4f52_4d45;
    let page = context.allocate_page()?;
    let write = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let bits = AddressBits::new(48).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size4KiB,
        bits,
        bits,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            CurrentRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(&mut root, aarch64_vmsa::address::Level::L0, 48, 48)?;
        mapper.map_attributes_leaf(
            ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
        sandbox = context
            .prepare_transition_runtime(&mut mapper, malformed_vmsa64_leaf as *const () as u64)?;
        let walk = mapper.inspect_walk(ADDRESS)?;
        let leaf = walk
            .leaf()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut replacement = leaf
            .raw
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        match mutation {
            Vmsa64MalformedLeaf::ReservedType => replacement.low &= !(1 << 1),
            Vmsa64MalformedLeaf::Res0 => replacement.low |= 1 << 48,
            Vmsa64MalformedLeaf::Res1 => replacement.low &= !1,
        }
        let original = mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ADDRESS, replacement)?;
        if original != leaf.raw.unwrap_or(replacement) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let setup = vmsa_test_harness::TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
        stage: vmsa_test_harness::TranslationStage::Stage1,
        granule: vmsa_test_harness::Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits: bits,
        output_bits: bits,
        start_level: LookupLevel::new(0),
        asid: None,
        vmid: None,
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let translation = context.install_owned_in_sandbox(root, setup, &sandbox)?;
    let fault = vmsa_test_harness::expect_matching_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::FaultMatcher::new(
            vmsa_test_harness::ExpectedFault::translation_read_stage1(),
        )
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(ADDRESS)
        .with_ipa(None),
    );
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.emergency_restore_for_test();
    let fresh = fresh_vmsa64_mapping(context);
    if !matches!(fresh, TestResult::Pass) {
        return fresh;
    }
    fault
}

fn fresh_vmsa64_mapping(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let bits = vmsa_test_harness::AddressBits::new(48)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el2_stage1_controls(
        vmsa_test_harness::Granule::Size4KiB,
        bits,
        bits,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
    active_granule::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        context,
        root,
        ActiveGeometry {
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            start_level: aarch64_vmsa::address::Level::L0,
            input_width: 48,
            output_width: 48,
            controls,
        },
        false,
    )
}

#[derive(Clone, Copy)]
enum Lpa2MalformedLeaf {
    ReservedType,
    Address,
    Res0,
    Res1,
}

macro_rules! lpa2_malformed_case {
    ($name:ident, $granule:ty, $granule_value:expr, $start:expr, $mutation:expr, $address_bit:expr, $res0_bit:expr) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            malformed_lpa2_leaf::<$granule>(
                context,
                $granule_value,
                $start,
                $mutation,
                $address_bit,
                $res0_bit,
            )
        }
    };
}

lpa2_malformed_case!(
    lpa2_ds_reserved_type,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::NEG1,
    Lpa2MalformedLeaf::ReservedType,
    8,
    59
);
lpa2_malformed_case!(
    lpa2_ds_address,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::NEG1,
    Lpa2MalformedLeaf::Address,
    8,
    59
);
lpa2_malformed_case!(
    lpa2_ds_res0,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::NEG1,
    Lpa2MalformedLeaf::Res0,
    8,
    59
);
lpa2_malformed_case!(
    lpa2_ds_res1,
    aarch64_vmsa::address::Granule4KiB,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::NEG1,
    Lpa2MalformedLeaf::Res1,
    8,
    59
);
lpa2_malformed_case!(
    lpa2_64k_reserved_type,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    Lpa2MalformedLeaf::ReservedType,
    12,
    48
);
lpa2_malformed_case!(
    lpa2_64k_address,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    Lpa2MalformedLeaf::Address,
    12,
    48
);
lpa2_malformed_case!(
    lpa2_64k_res0,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    Lpa2MalformedLeaf::Res0,
    12,
    48
);
lpa2_malformed_case!(
    lpa2_64k_res1,
    aarch64_vmsa::address::Granule64KiB,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L1,
    Lpa2MalformedLeaf::Res1,
    12,
    48
);

fn malformed_lpa2_leaf<G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    mutation: Lpa2MalformedLeaf,
    address_bit: u8,
    res0_bit: u8,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    CurrentRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::descriptor::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    aarch64_vmsa::descriptor::Vmsa64Lpa2:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
            aarch64_vmsa::translation::Stage1,
            G,
            LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                CurrentRegime,
                G,
            >,
            TableFields = aarch64_vmsa::regime::TableFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                CurrentRegime,
                G,
            >,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, CurrentRegime, G>: Copy,
    aarch64_vmsa::attrs::VmsaAttributeCodec: aarch64_vmsa::attrs::AttributeCodec<
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
            CurrentRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<()>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
                (),
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits,
                (),
                aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
            >,
            RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64Lpa2,
                CurrentRegime,
                G,
            >,
            RawTable = aarch64_vmsa::regime::TableFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64Lpa2,
                CurrentRegime,
                G,
            >,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, MappingAttributes, PhysicalAddress};

    const ADDRESS: u64 = (1 << 50) | 0x6a00_0000;
    const VALUE: u64 = 0x4c50_4132_4d41_4c46;
    let page = context.allocate_granule(granule)?;
    let write = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let input = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::lpa2_el2_stage1_controls(granule, input, output)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root_in(context.native_pas(), granule)?;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            CurrentRegime,
            G,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(&mut root, start_level, 52, 52)?;
        mapper.map_attributes_leaf(
            ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            active_granule::<aarch64_vmsa::descriptor::Vmsa64Lpa2, G> as *const () as u64,
        )?;
        let leaf = mapper
            .inspect_walk(ADDRESS)?
            .leaf()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut replacement = leaf
            .raw
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        match mutation {
            Lpa2MalformedLeaf::ReservedType => replacement.low &= !(1 << 1),
            Lpa2MalformedLeaf::Address => replacement.low |= 1u64 << address_bit,
            Lpa2MalformedLeaf::Res0 => replacement.low |= 1u64 << res0_bit,
            Lpa2MalformedLeaf::Res1 => replacement.low &= !1,
        }
        mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ADDRESS, replacement)?;
    }
    let setup = vmsa_test_harness::TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
        stage: vmsa_test_harness::TranslationStage::Stage1,
        granule,
        format: vmsa_test_harness::TranslationFormat::Vmsa64Lpa2,
        input_bits: input,
        output_bits: output,
        start_level: LookupLevel::new(start_level.as_i8()),
        asid: None,
        vmid: None,
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    let translation = context.install_owned_in_sandbox(root, setup, &sandbox)?;
    let expected = if matches!(mutation, Lpa2MalformedLeaf::Address) {
        vmsa_test_harness::ExpectedFault::address_size_read_stage1()
    } else {
        vmsa_test_harness::ExpectedFault::translation_read_stage1()
    };
    let fault = vmsa_test_harness::expect_matching_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::FaultMatcher::new(expected)
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(ADDRESS)
            .with_ipa(None),
    );
    let mut root = translation.restore_owned()?;
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.emergency_restore_for_test();
    let fresh_address = ADDRESS
        .checked_add(G::SIZE)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            CurrentRegime,
            G,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(&mut root, start_level, 52, 52)?;
        mapper.map_attributes_leaf(
            fresh_address,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    }
    let fresh_translation = context.install_owned_in_sandbox(root, setup, &sandbox)?;
    let fresh = vmsa_test_harness::expect_value(context.read_u64(fresh_address), VALUE);
    drop(fresh_translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if !matches!(fresh, TestResult::Pass) {
        return fresh;
    }
    fault
}

#[derive(Clone, Copy)]
enum D128MalformedLeaf {
    ValidRes1,
    Skl,
    Address,
    Res0,
}

pub(super) fn d128_valid_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_d128_leaf(context, D128MalformedLeaf::ValidRes1)
}

pub(super) fn d128_skl(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_d128_leaf(context, D128MalformedLeaf::Skl)
}

pub(super) fn d128_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_d128_leaf(context, D128MalformedLeaf::Address)
}

pub(super) fn d128_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_d128_leaf(context, D128MalformedLeaf::Res0)
}

fn malformed_d128_leaf(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mutation: D128MalformedLeaf,
) -> TestResult {
    use vmsa_test_harness::{AddressBits, D128HardwareManagedAttributes, D128MappingPermissions};

    const ADDRESS: u64 = (1 << 50) | 0x7200_0000;
    const VALUE: u64 = 0x4431_3238_4d41_4c46;
    let page = context.allocate_page()?;
    let write = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = aarch64_vmsa::address::Level::NEG1;
    let controls = vmsa_test_harness::d128_el1_stage1_controls(
        vmsa_test_harness::Granule::Size4KiB,
        bits,
        bits,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    let observation = {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            crate::LowerRegime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >(&mut root, start, 52, 52)?;
        mapper.map_hardware_managed_page(
            ADDRESS,
            page.phys_addr(),
            D128HardwareManagedAttributes {
                permissions: D128MappingPermissions::ReadWrite,
                access_flag: true,
                dirty: true,
            },
        )?;
        let leaf = mapper
            .inspect_walk(ADDRESS)?
            .leaf()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let mut replacement = leaf
            .raw
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        match mutation {
            D128MalformedLeaf::ValidRes1 => replacement.low &= !1,
            D128MalformedLeaf::Skl => replacement.high |= 1 << (109 - 64),
            D128MalformedLeaf::Address => replacement.low |= 1 << 52,
            D128MalformedLeaf::Res0 => replacement.low |= 1 << 1,
        }
        let original = mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ADDRESS, replacement)?;
        let rejected = if matches!(mutation, D128MalformedLeaf::Address) {
            mapper.translate(ADDRESS) == Err(vmsa_test_harness::HarnessError::InvalidState)
        } else {
            mapper
                .inspect_walk(ADDRESS)?
                .steps()
                .last()
                .and_then(|step| *step)
                .is_some_and(|step| {
                    step.kind == vmsa_test_harness::WalkDescriptorKind::Invalid
                        && step.level
                            == vmsa_test_harness::LookupLevel::new(3)
                                .expect("L3 is an architectural level")
                })
        };
        let observation = if rejected {
            TestResult::Pass
        } else {
            TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::MissingFault,
                expected: 1,
                actual: 0,
            })
        };
        mapper
            .isolated_malformed_table()
            .replace_terminal_descriptor(ADDRESS, original)?;
        if mapper.inspect_walk(ADDRESS)?.leaf().is_none() {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        observation
    };
    let setup = vmsa_test_harness::TranslationSetup {
        root: vmsa_test_harness::PhysicalAddress::new(root.phys_addr()),
        stage: vmsa_test_harness::TranslationStage::Stage1,
        granule: vmsa_test_harness::Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa128,
        input_bits: bits,
        output_bits: bits,
        start_level: vmsa_test_harness::LookupLevel::new(start.as_i8()),
        asid: None,
        vmid: None,
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    };
    context.emergency_restore_for_test();
    let fresh_translation = context.install_lower_owned(root, setup)?;
    let fresh = vmsa_test_harness::expect_value(context.lower_read_u64(ADDRESS), VALUE);
    drop(fresh_translation);
    if !matches!(fresh, TestResult::Pass) {
        return fresh;
    }
    observation
}
