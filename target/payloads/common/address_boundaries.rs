use crate::{CurrentEnvironment, LowerRegime};
use vmsa_test_harness::{TestContext, TestResult};

fn stage1_boundary<F, G, P>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    input_width: u8,
    output_width: u8,
    format: vmsa_test_harness::TranslationFormat,
    controls: vmsa_test_harness::TranslationControls,
    pas: P,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    F: vmsa_test_harness::adapter::TestFormat
        + aarch64_vmsa::descriptor::DescriptorFormat
        + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>
        + aarch64_vmsa::regime::HasRegimeLayout<LowerRegime, G>,
    P: Copy + core::fmt::Debug + Eq + PartialEq,
    LowerRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    crate::LeafFieldsOf<F, LowerRegime, G>: Copy,
    F: vmsa_test_harness::AttributeCodecCompat<
            LowerRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<P>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::Stage1EffectivePermissions,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::TwoPrivilegeTablePermissionLimits,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
            >,
            RawLeaf = crate::LeafFieldsOf<F, LowerRegime, G>,
            RawTable = crate::TableFieldsOf<F, LowerRegime, G>,
        >,
{
    use aarch64_vmsa::attrs::*;
    use vmsa_test_harness::{AddressBits, LookupLevel, PhysicalAddress, TranslationQueryAccess};

    const FIRST_VALUE: u64 = 0x4649_5253_5450_4147;
    const LAST_VALUE: u64 = 0x4c41_5354_5041_4745;
    let first_page = context.allocate_granule(granule)?;
    let last_page = context.allocate_granule(granule)?;
    for (page, value) in [(&first_page, FIRST_VALUE), (&last_page, LAST_VALUE)] {
        let initialized =
            vmsa_test_harness::expect_completed(context.write_u64(page.virtual_address() as u64 + 8, value));
        if !matches!(initialized, TestResult::Pass) {
            return initialized;
        }
    }
    let first = 8;
    let last = (1u64 << input_width) - granule.bytes() as u64 + 8;
    let input_bits = AddressBits::new(input_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(output_width)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: Stage1PermissionSettings::direct(),
        stage2_permissions: Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: pas,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: false,
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: TwoPrivilegeTablePermissionLimits {
            privileged_data_limit: DataAccess::ReadWrite,
            unprivileged_data_limit: DataAccess::ReadWrite,
            privileged_execute_limit: false,
            unprivileged_execute_limit: false,
        },
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let root = context.allocate_root_in(context.native_pas(), granule)?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_lower_owned(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule,
            format,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(start_level.as_i8()),
            asid: None,
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::lower_regime_attributes(),
        },
    )?;
    for (input, page) in [(first, &first_page), (last, &last_page)] {
        translation.map_semantic_for::<LowerRegime, F, G, _>(
            &config,
            input & !(granule.bytes() as u64 - 1),
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        )?;
        let target = page.phys_addr() + 8;
        match context.translate_lower_stage1(input, TranslationQueryAccess::Read) {
            vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. }
                if physical_address == target => {}
            vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. } => {
                return TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target,
                    actual: physical_address,
                });
            }
            vmsa_test_harness::TranslationQueryResult::Fault { raw, .. } => {
                return TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target,
                    actual: raw,
                });
            }
            vmsa_test_harness::TranslationQueryResult::Unsupported => {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: target,
                    actual: u64::MAX,
                }
                .into();
            }
        }
    }
    let high_input = granule.bytes() as u64 + 8;
    let high_output_page = (1u64 << output_width) - granule.bytes() as u64;
    translation.map_semantic_for::<LowerRegime, F, G, _>(
        &config,
        high_input & !(granule.bytes() as u64 - 1),
        high_output_page,
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    match context.translate_lower_stage1(high_input, TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. }
            if physical_address == high_output_page + 8 => {}
        vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. } => {
            return TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongValue,
                expected: high_output_page + 8,
                actual: physical_address,
            });
        }
        vmsa_test_harness::TranslationQueryResult::Fault { raw, .. } => {
            return TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongValue,
                expected: high_output_page + 8,
                actual: raw,
            });
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: high_output_page + 8,
                actual: u64::MAX,
            }
            .into();
        }
    }
    let first_result = vmsa_test_harness::expect_value(context.lower_read_u64(first), FIRST_VALUE);
    if !matches!(first_result, TestResult::Pass) {
        return first_result;
    }
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(last), LAST_VALUE);
    drop(translation);
    result
}

macro_rules! boundary_case {
    ($name:ident, $granule_type:ty, $granule:expr, $level:expr, $width:expr, $output:expr) => {
        pub fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            let bits = vmsa_test_harness::AddressBits::new($width)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let controls = vmsa_test_harness::vmsa64_el1_stage1_controls($granule, bits, vmsa_test_harness::AddressBits::new($output).unwrap())
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            stage1_boundary::<aarch64_vmsa::config::format::Vmsa64, $granule_type, crate::LowerPas>(
                context, $granule, $level, $width, $output, vmsa_test_harness::TranslationFormat::Vmsa64, controls, crate::lower_pas(),
            )
        }
    };
}

boundary_case!(vmsa64_stage1_4k_l0, aarch64_vmsa::config::granule::Granule4KiB, vmsa_test_harness::Granule::Size4KiB, aarch64_vmsa::address::Level::L0, 48, 48);
boundary_case!(vmsa64_stage1_4k_l1, aarch64_vmsa::config::granule::Granule4KiB, vmsa_test_harness::Granule::Size4KiB, aarch64_vmsa::address::Level::L1, 39, 48);
boundary_case!(vmsa64_stage1_16k_l0, aarch64_vmsa::config::granule::Granule16KiB, vmsa_test_harness::Granule::Size16KiB, aarch64_vmsa::address::Level::L0, 48, 48);
boundary_case!(vmsa64_stage1_16k_l1, aarch64_vmsa::config::granule::Granule16KiB, vmsa_test_harness::Granule::Size16KiB, aarch64_vmsa::address::Level::L1, 47, 48);
boundary_case!(vmsa64_stage1_16k_l2, aarch64_vmsa::config::granule::Granule16KiB, vmsa_test_harness::Granule::Size16KiB, aarch64_vmsa::address::Level::L2, 36, 48);
boundary_case!(vmsa64_stage1_64k_l1, aarch64_vmsa::config::granule::Granule64KiB, vmsa_test_harness::Granule::Size64KiB, aarch64_vmsa::address::Level::L1, 48, 48);
boundary_case!(vmsa64_stage1_64k_l2, aarch64_vmsa::config::granule::Granule64KiB, vmsa_test_harness::Granule::Size64KiB, aarch64_vmsa::address::Level::L2, 42, 48);

macro_rules! lpa2_boundary_case {
    ($name:ident, $granule_type:ty, $granule:expr, $level:expr) => {
        pub fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            let bits = vmsa_test_harness::AddressBits::new(52)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            let controls = vmsa_test_harness::lpa2_el1_stage1_controls($granule, bits, bits)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            stage1_boundary::<aarch64_vmsa::config::format::Vmsa64Lpa2, $granule_type, crate::LowerPas>(
                context, $granule, $level, 52, 52, vmsa_test_harness::TranslationFormat::Vmsa64Lpa2, controls, crate::lower_pas(),
            )
        }
    };
}

lpa2_boundary_case!(lpa2_stage1_4k_lneg1, aarch64_vmsa::config::granule::Granule4KiB, vmsa_test_harness::Granule::Size4KiB, aarch64_vmsa::address::Level::NEG1);
lpa2_boundary_case!(lpa2_stage1_16k_l0, aarch64_vmsa::config::granule::Granule16KiB, vmsa_test_harness::Granule::Size16KiB, aarch64_vmsa::address::Level::L0);
lpa2_boundary_case!(lpa2_stage1_64k_l1, aarch64_vmsa::config::granule::Granule64KiB, vmsa_test_harness::Granule::Size64KiB, aarch64_vmsa::address::Level::L1);

fn d128_stage1_boundary<G>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    LowerRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa128:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    <aarch64_vmsa::config::format::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        G,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::translation::Stage1,
            G,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    use vmsa_test_harness::{AddressBits, LookupLevel, PhysicalAddress, TranslationQueryAccess};
    const FIRST_VALUE: u64 = 0x4431_3238_4652_5354;
    const LAST_VALUE: u64 = 0x4431_3238_4c41_5354;
    let first_page = context.allocate_granule(granule)?;
    let last_page = context.allocate_granule(granule)?;
    for (page, value) in [(&first_page, FIRST_VALUE), (&last_page, LAST_VALUE)] {
        let initialized = vmsa_test_harness::expect_completed(
            context.write_u64(page.virtual_address() as u64 + 8, value),
        );
        if !matches!(initialized, TestResult::Pass) {
            return initialized;
        }
    }
    let first = 8;
    let last = (1u64 << 52) - granule.bytes() as u64 + 8;
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root_in(context.native_pas(), granule)?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            LowerRegime,
            G,
            aarch64_vmsa::config::format::Vmsa128,
        >(&mut root, start_level, 52, 52)?;
        for (input, page) in [(first, &first_page), (last, &last_page)] {
            mapper.map_hardware_managed_leaf_exact(
                input & !(granule.bytes() as u64 - 1),
                page.phys_addr(),
                3,
                vmsa_test_harness::D128HardwareManagedAttributes {
                    permissions: vmsa_test_harness::D128MappingPermissions::ReadWrite,
                    access_flag: true,
                    dirty: true,
                },
            )
            .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
        }
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let controls = vmsa_test_harness::d128_el1_stage1_controls(granule, bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let translation = context.install_lower_owned(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa128,
            input_bits: bits,
            output_bits: bits,
            start_level: LookupLevel::new(start_level.as_i8()),
            asid: None,
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::lower_regime_attributes(),
        },
    )?;
    for (input, page) in [(first, &first_page), (last, &last_page)] {
        let target = page.phys_addr() + 8;
        let observed = context
            .translate_lower_stage1_d128_raw(input, TranslationQueryAccess::Read)
            .map(|(low, high)| {
                vmsa_test_harness::TranslationQueryResult::from_raw_par128_for_test(
                    input, low, high,
                )
            });
        match observed {
            Some(vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. })
                if physical_address == target => {}
            Some(vmsa_test_harness::TranslationQueryResult::Success { physical_address, .. }) => {
                return TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target,
                    actual: physical_address,
                });
            }
            Some(vmsa_test_harness::TranslationQueryResult::Fault { raw, .. }) => {
                return TestResult::Fail(vmsa_test_harness::TestFailure {
                    kind: vmsa_test_harness::FailureKind::WrongValue,
                    expected: target,
                    actual: raw,
                });
            }
            _ => {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: target,
                    actual: u64::MAX,
                }
                .into();
            }
        }
    }
    let first_result = vmsa_test_harness::expect_value(context.lower_read_u64(first), FIRST_VALUE);
    if !matches!(first_result, TestResult::Pass) {
        return first_result;
    }
    let result = vmsa_test_harness::expect_value(context.lower_read_u64(last), LAST_VALUE);
    drop(translation);
    result
}

macro_rules! d128_boundary_case {
    ($name:ident, $granule_type:ty, $granule:expr, $level:expr) => {
        pub fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            d128_stage1_boundary::<$granule_type>(context, $granule, $level)
        }
    };
}

d128_boundary_case!(d128_stage1_4k_lneg1, aarch64_vmsa::config::granule::Granule4KiB, vmsa_test_harness::Granule::Size4KiB, aarch64_vmsa::address::Level::NEG1);
d128_boundary_case!(d128_stage1_16k_l0, aarch64_vmsa::config::granule::Granule16KiB, vmsa_test_harness::Granule::Size16KiB, aarch64_vmsa::address::Level::L0);
d128_boundary_case!(d128_stage1_64k_l1, aarch64_vmsa::config::granule::Granule64KiB, vmsa_test_harness::Granule::Size64KiB, aarch64_vmsa::address::Level::L1);
