use crate::{CurrentEnvironment, CurrentRegime};
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn recursive_table_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, MappingAttributes, PhysicalAddress, TranslationControls,
        TranslationFormat, TranslationSetup, TranslationStage,
    };

    const ADDRESS: u64 = 0x6700_0000;
    const RECURSIVE_INDEX: usize = 1;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits: AddressBits::new(capabilities.va_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            output_bits: AddressBits::new(capabilities.pa_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    let start_level = translation
        .setup()
        .start_level
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .get();
    let mut recursive_base = 0u64;
    for level in start_level..=3 {
        let shift = match level {
            0 => 39,
            1 => 30,
            2 => 21,
            3 => 12,
            _ => {
                return vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into();
            }
        };
        recursive_base |= (RECURSIVE_INDEX as u64) << shift;
    }
    let updates = context.enable_hardware_updates(false)?;
    let mapping = translation.map_recursive_4k(
        RECURSIVE_INDEX,
        recursive_base,
        ADDRESS,
        page.phys_addr(),
        MappingAttributes::READ_WRITE,
    )?;
    if mapping.output != page.phys_addr() {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    drop(updates);
    let written = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x5245_4355));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    vmsa_test_harness::expect_value(context.read_u64(ADDRESS), 0x5245_4355)
}

pub(super) fn translation_table_read_write(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    if context.verify_translation_table_read_write() {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

fn offline_vmsa64_mapper<'a>(
    context: &'a TestContext<'_, CurrentEnvironment>,
    root: &'a mut vmsa_test_harness::RootTableMemory,
) -> Result<
    vmsa_test_harness::TestMapper<
        CurrentRegime,
        aarch64_vmsa::config::granule::Granule4KiB,
        aarch64_vmsa::config::format::Vmsa64,
    >,
    vmsa_test_harness::HarnessError,
> {
    context.offline_mapper_for_format_with_geometry::<
        CurrentRegime,
        aarch64_vmsa::config::granule::Granule4KiB,
        aarch64_vmsa::config::format::Vmsa64,
    >(root, aarch64_vmsa::address::Level::L0, 48, 48)
}

pub(super) fn walker_invalid_agreement(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let mut root = context.allocate_root()?;
    let mapper = offline_vmsa64_mapper(context, &mut root)?;
    let input = 0x1234_5678;
    let walk = mapper.inspect_walk(input)?;
    let Some(step) = walk.leaf() else {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    };
    if walk.steps().len() != 1
        || step.level != vmsa_test_harness::LookupLevel::new(0).unwrap()
        || step.kind != vmsa_test_harness::WalkDescriptorKind::Invalid
        || step.raw.is_some()
        || step.next_table.is_some()
        || step.output.is_some()
        || mapper.translate(input)?.is_some()
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub(super) fn walker_block_agreement(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const INPUT_BASE: u64 = 0x8000_0000;
    const OUTPUT_BASE: u64 = 0x4000_0000;
    const OFFSET: u64 = 0x12_3456;
    let mut root = context.allocate_root()?;
    let mut mapper = offline_vmsa64_mapper(context, &mut root)?;
    mapper.map_leaf(
        INPUT_BASE,
        OUTPUT_BASE,
        vmsa_test_harness::LookupLevel::new(1).unwrap(),
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(INPUT_BASE + OFFSET)?;
    let Some(leaf) = walk.leaf() else {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    };
    let translated = mapper
        .translate(INPUT_BASE + OFFSET)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() != 2
        || walk.steps()[0].map(|step| step.kind)
            != Some(vmsa_test_harness::WalkDescriptorKind::Table)
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Block
        || leaf.level != vmsa_test_harness::LookupLevel::new(1).unwrap()
        || leaf.output != Some(OUTPUT_BASE + OFFSET)
        || translated.output != OUTPUT_BASE + OFFSET
        || translated.level != vmsa_test_harness::LookupLevel::new(1).unwrap()
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub(super) fn walker_table_page_agreement(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const INPUT_BASE: u64 = 0x9000_0000;
    const OUTPUT_BASE: u64 = 0x2000_0000;
    const OFFSET: u64 = 0x678;
    let mut root = context.allocate_root()?;
    let mut mapper = offline_vmsa64_mapper(context, &mut root)?;
    mapper.map_leaf(
        INPUT_BASE,
        OUTPUT_BASE,
        vmsa_test_harness::LookupLevel::new(3).unwrap(),
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(INPUT_BASE + OFFSET)?;
    for (index, level) in (0i8..3).enumerate() {
        let Some(step) = walk.steps().get(index).and_then(|step| *step) else {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        };
        if step.level != vmsa_test_harness::LookupLevel::new(level).unwrap()
            || step.kind != vmsa_test_harness::WalkDescriptorKind::Table
            || step.raw.is_none()
            || step.next_table.is_none()
            || step.output.is_some()
        {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
    }
    let Some(leaf) = walk.leaf() else {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    };
    let translated = mapper
        .translate(INPUT_BASE + OFFSET)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() != 4
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.level != vmsa_test_harness::LookupLevel::new(3).unwrap()
        || leaf.output != Some(OUTPUT_BASE + OFFSET)
        || translated.output != OUTPUT_BASE + OFFSET
        || translated.level != vmsa_test_harness::LookupLevel::new(3).unwrap()
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

macro_rules! walker_error_case {
    ($name:ident, $verification:ident) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            if context.$verification() {
                TestResult::Pass
            } else {
                vmsa_test_harness::HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                }
                .into()
            }
        }
    };
}

walker_error_case!(walker_access_error, verify_walker_access_error);
walker_error_case!(
    walker_access_location_error,
    verify_walker_access_location_error
);
walker_error_case!(walker_cursor_error, verify_walker_cursor_error);
walker_error_case!(
    walker_invalid_table_address_error,
    verify_walker_invalid_table_address_error
);
walker_error_case!(walker_entry_index_error, verify_walker_entry_index_error);
walker_error_case!(walker_final_table_error, verify_walker_final_table_error);
walker_error_case!(
    walker_output_overflow_error,
    verify_walker_output_overflow_error
);
walker_error_case!(recursive_index_error, verify_recursive_index_error);
walker_error_case!(recursive_base_errors, verify_recursive_base_errors);
walker_error_case!(recursive_level_error, verify_recursive_level_error);
walker_error_case!(recursive_path_errors, verify_recursive_path_errors);
walker_error_case!(recursive_overflow_error, verify_recursive_overflow_error);
walker_error_case!(
    recursive_null_mapping_error,
    verify_recursive_null_mapping_error
);
