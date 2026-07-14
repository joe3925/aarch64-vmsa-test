use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn hardware_access_dirty(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::descriptor::Vmsa64;
    use vmsa_test_harness::{
        AddressBits, Granule, HardwareManagedAttributes, LookupLevel, MappingAttributes,
        PhysicalAddress, TranslationControls, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    const ADDRESS: u64 = 0x6500_0000;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    translation.map_hardware_managed::<Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        HardwareManagedAttributes {
            mapping: MappingAttributes::READ_WRITE,
            access_flag: false,
            dirty_modifier: false,
        },
    )?;
    let access_flag_fault = vmsa_test_harness::expect_matching_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::AccessFlag),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: LookupLevel::new(3),
        })
        .with_class(vmsa_test_harness::FaultClass::DataAbort)
        .at_address(ADDRESS)
        .with_ipa(None),
    );
    if !matches!(access_flag_fault, TestResult::Pass) {
        return access_flag_fault;
    }
    {
        let _updates = context.enable_hardware_updates(false)?;
        let result = vmsa_test_harness::expect_completed(context.read_u64(ADDRESS));
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    if !translation
        .inspect_hardware_updates::<Granule4KiB>(ADDRESS)?
        .access_flag
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    translation.unmap::<Vmsa64, Granule4KiB>(ADDRESS)?;
    translation.map_hardware_managed::<Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        HardwareManagedAttributes {
            mapping: MappingAttributes::READ_ONLY,
            access_flag: true,
            dirty_modifier: true,
        },
    )?;
    {
        let _updates = context.enable_hardware_updates(true)?;
        let result = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x4841_4844));
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    let became_writable = translation
        .inspect_hardware_updates::<Granule4KiB>(ADDRESS)?
        .writable;
    if became_writable {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}
