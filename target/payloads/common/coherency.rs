use vmsa_test_harness::{
    AddressBits, ExpectedFault, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TestContext, TestResult, TranslationControls, TranslationSetup,
    TranslationStage, expect_fault, expect_value,
};

pub fn generated_execution<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime:
        vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::config::granule::Granule4KiB>,
    aarch64_vmsa::config::format::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<E::Regime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
    crate::LeafFieldsOf<
        aarch64_vmsa::config::format::Vmsa64,
        E::Regime,
        aarch64_vmsa::config::granule::Granule4KiB,
    >: Copy,
    crate::TableFieldsOf<
        aarch64_vmsa::config::format::Vmsa64,
        E::Regime,
        aarch64_vmsa::config::granule::Granule4KiB,
    >: Copy,
{
    const EXECUTE_ADDRESS: u64 = 0x6400_0000;
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    for (offset, instruction) in [(0, 0xd280_0020), (4, 0xd65f_03c0)] {
        let write = context.write_u32(address + offset, instruction);
        if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(write);
        }
    }
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let setup = TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: LookupLevel::new(0),
        asid: None,
        vmid: None,
        controls: TranslationControls::PRESERVE_CURRENT,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime,
    };
    let mut translation = context.install_owned(root, setup)?;
    translation
        .map::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
            EXECUTE_ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes {
                writable: false,
                executable: true,
                user_accessible: false,
            },
        )?;
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
            address: EXECUTE_ADDRESS,
            bytes: 8,
        },
    )?;
    let first = expect_value(context.execute(EXECUTE_ADDRESS), 1);
    if !matches!(first, TestResult::Pass) {
        return first;
    }
    let modify = context.write_u32(address, 0xd280_0040);
    if !matches!(modify, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(modify);
    }
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
            address: EXECUTE_ADDRESS,
            bytes: 8,
        },
    )?;
    let modified = expect_value(context.execute(EXECUTE_ADDRESS), 2);
    if !matches!(modified, TestResult::Pass) {
        return modified;
    }
    translation.protect::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
        EXECUTE_ADDRESS,
        MappingAttributes::READ_WRITE,
    )?;
    let execute_never = expect_fault(
        context.execute(EXECUTE_ADDRESS),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Permission),
            access: Some(vmsa_test_harness::AccessKind::Execute),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(execute_never, TestResult::Pass) {
        return execute_never;
    }
    translation.protect::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
        EXECUTE_ADDRESS,
        MappingAttributes {
            writable: false,
            executable: true,
            user_accessible: false,
        },
    )?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
        address,
        bytes: 8,
    })?;
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::CleanInvalidateData { address, bytes: 8 },
    )?;
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::InvalidateData { address, bytes: 8 },
    )?;
    context
        .maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::TranslationTableVisibility)?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
            address: EXECUTE_ADDRESS,
            bytes: 8,
        },
    )?;
    let final_execution = expect_value(context.execute(EXECUTE_ADDRESS), 2);
    if !matches!(final_execution, TestResult::Pass) {
        return final_execution;
    }

    translation.restore()?;
    TestResult::Pass
}

pub fn multi_pe_translation_visibility<E>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::config::granule::Granule4KiB>
        + vmsa_test_harness::adapter::HardwareManagedStage1Regime<
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
    aarch64_vmsa::config::format::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            crate::StageOf<E::Regime>,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
    crate::LeafFieldsOf<
        aarch64_vmsa::config::format::Vmsa64,
        E::Regime,
        aarch64_vmsa::config::granule::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x6800_0000;
    const VALUE: u64 = 0x4d55_4c54_492d_5045;
    let page = context.allocate_page()?;
    let remap_page = context.allocate_page()?;
    let backing = page.virtual_address() as u64;
    let remap_backing = remap_page.virtual_address() as u64;
    let write = context.write_u64(backing, VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let remap_value = VALUE + 1;
    if !matches!(
        context.write_u64(remap_backing, remap_value),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits: AddressBits::new(capabilities.va_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            output_bits: AddressBits::new(capabilities.pa_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    translation
        .map::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
            ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
        address: backing,
        bytes: core::mem::size_of::<u64>(),
    })?;
    context
        .maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::TranslationTableVisibility)?;
    let primary = expect_value(context.read_u64(ADDRESS), VALUE);
    if !matches!(primary, TestResult::Pass) {
        return primary;
    }
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    let mut secondary = context.secondary_pe_session()?;
    let first = expect_value(secondary.read_u64(ADDRESS), VALUE);
    if !matches!(first, TestResult::Pass) {
        return first;
    }
    secondary.stop()?;
    let mut following = context.secondary_pe_session()?;
    let result = expect_value(following.read_u64(ADDRESS), VALUE);
    following.stop()?;
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    translation
        .remap::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
            ADDRESS,
            remap_page.phys_addr(),
            MappingAttributes::READ_WRITE,
        )?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
        address: remap_backing,
        bytes: core::mem::size_of::<u64>(),
    })?;
    context
        .maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::TranslationTableVisibility)?;
    translation.tlbi_scoped(
        vmsa_test_harness::TlbiScope::Local,
        vmsa_test_harness::TlbiOperation::VirtualAddress(ADDRESS),
    )?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(ADDRESS))?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    let mut remapped_secondary = context.secondary_pe_session()?;
    let remapped_result = expect_value(remapped_secondary.read_u64(ADDRESS), remap_value);
    remapped_secondary.stop()?;
    if !matches!(remapped_result, TestResult::Pass) {
        return remapped_result;
    }
    if !matches!(
        context.write_u64(ADDRESS, 7),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::SecondaryPe)?;
    if !matches!(
        execution.translate(
            ADDRESS,
            vmsa_test_harness::TranslationQueryAccess::Read,
        ),
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == remap_page.phys_addr()
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    if !matches!(
        execution.write_u8(ADDRESS, 0x5a),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u8(ADDRESS),
        vmsa_test_harness::AccessResult::Completed { value: 0x5a }
    ) || !matches!(
        execution.write_u16(ADDRESS, 0xa55a),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u16(ADDRESS),
        vmsa_test_harness::AccessResult::Completed { value: 0xa55a }
    ) || !matches!(
        execution.write_u32(ADDRESS, 0x89ab_cdef),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_u32(ADDRESS),
        vmsa_test_harness::AccessResult::Completed { value: 0x89ab_cdef }
    ) || !matches!(
        execution.execute(crate::runtime_support::execution_probe as *const () as usize as u64),
        vmsa_test_harness::AccessResult::Completed {
            value: 0x5345_434f_4e44_4152
        }
    ) || !matches!(
        execution.write_release_u64(ADDRESS, 7),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) || !matches!(
        execution.read_acquire_u64(ADDRESS),
        vmsa_test_harness::AccessResult::Completed { value: 7 }
    ) || !matches!(
        execution.atomic_swap_u64(ADDRESS, 11),
        vmsa_test_harness::AccessResult::Completed { value: 7 }
    ) || !matches!(
        execution.exclusive_add_u64(ADDRESS, 5),
        vmsa_test_harness::AccessResult::Completed { value: 11 }
    ) || !matches!(
        execution.write_pair_u64(ADDRESS, VALUE, VALUE + 1),
        vmsa_test_harness::AccessResult::CompletedPair { .. }
    ) || !matches!(
        execution.read_pair_u64(ADDRESS),
        vmsa_test_harness::AccessResult::CompletedPair {
            first: VALUE,
            second
        } if second == VALUE + 1
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let secondary_fault = expect_fault(
        execution.read_pair_u64(ADDRESS + 1),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Alignment),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(secondary_fault, TestResult::Pass) {
        return secondary_fault;
    }
    execution.finish()?;
    translation
        .unmap::<aarch64_vmsa::config::format::Vmsa64, aarch64_vmsa::config::granule::Granule4KiB>(
            ADDRESS,
        )?;
    translation.map_hardware_managed::<aarch64_vmsa::config::granule::Granule4KiB>(
        ADDRESS,
        remap_page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::HardwareManagedAttributes {
            mapping: MappingAttributes::READ_WRITE,
            access_flag: false,
            dirty_modifier: false,
        },
    )?;
    context
        .maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::TranslationTableVisibility)?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(ADDRESS))?;
    {
        let _updates = context.enable_hardware_updates(false)?;
        let mut hardware_secondary = context.secondary_pe_session()?;
        let hardware_result = expect_value(hardware_secondary.read_u64(ADDRESS), VALUE);
        hardware_secondary.stop()?;
        if !matches!(hardware_result, TestResult::Pass) {
            return hardware_result;
        }
    }
    if !translation
        .inspect_hardware_updates::<aarch64_vmsa::config::granule::Granule4KiB>(ADDRESS)?
        .access_flag
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}
