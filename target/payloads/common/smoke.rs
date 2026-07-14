use vmsa_test_harness::{
    AddressBits, Asid, ExpectedFault, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TestContext, TestResult, TranslationControls, TranslationSetup,
    TranslationStage, Vmid, expect_fault, expect_value, vmsa64_stage2_controls_4k,
};

pub fn realm_pas_semantics<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience, RealmOrNonSecurePa,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
        Shareability, SoftwareMetadata, Stage2LeafPermissions, Stage2MemoryAttributes,
        Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::RealmEl2Stage2;

    const ADDRESS: u64 = 0x5100_0000;
    let cacheability = Cacheability::Cacheable {
        policy: CachePolicy::WriteBack,
        transience: MemoryTransience::NonTransient,
        allocation: AllocationHints::ReadWriteAllocate,
    };
    let memory = MemoryAttributes::Normal {
        inner: cacheability,
        outer: cacheability,
    };
    let config = |output_pas| LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas,
    };
    let leaf = |output_address_space| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory),
        permissions: Stage2LeafPermissions {
            data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let output = context.allocate_contiguous(2)?;
    let mut root = context.allocate_root()?;
    let mut mapper = context
        .offline_mapper_for_format_with_geometry::<RealmEl2Stage2, Granule4KiB, Vmsa64>(
            &mut root,
            aarch64_vmsa::address::Level::L0,
            48,
            48,
        )?;
    for (index, pas) in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure]
        .into_iter()
        .enumerate()
    {
        let address = ADDRESS + index as u64 * 4096;
        let config = config(pas);
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            address,
            output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf(pas),
            SemanticVmsa64Stage2TableAttrs::default(),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.output_address_space != pas {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    TestResult::Pass
}

pub(crate) extern "C" fn execution_probe() -> u64 {
    0x5345_434f_4e44_4152
}

struct IdentityBuffer {
    bytes: [u8; 160],
    length: usize,
}

impl core::fmt::Write for IdentityBuffer {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or(core::fmt::Error)?;
        let target = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(core::fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub fn matrix_catalog<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    use core::fmt::Write;
    use vmsa_test_harness::{
        Applicability, BootProfile, ExecutionContext, HarnessCapabilities, HarnessCapability,
        IsolationRequirement, MatrixSelection, SecurityEnvironment, SecurityEnvironments,
        TranslationOwnership,
    };

    let Some(entry) = vmsa_test_harness::TEST_CATALOG
        .iter()
        .find(|entry| entry.id == vmsa_test_harness::LogicalTest::AdapterStateMachine)
    else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let mut cases = entry.architecture.cases(entry.name);
    let Some(first) = cases.next() else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let expected_selection = MatrixSelection {
        environment: SecurityEnvironment::Normal,
        boot_profile: BootProfile::NsEl2,
        ownership: TranslationOwnership::CurrentStage1,
        context: ExecutionContext::CurrentEl,
        format: vmsa_test_harness::DescriptorFormat::Vmsa64,
        granule: vmsa_test_harness::TranslationGranule::Size4KiB,
    };
    if first.selection != expected_selection {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut identity = IdentityBuffer {
        bytes: [0; 160],
        length: 0,
    };
    if write!(&mut identity, "{first}").is_err()
        || core::str::from_utf8(&identity.bytes[..identity.length])
            != Ok(
                "smoke.adapter-state-machine/env=normal/boot=ns-el2/owner=current-stage1/exec=current-el/format=vmsa64/granule=4k",
            )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let available = HarnessCapabilities::one(HarnessCapability::AdapterStateMachine);
    if entry
        .architecture
        .classify(expected_selection, available, true)
        != Applicability::Applicable
        || entry
            .architecture
            .classify(expected_selection, HarnessCapabilities::NONE, true)
            != Applicability::AdapterMissing
        || entry
            .architecture
            .classify(expected_selection, available, false)
            != Applicability::Unsupported
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut specialized = entry.architecture;
    specialized.environments = SecurityEnvironments::SECURE;
    if specialized.classify(expected_selection, available, true) != Applicability::Inapplicable {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    specialized = entry.architecture;
    specialized.isolation = IsolationRequirement::SeparateBoot;
    if specialized.classify(expected_selection, available, true) != Applicability::Isolated {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    specialized.expects_model_termination = true;
    if specialized.classify(expected_selection, available, true) != Applicability::Destructive {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn adapter_state_machine<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    if context.verify_invalid_adapter_transition_rejected()
        && context.verify_common_abi_rejection()
        && context.verify_fault_normalization()
    {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}

pub fn current_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let native_pas = context.native_pas();
    if context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::FirmwareShared)
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let page = context.allocate_page_in(native_pas)?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::CurrentEl)?;
    let write = execution.write_u64(address, 0x564d_5341_5445_5354);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x564d_5341_5445_5354);
    execution.finish()?;
    result
}

pub fn access_widths<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let pages = context.allocate_contiguous(2)?;
    let base = pages.virtual_address() as u64;
    for result in [
        context.write_u8(base, 0xa5),
        context.write_u16(base + 2, 0xb6c7),
        context.write_u32(base + 4, 0xd8e9_f001),
        context.write_u64(base + 8, 0x1234_5678_9abc_def0),
    ] {
        if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(result);
        }
    }
    for (result, expected) in [
        (context.read_u8(base), 0xa5),
        (context.read_u16(base + 2), 0xb6c7),
        (context.read_u32(base + 4), 0xd8e9_f001),
        (context.read_u64(base + 8), 0x1234_5678_9abc_def0),
    ] {
        let checked = expect_value(result, expected);
        if !matches!(checked, TestResult::Pass) {
            return checked;
        }
    }
    for address in [base + 9, base + 4092] {
        let checked = vmsa_test_harness::expect_matching_fault(
            context.write_u64(address, 0x0fed_cba9_8765_4321),
            vmsa_test_harness::FaultMatcher::new(ExpectedFault {
                status: Some(vmsa_test_harness::FaultStatus::Alignment),
                access: Some(vmsa_test_harness::AccessKind::Write),
                stage: Some(vmsa_test_harness::FaultStage::Stage1),
                level: None,
            })
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(address)
            .with_ipa(None),
        );
        if !matches!(checked, TestResult::Pass) {
            return checked;
        }
    }
    TestResult::Pass
}

pub fn pair_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let first = 0x0123_4567_89ab_cdef;
    let second = 0xfedc_ba98_7654_3210;
    match context.write_pair_u64(address, first, second) {
        vmsa_test_harness::AccessResult::CompletedPair { .. } => {}
        result => return vmsa_test_harness::expect_completed(result),
    }
    match context.read_pair_u64(address) {
        vmsa_test_harness::AccessResult::CompletedPair {
            first: observed_first,
            second: observed_second,
        } if observed_first == first && observed_second == second => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    let fault = expect_fault(
        context.read_pair_u64(address + 1),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Alignment),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
        vmsa_test_harness::ExecutionContext::El0UnderEl2,
    ] {
        let mut execution = context.execution(execution_context)?;
        if !matches!(
            execution.write_pair_u64(address, first, second),
            vmsa_test_harness::AccessResult::CompletedPair { .. }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        match execution.read_pair_u64(address) {
            vmsa_test_harness::AccessResult::CompletedPair {
                first: observed_first,
                second: observed_second,
            } if observed_first == first && observed_second == second => {}
            _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
        }
        execution.finish()?;
    }
    TestResult::Pass
}

pub fn ordered_atomic_access<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let released = context.write_release_u64(address, 7);
    if !matches!(released, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(released);
    }
    let acquired = expect_value(context.read_acquire_u64(address), 7);
    if !matches!(acquired, TestResult::Pass) {
        return acquired;
    }
    let swapped = expect_value(context.atomic_swap_u64(address, 11), 7);
    if !matches!(swapped, TestResult::Pass) {
        return swapped;
    }
    let exclusive = expect_value(context.exclusive_add_u64(address, 5), 11);
    if !matches!(exclusive, TestResult::Pass) {
        return exclusive;
    }
    let final_value = expect_value(context.read_u64(address), 16);
    if !matches!(final_value, TestResult::Pass) {
        return final_value;
    }
    let alignment = expect_fault(
        context.atomic_swap_u64(address + 1, 0),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Alignment),
            access: None,
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(alignment, TestResult::Pass) {
        return alignment;
    }
    let fault = expect_fault(
        context.exclusive_add_u64(invalid_virtual_address(context), 1),
        ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::Translation),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: Some(vmsa_test_harness::FaultStage::Stage1),
            level: None,
        },
    );
    if !matches!(fault, TestResult::Pass) {
        return fault;
    }
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
    ] {
        if !matches!(
            context.write_u64(address, 7),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let mut execution = context.execution(execution_context)?;
        if !matches!(
            execution.write_release_u64(address, 7),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        if !matches!(
            execution.read_acquire_u64(address),
            vmsa_test_harness::AccessResult::Completed { value: 7 }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        execution.finish()?;
        if !matches!(
            context.read_u64(address),
            vmsa_test_harness::AccessResult::Completed { value: 7 }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    TestResult::Pass
}

pub fn address_translation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    match context.translate_current_stage1(address, vmsa_test_harness::TranslationQueryAccess::Read)
    {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == page.phys_addr() => {}
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            return vmsa_test_harness::HarnessError::Memory.into();
        }
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
            return vmsa_test_harness::HarnessError::Environment.into();
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    match context.translate_current_stage1(
        invalid_virtual_address(context),
        vmsa_test_harness::TranslationQueryAccess::Read,
    ) {
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            vmsa_test_harness::HarnessError::Memory.into()
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::InvalidState.into()
        }
    }
}

pub fn lower_address_translation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
    _: RegimeAttributes,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    for execution_context in [
        vmsa_test_harness::ExecutionContext::El1,
        vmsa_test_harness::ExecutionContext::El0UnderEl1,
    ] {
        let mut execution = context.execution(execution_context)?;
        let query = execution.translate(address, vmsa_test_harness::TranslationQueryAccess::Read);
        match query {
            vmsa_test_harness::TranslationQueryResult::Success { .. } => {}
            vmsa_test_harness::TranslationQueryResult::Fault { .. } => {
                return vmsa_test_harness::HarnessError::Environment.into();
            }
            vmsa_test_harness::TranslationQueryResult::Unsupported => {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        execution.finish()?;
    }
    let mut host_el0 = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    match host_el0.translate(address, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == address => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    host_el0.finish()?;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El1)?;
    let invalid_query = execution.translate(
        1u64 << context.capabilities().va_bits.min(52),
        vmsa_test_harness::TranslationQueryAccess::Read,
    );
    let result = match invalid_query {
        vmsa_test_harness::TranslationQueryResult::Fault { .. } => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Success { .. } => {
            vmsa_test_harness::HarnessError::Memory.into()
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::InvalidState.into()
        }
    };
    execution.finish()?;
    result
}

pub fn generated_execution<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
    aarch64_vmsa::regime::TableFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
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
    let injected_root = context.allocate_root()?;
    let mut injected_setup = setup;
    injected_setup.root = PhysicalAddress::new(injected_root.phys_addr());
    let injected_install = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::TranslationInstallation,
        0,
        || context.install_owned(injected_root, injected_setup),
    );
    if !matches!(
        injected_install,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
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
    translation.protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
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
    translation.protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
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

    let injected_restore = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::TranslationRestoration,
        0,
        || translation.restore(),
    );
    if !matches!(
        injected_restore,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    // The consumed guard's Drop path must restore the original translation even
    // when the explicit restoration operation reports an injected failure.
    let following_root = context.allocate_root()?;
    let mut following_setup = setup;
    following_setup.root = PhysicalAddress::new(following_root.phys_addr());
    context
        .install_owned(following_root, following_setup)?
        .restore()?;
    TestResult::Pass
}

pub fn live_range_mapping<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x661f_f000;
    const PAGES: u64 = 3;
    let pages = context.allocate_contiguous(PAGES as usize)?;
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
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime,
        },
    )?;
    let injected_range =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Map, 0, || {
            translation
                .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    pages.phys_addr(),
                    PAGES * 4096,
                    LookupLevel::new(3).expect("level 3 is valid"),
                    MappingAttributes::READ_WRITE,
                )
        });
    if !matches!(
        injected_range,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for index in 0..PAGES {
        if translation
            .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS + index * 4096,
            )?
            .is_some()
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let outcome = translation
        .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
            pages.phys_addr(),
            PAGES * 4096,
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    let expected_tables = 2;
    if outcome.mappings_created != PAGES
        || outcome.bytes_mapped != PAGES * 4096
        || outcome.tables_allocated != expected_tables
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let final_mapping = translation
        .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS + (PAGES - 1) * 4096,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if final_mapping.output != pages.phys_addr() + (PAGES - 1) * 4096
        || final_mapping.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS + (PAGES - 1) * 4096,
        )?;
    let first_walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?;
    let steps = walk.steps();
    let first_steps = first_walk.steps();
    let effective_start = translation
        .setup()
        .start_level
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .get();
    let expected_length = usize::try_from(4 - i16::from(effective_start))
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if steps.len() != expected_length || first_steps.len() != expected_length {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let first_leaf_table = first_steps
        .get(expected_length - 2)
        .and_then(|step| *step)
        .and_then(|step| step.next_table);
    let final_leaf_table = steps
        .get(expected_length - 2)
        .and_then(|step| *step)
        .and_then(|step| step.next_table);
    if first_leaf_table.is_none()
        || final_leaf_table.is_none()
        || first_leaf_table == final_leaf_table
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for (index, expected_level) in (effective_start..3).enumerate() {
        let Some(step) = steps[index] else {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        };
        if step.level != LookupLevel::new(expected_level).expect("walk level is valid")
            || step.kind != vmsa_test_harness::WalkDescriptorKind::Table
            || step.raw.is_none()
            || step.next_table.is_none()
            || step.output.is_some()
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    let Some(leaf) = walk.leaf() else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    if leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.raw.is_none()
        || leaf.next_table.is_some()
        || leaf.output != Some(pages.phys_addr() + (PAGES - 1) * 4096)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for index in 0..PAGES {
        let address = ADDRESS + index * 4096;
        let value = 0x5241_4e47_4500_0000 | index;
        let written = vmsa_test_harness::expect_completed(context.write_u64(address, value));
        if !matches!(written, TestResult::Pass) {
            return written;
        }
        let read = expect_value(context.read_u64(address), value);
        if !matches!(read, TestResult::Pass) {
            return read;
        }
    }
    for index in 0..PAGES {
        let removed = translation
            .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS + index * 4096,
            )?;
        if removed.output != pages.phys_addr() + index * 4096 {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }
    for index in 0..PAGES {
        let fault = expect_fault(
            context.read_u64(ADDRESS + index * 4096),
            ExpectedFault::translation_read_stage1(),
        );
        if !matches!(fault, TestResult::Pass) {
            return fault;
        }
    }
    TestResult::Pass
}

pub fn multi_pe_translation_visibility<E>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>
        + vmsa_test_harness::adapter::HardwareManagedStage1Regime<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
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
    let injected_secondary = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeStartup,
        0,
        || context.secondary_pe_session(),
    );
    if !matches!(
        injected_secondary,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    let mut secondary = context.secondary_pe_session()?;
    let first = expect_value(secondary.read_u64(ADDRESS), VALUE);
    if !matches!(first, TestResult::Pass) {
        return first;
    }
    let injected_cleanup =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Cleanup, 0, || {
            secondary.stop()
        });
    if !matches!(
        injected_cleanup,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut following = context.secondary_pe_session()?;
    let result = expect_value(following.read_u64(ADDRESS), VALUE);
    following.stop()?;
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    translation.remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
        execution.execute(execution_probe as *const () as usize as u64),
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
        return vmsa_test_harness::HarnessError::InvalidState.into();
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
        .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(ADDRESS)?;
    translation.map_hardware_managed::<aarch64_vmsa::address::Granule4KiB>(
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
        .inspect_hardware_updates::<aarch64_vmsa::address::Granule4KiB>(ADDRESS)?
        .access_flag
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn current_fault<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    current_fault_expected(context, ExpectedFault::translation_read_stage1())
}

pub fn current_fault_expected<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
    expected: ExpectedFault,
) -> TestResult {
    expect_fault(context.read_u64(invalid_virtual_address(context)), expected)
}

pub fn lower_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = match context.allocate_page() {
        Ok(page) => page,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let address = page.virtual_address() as u64;
    let injected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::LowerElEntry,
        0,
        || context.lower_read_u64(address),
    );
    if injected
        != vmsa_test_harness::AccessResult::HarnessFailure(
            vmsa_test_harness::HarnessError::InjectedFailure,
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El1)?;
    let write = execution.write_u64(address, 0x4c4f_5745_522d_454c);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x4c4f_5745_522d_454c);
    execution.finish()?;
    result
}

pub fn el0_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl1)?;
    let write = execution.write_u64(address, 0x454c_302d_564d_5341);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x454c_302d_564d_5341);
    execution.finish()?;
    result
}

pub fn el2_el0_access<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    let write = execution.write_u64(address, 0x454c_3226_302d_564d);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let result = expect_value(execution.read_u64(address), 0x454c_3226_302d_564d);
    execution.finish()?;
    result
}

pub fn lower_fault<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> TestResult {
    lower_fault_expected(context, ExpectedFault::address_size_read_stage1())
}

pub fn lower_fault_expected<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
    expected: ExpectedFault,
) -> TestResult {
    expect_fault(
        context.lower_read_u64(invalid_virtual_address(context)),
        expected,
    )
}

fn invalid_virtual_address<E: vmsa_test_harness::adapter::Environment>(
    context: &TestContext<'_, E>,
) -> u64 {
    1u64 << context.capabilities().va_bits.min(47)
}

pub fn mapper_lpa2<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::descriptor::Vmsa64Lpa2: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    <aarch64_vmsa::descriptor::Vmsa64Lpa2 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::regime::StageOf<E::Regime>,
        aarch64_vmsa::address::Granule4KiB,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
            LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                E::Regime,
                aarch64_vmsa::address::Granule4KiB,
            >,
            TableFields = aarch64_vmsa::regime::TableFieldsOf<
                aarch64_vmsa::descriptor::Vmsa64,
                E::Regime,
                aarch64_vmsa::address::Granule4KiB,
            >,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let Some(start_level) = LookupLevel::new(-1) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(address_bits) = AddressBits::new(52) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let mut mapper =
        context.offline_mapper_lpa2_4k(&mut root, start_level, address_bits, address_bits)?;
    mapper.map_page(
        page.virtual_address() as u64,
        page.phys_addr(),
        MappingAttributes::READ_WRITE,
    )?;
    TestResult::Pass
}

pub fn mapper_d128<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::regime::StageOf<E::Regime>,
        aarch64_vmsa::address::Granule4KiB,
    >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
        >,
{
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let Some(start_level) = LookupLevel::new(-2) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(address_bits) = AddressBits::new(52) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let mut mapper =
        context.offline_mapper_d128_4k(&mut root, start_level, address_bits, address_bits)?;
    mapper.map_page(page.virtual_address() as u64, page.phys_addr())?;
    TestResult::Pass
}

pub fn mapper_16k<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule16KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule16KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule16KiB,
    >: Copy,
{
    let mut root = context.allocate_root_16k()?;
    let output = context.allocate_root_16k()?;
    let mut mapper = context.offline_mapper_16k(&mut root)?;
    const ADDRESS: u64 = 0x4000_0000;
    mapper.map_attributes_leaf(
        ADDRESS,
        output.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(ADDRESS)?;
    let leaf = walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() < 2
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.output != Some(output.phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn mapper_64k<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule64KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule64KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule64KiB,
    >: Copy,
{
    let mut root = context.allocate_root_64k()?;
    let output = context.allocate_root_64k()?;
    let mut mapper = context.offline_mapper_64k(&mut root)?;
    const ADDRESS: u64 = 0x8000_0000;
    mapper.map_attributes_leaf(
        ADDRESS,
        output.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let walk = mapper.inspect_walk(ADDRESS)?;
    let leaf = walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if walk.steps().len() < 2
        || leaf.kind != vmsa_test_harness::WalkDescriptorKind::Page
        || leaf.level != LookupLevel::new(3).expect("level 3 is valid")
        || leaf.output != Some(output.phys_addr())
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn stage1_translation_cycle<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const LIVE_ADDRESS: u64 = 0x6000_0000;
    const LIVE_VALUE: u64 = 0x4c49_5645_4d41_5050;
    const RANGE_ADDRESS: u64 = 0x6200_0000;
    const BLOCK_ADDRESS: u64 = 0x7000_0000;
    const BLOCK_OUTPUT: u64 = 0x8000_0000;
    const BLOCK_OFFSET: u64 = 0x1234;

    let page = context.allocate_page()?;
    let range = context.allocate_contiguous(2)?;
    let root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let Some(input_bits) = AddressBits::new(capabilities.va_bits.min(48)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(output_bits) = AddressBits::new(capabilities.pa_bits.min(48)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
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
    let injected_map =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Map, 0, || {
            translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                LIVE_ADDRESS,
                page.phys_addr(),
                LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                MappingAttributes::READ_WRITE,
            )
        });
    if injected_map != Err(vmsa_test_harness::HarnessError::InjectedFailure)
        || translation
            .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                LIVE_ADDRESS,
            )?
            .is_some()
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        LIVE_ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let mapping = translation
        .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if mapping.output != page.phys_addr()
        || mapping.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        BLOCK_ADDRESS,
        BLOCK_OUTPUT,
        LookupLevel::new(2).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        MappingAttributes::READ_WRITE,
    )?;
    let block_walk = translation
        .inspect_walk::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            BLOCK_ADDRESS + BLOCK_OFFSET,
        )?;
    let block_leaf = block_walk
        .leaf()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if block_leaf.kind != vmsa_test_harness::WalkDescriptorKind::Block
        || block_leaf.level != LookupLevel::new(2).expect("level 2 is valid")
        || block_leaf.output != Some(BLOCK_OUTPUT + BLOCK_OFFSET)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    match context.translate_current_stage1(
        BLOCK_ADDRESS + BLOCK_OFFSET,
        vmsa_test_harness::TranslationQueryAccess::Read,
    ) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == BLOCK_OUTPUT + BLOCK_OFFSET => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    let removed_block = translation
        .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            BLOCK_ADDRESS,
        )?;
    if removed_block.output != BLOCK_OUTPUT
        || removed_block.level != LookupLevel::new(2).expect("level 2 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let range_outcome = translation
        .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            RANGE_ADDRESS,
            range.phys_addr(),
            8192,
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    if range_outcome.mappings_created != 2 || range_outcome.bytes_mapped != 8192 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if translation.tlbi(vmsa_test_harness::TlbiOperation::Address(LIVE_ADDRESS + 1))
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.tlbi_scoped(
        vmsa_test_harness::TlbiScope::Local,
        vmsa_test_harness::TlbiOperation::VirtualAddress(LIVE_ADDRESS),
    )?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(
        LIVE_ADDRESS,
    ))?;
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualRange {
        start: RANGE_ADDRESS,
        pages: 2,
    })?;
    if translation.tlbi(vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(LIVE_ADDRESS))
        != Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.tlbi(vmsa_test_harness::TlbiOperation::All)?;
    let write = context.write_u64(LIVE_ADDRESS, LIVE_VALUE);
    if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(write);
    }
    let value_result = expect_value(context.read_u64(LIVE_ADDRESS), LIVE_VALUE);
    if !matches!(value_result, TestResult::Pass) {
        return value_result;
    }
    for (offset, value) in [(0, LIVE_VALUE + 3), (4096, LIVE_VALUE + 4)] {
        let write = context.write_u64(RANGE_ADDRESS + offset, value);
        if !matches!(write, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(write);
        }
        let read = expect_value(context.read_u64(RANGE_ADDRESS + offset), value);
        if !matches!(read, TestResult::Pass) {
            return read;
        }
    }
    for address in [RANGE_ADDRESS, RANGE_ADDRESS + 4096] {
        translation
            .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                address,
            )?;
    }
    for address in [RANGE_ADDRESS, RANGE_ADDRESS + 4096] {
        let result = expect_fault(
            context.read_u64(address),
            ExpectedFault::translation_read_stage1(),
        );
        if !matches!(result, TestResult::Pass) {
            return result;
        }
    }
    let injected_remap =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Remap, 0, || {
            translation
                .remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    LIVE_ADDRESS,
                    page.phys_addr(),
                    MappingAttributes::READ_WRITE,
                )
        });
    if injected_remap != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let injected_remap_preserved = expect_value(context.read_u64(LIVE_ADDRESS), LIVE_VALUE);
    if !matches!(injected_remap_preserved, TestResult::Pass) {
        return injected_remap_preserved;
    }
    let rejected_remap = translation
        .remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
            page.phys_addr() + 1,
            MappingAttributes::READ_WRITE,
        );
    if rejected_remap != Err(vmsa_test_harness::HarnessError::InvalidState) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = expect_value(context.read_u64(LIVE_ADDRESS), LIVE_VALUE);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    let injected_protect =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Protect, 0, || {
            translation
                .protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    LIVE_ADDRESS,
                    MappingAttributes::READ_ONLY,
                )
        });
    if injected_protect != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if !matches!(
        context.write_u64(LIVE_ADDRESS, LIVE_VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let protected = translation
        .protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
            MappingAttributes::READ_ONLY,
        )?;
    if protected.output != page.phys_addr()
        || protected.level != LookupLevel::new(3).expect("level 3 is valid")
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let read_only = expect_fault(
        context.write_u64(LIVE_ADDRESS, LIVE_VALUE.wrapping_add(1)),
        ExpectedFault::permission_write(),
    );
    if !matches!(read_only, TestResult::Pass) {
        return read_only;
    }
    translation.protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        LIVE_ADDRESS,
        MappingAttributes::READ_WRITE,
    )?;
    let remap_value = LIVE_VALUE.wrapping_add(2);
    let remapped_write = context.write_u64(LIVE_ADDRESS, remap_value);
    if !matches!(
        remapped_write,
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::expect_completed(remapped_write);
    }
    let remapped_read = expect_value(context.read_u64(LIVE_ADDRESS), remap_value);
    if !matches!(remapped_read, TestResult::Pass) {
        return remapped_read;
    }
    let injected_unmap =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Unmap, 0, || {
            translation.unmap_reclaim::<
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(LIVE_ADDRESS)
        });
    if injected_unmap != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let injected_unmap_preserved = expect_value(context.read_u64(LIVE_ADDRESS), remap_value);
    if !matches!(injected_unmap_preserved, TestResult::Pass) {
        return injected_unmap_preserved;
    }
    let reclaimed = translation
        .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            LIVE_ADDRESS,
        )?;
    if reclaimed.tables_freed == 0 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let final_fault = expect_fault(
        context.read_u64(LIVE_ADDRESS),
        ExpectedFault::translation_read_stage1(),
    );
    if !matches!(final_fault, TestResult::Pass) {
        return final_fault;
    }
    vmsa_test_harness::adapter::force_runner_emergency_restoration(translation);
    TestResult::Pass
}

pub fn lower_stage1_asid_isolation<E, R>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
    R: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        R,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    const ADDRESS: u64 = 0x6600_0000;
    let first_page = context.allocate_page()?;
    let second_page = context.allocate_page()?;
    let first_root = context.allocate_root()?;
    let second_root = context.allocate_root()?;
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let cacheability = aarch64_vmsa::attrs::Cacheability::Cacheable {
        policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
        transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
        allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
    };
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT
        .with_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::attrs::MemoryAttributes::Normal {
                inner: cacheability,
                outer: cacheability,
            },
        )
        .map_err(vmsa_test_harness::HarnessError::Attribute)?;
    let mut first_effective_setup = None;
    let mut roots = [Some(first_root), Some(second_root)];
    for (index, page, asid) in [(0, first_page, Asid(11)), (1, second_page, Asid(12))] {
        let root = roots[index]
            .take()
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        let setup = TranslationSetup {
            root: PhysicalAddress::new(root.phys_addr()),
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(0),
            asid: Some(asid),
            vmid: None,
            controls,
            stage1_memory,
            regime,
        };
        let mut translation = context.install_lower_owned(root, setup)?;
        translation
            .map_for::<R, aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
                page.phys_addr(),
                LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                MappingAttributes {
                    writable: true,
                    executable: false,
                    user_accessible: true,
                },
            )?;
        if index == 0 {
            if !matches!(
                context.write_u64(page.virtual_address() as u64, 7),
                vmsa_test_harness::AccessResult::Completed { .. }
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            for execution_context in [
                vmsa_test_harness::ExecutionContext::El1,
                vmsa_test_harness::ExecutionContext::El0UnderEl1,
            ] {
                let mut execution = context.execution(execution_context)?;
                let atomic = execution.atomic_swap_u64(ADDRESS, 11);
                if !matches!(
                    atomic,
                    vmsa_test_harness::AccessResult::Completed { value: 7 }
                ) || !matches!(
                    execution.exclusive_add_u64(ADDRESS, 5),
                    vmsa_test_harness::AccessResult::Completed { value: 11 }
                ) {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
                execution.finish()?;
                if !matches!(
                    context.write_u64(page.virtual_address() as u64, 7),
                    vmsa_test_harness::AccessResult::Completed { .. }
                ) {
                    return vmsa_test_harness::HarnessError::InvalidState.into();
                }
            }
        }
        if asid == Asid(11) {
            first_effective_setup = Some(translation.setup());
        }
        translation.tlbi(vmsa_test_harness::TlbiOperation::Asid(asid))?;
        translation.tlbi_scoped(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::TlbiOperation::Asid(asid),
        )?;
        if translation.tlbi(vmsa_test_harness::TlbiOperation::Asid(Asid(asid.0 + 1)))
            != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        match context
            .translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read)
        {
            vmsa_test_harness::TranslationQueryResult::Success {
                physical_address, ..
            } if physical_address == page.phys_addr() => {}
            _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
        }
        roots[index] = Some(translation.restore_owned()?);
    }
    let setup = first_effective_setup.ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let first_root = roots[0]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let second_root = roots[1]
        .take()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut translation = context.install_lower_owned(first_root, setup)?;
    let first_root = translation.initial_root()?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == first_page.phys_addr() => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    translation.adopt_and_switch_lower_stage1_root(second_root, Asid(12))?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == second_page.phys_addr() => {}
        _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
    }
    translation.switch_lower_stage1_root(first_root, Asid(11))?;
    match context.translate_lower_stage1(ADDRESS, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == first_page.phys_addr() => TestResult::Pass,
        _ => vmsa_test_harness::HarnessError::InvalidState.into(),
    }
}

pub fn stage2_translation_cycle<E: vmsa_test_harness::adapter::TranslationRegimeEnvironment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult
where
    E::Regime: vmsa_test_harness::adapter::TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
    aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            aarch64_vmsa::address::Granule4KiB,
        >,
    aarch64_vmsa::regime::LeafFieldsOf<
        aarch64_vmsa::descriptor::Vmsa64,
        E::Regime,
        aarch64_vmsa::address::Granule4KiB,
    >: Copy,
{
    let page = match context.allocate_page() {
        Ok(page) => page,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let mut root = match context.allocate_root() {
        Ok(root) => root,
        Err(error) => return TestResult::Fail(error.into()),
    };
    let Some(input_bits) = AddressBits::new(context.capabilities().pa_bits.min(39)) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(output_bits) = AddressBits::new(context.capabilities().pa_bits) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let Some(start_level) = LookupLevel::new(1) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    {
        let mut mapper = match context.offline_mapper_with_geometry(
            &mut root,
            start_level,
            input_bits,
            output_bits,
        ) {
            Ok(mapper) => mapper,
            Err(error) => return TestResult::Fail(error.into()),
        };
        if let Err(error) =
            mapper.map_block(0x4000_0000, page.phys_addr(), MappingAttributes::READ_WRITE)
        {
            return TestResult::Fail(error.into());
        }
    }
    let Some(controls) = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level) else {
        return TestResult::Fail(vmsa_test_harness::HarnessError::InvalidState.into());
    };
    let setup = TranslationSetup {
        root: PhysicalAddress::new(root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: Some(start_level),
        asid: None,
        vmid: Some(Vmid(1)),
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime,
    };
    match context.install_owned(root, setup) {
        Ok(translation) => {
            drop(translation);
            TestResult::Pass
        }
        Err(error) => TestResult::Fail(error.into()),
    }
}

pub fn stage2_vmid_isolation<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
    regime: RegimeAttributes,
) -> TestResult {
    let Some(input_bits) = AddressBits::new(39) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let output_width = match context.capabilities().pa_bits {
        0..=32 => 32,
        33..=36 => 36,
        37..=40 => 40,
        41..=42 => 42,
        43..=44 => 44,
        45..=48 => 48,
        _ => 52,
    };
    let Some(output_bits) = AddressBits::new(output_width) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let Some(start_level) = LookupLevel::new(1) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    let Some(controls) = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level) else {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    };
    for vmid in [Vmid(0x15), Vmid(0x2a)] {
        let root = context.allocate_root()?;
        let root_address = PhysicalAddress::new(root.phys_addr());
        let mut translation = context.install_owned(
            root,
            TranslationSetup {
                root: root_address,
                stage: TranslationStage::Stage2,
                granule: Granule::Size4KiB,
                format: vmsa_test_harness::TranslationFormat::Vmsa64,
                input_bits,
                output_bits,
                start_level: Some(start_level),
                asid: None,
                vmid: Some(vmid),
                controls,
                stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
                regime,
            },
        )?;
        if translation.setup().vmid != Some(vmid) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        translation
            .tlbi(vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(0x4000_0000))?;
        translation.tlbi_scoped(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::TlbiOperation::Vmid(vmid),
        )?;
        translation.tlbi(vmsa_test_harness::TlbiOperation::Vmid(vmid))?;
        if translation.tlbi(vmsa_test_harness::TlbiOperation::Vmid(Vmid(vmid.0 + 1)))
            != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        drop(translation);
    }
    TestResult::Pass
}
