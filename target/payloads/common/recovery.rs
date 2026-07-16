use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    if context.verify_arena_exhaustion_boundary() {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::InvalidState.into()
    }
}

pub(super) fn page_allocation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let rejected =
        context.with_memory_failure(vmsa_test_harness::MemoryFailurePoint::Page, 0, || {
            context.allocate_page()
        })?;
    if rejected != Err(vmsa_test_harness::HarnessError::Memory) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.allocate_page()?;
    fresh_access_sentinel(context)
}

pub(super) fn contiguous_allocation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let rejected = context.with_memory_failure(
        vmsa_test_harness::MemoryFailurePoint::Contiguous,
        0,
        || context.allocate_contiguous(2),
    )?;
    if rejected != Err(vmsa_test_harness::HarnessError::Memory) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.allocate_contiguous(2)?;
    fresh_access_sentinel(context)
}

pub(super) fn root_allocation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let rejected =
        context.with_memory_failure(vmsa_test_harness::MemoryFailurePoint::Root, 0, || {
            context.allocate_root()
        })?;
    if rejected != Err(vmsa_test_harness::HarnessError::Memory) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.allocate_root()?;
    fresh_access_sentinel(context)
}

fn table_allocation_failure_at(
    context: &mut TestContext<'_, CurrentEnvironment>,
    successful_allocations: usize,
) -> TestResult {
    const ADDRESS: u64 = 0x6800_0000;
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let baseline_allocations = context.arena_allocation_count();
    let rejected = context.with_table_allocation_failure(successful_allocations, || {
        let mut mapper = context.offline_mapper(&mut root)?;
        mapper.map_leaf(
            ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            vmsa_test_harness::MappingAttributes::READ_WRITE,
        )
    })?;
    if rejected != Err(vmsa_test_harness::HarnessError::InvalidState) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    if context.arena_allocation_count() != baseline_allocations + successful_allocations {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let mut mapper = context.offline_mapper(&mut root)?;
    if mapper.translate(ADDRESS)?.is_some() {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    mapper.map_leaf(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    if mapper.translate(ADDRESS)?.map(|mapping| mapping.output) != Some(page.phys_addr())
        || context.arena_allocation_count() != baseline_allocations + 3
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let reclaimed = mapper
        .unmap_reclaim_exact(ADDRESS)
        .map_err(|_| vmsa_test_harness::HarnessError::InvalidState)?;
    if reclaimed.mapping.output != page.phys_addr()
        || reclaimed.tables_freed != 3
        || !reclaimed.root_now_empty
        || context.arena_allocation_count() != baseline_allocations
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    fresh_access_sentinel(context)
}

pub(super) fn table_allocation_failure_0(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    table_allocation_failure_at(context, 0)
}

pub(super) fn table_allocation_failure_1(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    table_allocation_failure_at(context, 1)
}

pub(super) fn table_allocation_failure_2(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    table_allocation_failure_at(context, 2)
}

fn normal_setup(
    context: &TestContext<'_, CurrentEnvironment>,
    root: u64,
) -> Result<vmsa_test_harness::TranslationSetup, vmsa_test_harness::HarnessError> {
    let capabilities = context.capabilities();
    Ok(vmsa_test_harness::TranslationSetup {
        root: vmsa_test_harness::PhysicalAddress::new(root),
        stage: vmsa_test_harness::TranslationStage::Stage1,
        granule: vmsa_test_harness::Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits: vmsa_test_harness::AddressBits::new(capabilities.va_bits.min(48))
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        output_bits: vmsa_test_harness::AddressBits::new(capabilities.pa_bits.min(48))
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        start_level: vmsa_test_harness::LookupLevel::new(0),
        asid: None,
        vmid: None,
        controls: vmsa_test_harness::TranslationControls::PRESERVE_CURRENT,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    })
}

fn lower_setup(
    context: &TestContext<'_, CurrentEnvironment>,
    root: u64,
) -> Result<vmsa_test_harness::TranslationSetup, vmsa_test_harness::HarnessError> {
    let capabilities = context.capabilities();
    let input_bits = vmsa_test_harness::AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = vmsa_test_harness::AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    Ok(vmsa_test_harness::TranslationSetup {
        root: vmsa_test_harness::PhysicalAddress::new(root),
        stage: vmsa_test_harness::TranslationStage::Stage1,
        granule: vmsa_test_harness::Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: vmsa_test_harness::LookupLevel::new(0),
        asid: Some(vmsa_test_harness::Asid(0x51)),
        vmid: None,
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    })
}

fn stage2_translation_setup(
    context: &TestContext<'_, CurrentEnvironment>,
    root: u64,
) -> Result<vmsa_test_harness::TranslationSetup, vmsa_test_harness::HarnessError> {
    let input_bits = vmsa_test_harness::AddressBits::new(39)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = vmsa_test_harness::AddressBits::new(context.capabilities().pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = vmsa_test_harness::LookupLevel::new(1)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls =
        vmsa_test_harness::vmsa64_stage2_controls_4k(input_bits, output_bits, start_level)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    Ok(vmsa_test_harness::TranslationSetup {
        root: vmsa_test_harness::PhysicalAddress::new(root),
        stage: vmsa_test_harness::TranslationStage::Stage2,
        granule: vmsa_test_harness::Granule::Size4KiB,
        format: vmsa_test_harness::TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: Some(start_level),
        asid: None,
        vmid: Some(vmsa_test_harness::Vmid(0x52)),
        controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: vmsa_test_harness::RegimeAttributes::Normal,
    })
}

fn fresh_access_sentinel(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    const ADDRESS: u64 = 0x6560_0000;
    const VALUE: u64 = 0x5245_434f_5645_5259;
    let page = context.allocate_page()?;
    let write = vmsa_test_harness::expect_completed(
        context.write_u64(page.virtual_address() as u64, VALUE),
    );
    if !matches!(write, TestResult::Pass) {
        return write;
    }
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let read = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    translation.restore()?;
    read
}

pub(super) fn current_installation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::TranslationInstallation,
        0,
        || context.install_owned(root, setup),
    );
    let rejected_as_expected = matches!(
        rejected,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    );
    drop(rejected);
    if !rejected_as_expected {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let retry_root = context.allocate_root()?;
    let retry_setup = normal_setup(context, retry_root.phys_addr())?;
    context.install_owned(retry_root, retry_setup)?.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn lower_installation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    let setup = lower_setup(context, root.phys_addr())?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::TranslationInstallation,
        0,
        || context.install_lower_owned(root, setup),
    );
    let rejected_as_expected = matches!(
        rejected,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    );
    drop(rejected);
    if !rejected_as_expected {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let retry_root = context.allocate_root()?;
    let retry_setup = lower_setup(context, retry_root.phys_addr())?;
    context
        .install_lower_owned(retry_root, retry_setup)?
        .restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn partial_combined_installation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let stage1_root = context.allocate_root()?;
    let stage1_setup = lower_setup(context, stage1_root.phys_addr())?;
    let stage2_root = context.allocate_root()?;
    let stage2_setup = stage2_translation_setup(context, stage2_root.phys_addr())?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::PartialCombinedInstallation,
        0,
        || context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup),
    );
    let rejected_as_expected = matches!(
        rejected,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    );
    drop(rejected);
    if !rejected_as_expected {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let retry_stage1_root = context.allocate_root()?;
    let retry_stage1_setup = lower_setup(context, retry_stage1_root.phys_addr())?;
    let retry_stage2_root = context.allocate_root()?;
    let retry_stage2_setup = stage2_translation_setup(context, retry_stage2_root.phys_addr())?;
    context
        .install_combined_owned(
            retry_stage1_root,
            retry_stage1_setup,
            retry_stage2_root,
            retry_stage2_setup,
        )?
        .restore()?;
    fresh_access_sentinel(context)
}

fn lower_phase_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
    point: vmsa_test_harness::HarnessFailurePoint,
) -> TestResult {
    const VALUE: u64 = 0x4c4f_5745_525f_4f4b;
    let page = context.allocate_page()?;
    let address = page.virtual_address() as u64;
    let written = vmsa_test_harness::expect_completed(context.write_u64(address, VALUE));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    let rejected = context.with_harness_failure(point, 0, || context.lower_read_u64(address));
    if rejected
        != vmsa_test_harness::AccessResult::HarnessFailure(
            vmsa_test_harness::HarnessError::InjectedFailure,
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let retry = vmsa_test_harness::expect_value(context.lower_read_u64(address), VALUE);
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    fresh_access_sentinel(context)
}

pub(super) fn lower_entry_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    lower_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::LowerElEntry,
    )
}

pub(super) fn lower_action_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    lower_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::LowerElAction,
    )
}

pub(super) fn lower_return_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    lower_phase_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::LowerElReturn,
    )
}

fn secondary_session_creation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
    point: vmsa_test_harness::HarnessFailurePoint,
) -> TestResult {
    let rejected = context.with_harness_failure(point, 0, || context.secondary_pe_session());
    let rejected_as_expected = matches!(
        rejected,
        Err(vmsa_test_harness::HarnessError::InjectedFailure)
    );
    drop(rejected);
    if !rejected_as_expected {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.secondary_pe_session()?.stop()?;
    fresh_access_sentinel(context)
}

pub(super) fn secondary_start_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    secondary_session_creation_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeStartup,
    )
}

pub(super) fn secondary_rendezvous_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    secondary_session_creation_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeRendezvous,
    )
}

fn secondary_access_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
    point: vmsa_test_harness::HarnessFailurePoint,
) -> TestResult {
    const ADDRESS: u64 = 0x6570_0000;
    const VALUE: u64 = 0x5345_434f_4e44_4152;
    let page = context.allocate_page()?;
    let backing = page.virtual_address() as u64;
    let written = vmsa_test_harness::expect_completed(context.write_u64(backing, VALUE));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
        address: backing,
        bytes: core::mem::size_of::<u64>(),
    })?;
    context
        .maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::TranslationTableVisibility)?;
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::MultiPeVisibility)?;
    let mut session = context.secondary_pe_session()?;
    let rejected = context.with_harness_failure(point, 0, || session.read_u64(ADDRESS));
    if rejected
        != vmsa_test_harness::AccessResult::HarnessFailure(
            vmsa_test_harness::HarnessError::InjectedFailure,
        )
        || session.state() != vmsa_test_harness::SecondaryPeSessionState::Rendezvous
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let retry = vmsa_test_harness::expect_value(session.read_u64(ADDRESS), VALUE);
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    session.stop()?;
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn secondary_action_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    secondary_access_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeAction,
    )
}

pub(super) fn secondary_timeout_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    secondary_access_failure(
        context,
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeTimeout,
    )
}

pub(super) fn secondary_stop_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let session = context.secondary_pe_session()?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::SecondaryPeStop,
        0,
        || session.stop(),
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.secondary_pe_session()?.stop()?;
    fresh_access_sentinel(context)
}

pub(super) fn invalidation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const ADDRESS: u64 = 0x6580_0000;
    const OLD: u64 = 0x494e_5641_4c49_4430;
    const NEW: u64 = 0x494e_5641_4c49_4431;
    let old_page = context.allocate_page()?;
    let new_page = context.allocate_page()?;
    vmsa_test_harness::expect_completed(context.write_u64(old_page.virtual_address() as u64, OLD));
    vmsa_test_harness::expect_completed(context.write_u64(new_page.virtual_address() as u64, NEW));
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        old_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::Invalidation,
        0,
        || {
            translation
                .remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    new_page.phys_addr(),
                    vmsa_test_harness::MappingAttributes::READ_WRITE,
                )
        },
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), OLD);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    translation.remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        new_page.phys_addr(),
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let retry = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), NEW);
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn barrier_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let page = context.allocate_page()?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Barrier, 0, || {
            context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
                address: page.virtual_address() as u64,
                bytes: core::mem::size_of::<u64>(),
            })
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
        address: page.virtual_address() as u64,
        bytes: core::mem::size_of::<u64>(),
    })?;
    fresh_access_sentinel(context)
}

pub(super) fn tlbi_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    const ADDRESS: u64 = 0x6590_0000;
    const VALUE: u64 = 0x544c_4249_5f4f_4b21;
    let page = context.allocate_page()?;
    vmsa_test_harness::expect_completed(context.write_u64(page.virtual_address() as u64, VALUE));
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Tlbi, 0, || {
            translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(ADDRESS))
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    translation.tlbi(vmsa_test_harness::TlbiOperation::VirtualAddress(ADDRESS))?;
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn explicit_restore_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let translation = context.install_owned(root, setup)?;
    let rejected = context.with_harness_failure(
        vmsa_test_harness::HarnessFailurePoint::TranslationRestoration,
        0,
        || translation.restore(),
    );
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    fresh_access_sentinel(context)
}

pub(super) fn drop_restore(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let translation = context.install_owned(root, setup)?;
    drop(translation);
    fresh_access_sentinel(context)
}

pub(super) fn emergency_restore(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let translation = context.install_owned(root, setup)?;
    vmsa_test_harness::adapter::force_runner_emergency_restoration(translation);
    context.emergency_restore_for_test();
    fresh_access_sentinel(context)
}

pub(super) fn mapper_map_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    const ADDRESS: u64 = 0x6500_0000;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Map, 0, || {
            translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
                page.phys_addr(),
                vmsa_test_harness::LookupLevel::new(3)
                    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                vmsa_test_harness::MappingAttributes::READ_WRITE,
            )
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure)
        || translation
            .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
            )?
            .is_some()
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let retry =
        vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, 0x4d41_505f_5245_5452));
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn mapper_range_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const ADDRESS: u64 = 0x6510_0000;
    let pages = context.allocate_contiguous(2)?;
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Map, 0, || {
            translation
                .map_range::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    pages.phys_addr(),
                    8192,
                    vmsa_test_harness::LookupLevel::new(3)
                        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                    vmsa_test_harness::MappingAttributes::READ_WRITE,
                )
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    for address in [ADDRESS, ADDRESS + 4096] {
        if translation
            .inspect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                address,
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
            8192,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            vmsa_test_harness::MappingAttributes::READ_WRITE,
        )?;
    if outcome.mappings_created != 2 || outcome.bytes_mapped != 8192 {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn mapper_remap_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const ADDRESS: u64 = 0x6520_0000;
    const OLD: u64 = 0x4f4c_445f_4d41_5050;
    const NEW: u64 = 0x4e45_575f_4d41_5050;
    let first = context.allocate_page()?;
    let second = context.allocate_page()?;
    vmsa_test_harness::expect_completed(context.write_u64(first.virtual_address() as u64, OLD));
    vmsa_test_harness::expect_completed(context.write_u64(second.virtual_address() as u64, NEW));
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        first.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let rejected_replacement = translation
        .break_before_make::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
            Some(second.phys_addr() + 1),
            vmsa_test_harness::MappingAttributes::READ_WRITE,
        );
    if rejected_replacement != Err(vmsa_test_harness::HarnessError::InvalidState) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let rollback = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), OLD);
    if !matches!(rollback, TestResult::Pass) {
        return rollback;
    }
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Remap, 0, || {
            translation
                .remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    second.phys_addr(),
                    vmsa_test_harness::MappingAttributes::READ_WRITE,
                )
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), OLD);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    translation.remap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        second.phys_addr(),
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let retry = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), NEW);
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn mapper_protect_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const ADDRESS: u64 = 0x6530_0000;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Protect, 0, || {
            translation
                .protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                    ADDRESS,
                    vmsa_test_harness::MappingAttributes::READ_ONLY,
                )
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure)
        || !matches!(
            context.write_u64(ADDRESS, 1),
            vmsa_test_harness::AccessResult::Completed { .. }
        )
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    translation.protect::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        vmsa_test_harness::MappingAttributes::READ_ONLY,
    )?;
    let retry = vmsa_test_harness::expect_fault(
        context.write_u64(ADDRESS, 2),
        vmsa_test_harness::ExpectedFault::permission_write(),
    );
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

fn mapper_unmap_failure_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    reclaim: bool,
) -> TestResult {
    const ADDRESS: u64 = 0x6540_0000;
    const VALUE: u64 = 0x554e_4d41_505f_4f4b;
    let page = context.allocate_page()?;
    let root = context.allocate_root()?;
    let setup = normal_setup(context, root.phys_addr())?;
    let mut translation = context.install_owned(root, setup)?;
    translation.map::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        vmsa_test_harness::MappingAttributes::READ_WRITE,
    )?;
    let written = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, VALUE));
    if !matches!(written, TestResult::Pass) {
        return written;
    }
    let rejected =
        context.with_harness_failure(vmsa_test_harness::HarnessFailurePoint::Unmap, 0, || {
            if reclaim {
                translation.unmap_reclaim::<
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                >(ADDRESS)
            } else {
                translation
                    .unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                        ADDRESS,
                    )
                    .map(|mapping| vmsa_test_harness::UnmapResult {
                        mapping,
                        tables_freed: 0,
                        root_now_empty: false,
                    })
            }
        });
    if rejected != Err(vmsa_test_harness::HarnessError::InjectedFailure) {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    let preserved = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    if !matches!(preserved, TestResult::Pass) {
        return preserved;
    }
    if reclaim {
        let result = translation
            .unmap_reclaim::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
                ADDRESS,
            )?;
        if result.tables_freed == 0 {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    } else {
        translation.unmap::<aarch64_vmsa::descriptor::Vmsa64, aarch64_vmsa::address::Granule4KiB>(
            ADDRESS,
        )?;
    }
    let retry = vmsa_test_harness::expect_fault(
        context.read_u64(ADDRESS),
        vmsa_test_harness::ExpectedFault::translation_read_stage1(),
    );
    if !matches!(retry, TestResult::Pass) {
        return retry;
    }
    translation.restore()?;
    fresh_access_sentinel(context)
}

pub(super) fn mapper_unmap_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    mapper_unmap_failure_case(context, false)
}

pub(super) fn mapper_reclaim_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    mapper_unmap_failure_case(context, true)
}
