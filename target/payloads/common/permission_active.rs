use crate::{CurrentEnvironment, CurrentRegime};
use vmsa_test_harness::{TestContext, TestResult};

#[derive(Clone, Copy)]
enum Observation {
    Read,
    Write,
    Execute,
}

fn single_privilege_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    writable: bool,
    executable: bool,
    observation: Observation,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissionLimits, SoftwareMetadata,
        Stage2MemoryMode,
    };
    use vmsa_test_harness::{
        AccessKind, AddressBits, ExpectedFault, FaultClass, FaultMatcher, FaultStage, FaultStatus,
        Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    const ADDRESS: u64 = 0x6c00_0000;
    const DATA_OFFSET: u64 = 16;
    const INITIAL_VALUE: u64 = 0x5045_524d_4953_534e;
    const WRITTEN_VALUE: u64 = INITIAL_VALUE ^ u64::MAX;

    let page = context.allocate_page()?;
    let backing = page.virtual_address() as u64;
    for (offset, instruction) in [(0, 0xd280_0020), (4, 0xd65f_03c0)] {
        let result = context.write_u32(backing + offset, instruction);
        if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(result);
        }
    }
    let result = context.write_u64(backing + DATA_OFFSET, INITIAL_VALUE);
    if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(result);
    }

    let config = LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let permissions = SinglePrivilegeLeafPermissions {
        data: if writable {
            DataAccess::ReadWrite
        } else {
            DataAccess::ReadOnly
        },
        execute: executable,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions,
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut live = context.install_owned(
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
            controls: vmsa_test_harness::TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    live.map_semantic_for::<
        CurrentRegime,
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule4KiB,
        _,
    >(
        &config,
        ADDRESS,
        page.phys_addr(),
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let decoded = live
        .inspect_semantic_for::<
            CurrentRegime,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if decoded != leaf {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let result = match observation {
        Observation::Read => {
            vmsa_test_harness::expect_value(context.read_u64(ADDRESS + DATA_OFFSET), INITIAL_VALUE)
        }
        Observation::Write if writable => vmsa_test_harness::expect_completed(
            context.write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE),
        ),
        Observation::Write => vmsa_test_harness::expect_matching_fault(
            context.write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE),
            FaultMatcher::new(ExpectedFault {
                status: Some(FaultStatus::Permission),
                access: Some(AccessKind::Write),
                stage: Some(FaultStage::Stage1),
                level: None,
            })
            .with_class(FaultClass::DataAbort)
            .at_address(ADDRESS + DATA_OFFSET),
        ),
        Observation::Execute => {
            context.maintain_cache(
                vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
                    address: ADDRESS,
                    bytes: 8,
                },
            )?;
            // Current EL2 runs with SCTLR_EL2.WXN set, so a writable mapping
            // is execute-never even when the leaf enables execution.
            if executable && !writable {
                vmsa_test_harness::expect_value(context.execute(ADDRESS), 1)
            } else {
                vmsa_test_harness::expect_matching_fault(
                    context.execute(ADDRESS),
                    FaultMatcher::new(ExpectedFault {
                        status: Some(FaultStatus::Permission),
                        access: Some(AccessKind::Execute),
                        stage: Some(FaultStage::Stage1),
                        level: None,
                    })
                    .with_class(FaultClass::InstructionAbort)
                    .at_address(ADDRESS),
                )
            }
        }
    };
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    live.restore()?;
    TestResult::Pass
}

macro_rules! single_case {
    ($name:ident, $writable:literal, $executable:literal, $observation:ident) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            single_privilege_case(context, $writable, $executable, Observation::$observation)
        }
    };
}

single_case!(rw_x_read, true, true, Read);
single_case!(rw_x_write, true, true, Write);
single_case!(rw_x_execute, true, true, Execute);
single_case!(rw_xn_read, true, false, Read);
single_case!(rw_xn_write, true, false, Write);
single_case!(rw_xn_execute, true, false, Execute);
single_case!(ro_x_read, false, true, Read);
single_case!(ro_x_write, false, true, Write);
single_case!(ro_x_execute, false, true, Execute);
single_case!(ro_xn_read, false, false, Read);
single_case!(ro_xn_write, false, false, Write);
single_case!(ro_xn_execute, false, false, Execute);

#[derive(Clone, Copy)]
enum LowerPrivilege {
    Privileged,
    Unprivileged,
}

#[derive(Clone, Copy)]
enum LowerObservation {
    Read,
    Write,
    Execute,
}

fn two_privilege_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    privileged_data: aarch64_vmsa::attrs::DataAccess,
    unprivileged_data: aarch64_vmsa::attrs::DataAccess,
    privileged_execute: bool,
    unprivileged_execute: bool,
    privilege: LowerPrivilege,
    observation: LowerObservation,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SoftwareMetadata, Stage2MemoryMode, TwoPrivilegeLeafPermissions,
        TwoPrivilegeTablePermissionLimits,
    };
    use vmsa_test_harness::{
        AccessKind, AddressBits, Asid, ExpectedFault, FaultClass, FaultMatcher, FaultStage,
        FaultStatus, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };

    const ADDRESS: u64 = 0x6c00_0000;
    const DATA_OFFSET: u64 = 16;
    const INITIAL_VALUE: u64 = 0x5457_4f50_5249_564c;
    const WRITTEN_VALUE: u64 = INITIAL_VALUE ^ u64::MAX;

    let page = context.allocate_page()?;
    let backing = page.virtual_address() as u64;
    for (offset, instruction) in [(0, 0xd280_0020), (4, 0xd65f_03c0)] {
        let result = context.write_u32(backing + offset, instruction);
        if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
            return vmsa_test_harness::expect_completed(result);
        }
    }
    let result = context.write_u64(backing + DATA_OFFSET, INITIAL_VALUE);
    if !matches!(result, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(result);
    }
    if matches!(observation, LowerObservation::Execute) {
        context.maintain_cache(
            vmsa_test_harness::CacheMaintenanceOperation::InstructionCoherency {
                address: backing,
                bytes: 8,
            },
        )?;
    }

    let config = LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let permissions = TwoPrivilegeLeafPermissions {
        privileged_data,
        unprivileged_data,
        privileged_execute,
        unprivileged_execute,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions,
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: TwoPrivilegeTablePermissionLimits {
            privileged_data_limit: DataAccess::ReadWrite,
            unprivileged_data_limit: DataAccess::ReadWrite,
            privileged_execute_limit: true,
            unprivileged_execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let bits = AddressBits::new(48).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls_4k(bits, bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            crate::LowerRegime,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(&mut root, aarch64_vmsa::address::Level::L0, 48, 48)?;
        mapper.map_semantic_leaf::<_>(
            &config,
            ADDRESS,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut live = context.install_lower_owned(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits: bits,
            output_bits: bits,
            start_level: LookupLevel::new(0),
            asid: Some(Asid(0x61)),
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    let decoded = live
        .inspect_semantic_for::<
            crate::LowerRegime,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if decoded != leaf {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }

    let data_access = match privilege {
        LowerPrivilege::Privileged => privileged_data,
        LowerPrivilege::Unprivileged => unprivileged_data,
    };
    let execute_allowed = match privilege {
        LowerPrivilege::Privileged => privileged_execute,
        LowerPrivilege::Unprivileged => unprivileged_execute,
    };
    let result = match (privilege, observation) {
        (LowerPrivilege::Privileged, LowerObservation::Read) if data_access != DataAccess::None => {
            vmsa_test_harness::expect_value(
                context.lower_read_u64(ADDRESS + DATA_OFFSET),
                INITIAL_VALUE,
            )
        }
        (LowerPrivilege::Unprivileged, LowerObservation::Read)
            if data_access != DataAccess::None =>
        {
            vmsa_test_harness::expect_value(
                context.el0_read_u64(ADDRESS + DATA_OFFSET),
                INITIAL_VALUE,
            )
        }
        (LowerPrivilege::Privileged, LowerObservation::Write)
            if data_access == DataAccess::ReadWrite =>
        {
            vmsa_test_harness::expect_completed(
                context.lower_write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE),
            )
        }
        (LowerPrivilege::Unprivileged, LowerObservation::Write)
            if data_access == DataAccess::ReadWrite =>
        {
            vmsa_test_harness::expect_completed(
                context.el0_write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE),
            )
        }
        (selected_privilege, LowerObservation::Read | LowerObservation::Write) => {
            let access = if matches!(observation, LowerObservation::Read) {
                AccessKind::Read
            } else {
                AccessKind::Write
            };
            let observed = match (selected_privilege, observation) {
                (LowerPrivilege::Privileged, LowerObservation::Read) => {
                    context.lower_read_u64(ADDRESS + DATA_OFFSET)
                }
                (LowerPrivilege::Privileged, LowerObservation::Write) => {
                    context.lower_write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE)
                }
                (LowerPrivilege::Unprivileged, LowerObservation::Read) => {
                    context.el0_read_u64(ADDRESS + DATA_OFFSET)
                }
                (LowerPrivilege::Unprivileged, LowerObservation::Write) => {
                    context.el0_write_u64(ADDRESS + DATA_OFFSET, WRITTEN_VALUE)
                }
                _ => {
                    return vmsa_test_harness::HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                    .into();
                }
            };
            vmsa_test_harness::expect_matching_fault(
                observed,
                FaultMatcher::new(ExpectedFault {
                    status: Some(FaultStatus::Permission),
                    access: Some(access),
                    stage: Some(FaultStage::Stage1),
                    level: None,
                })
                .with_class(FaultClass::DataAbort)
                .at_address(ADDRESS + DATA_OFFSET),
            )
        }
        (selected_privilege, LowerObservation::Execute) => {
            let observed = match selected_privilege {
                LowerPrivilege::Privileged => context.lower_execute(ADDRESS),
                LowerPrivilege::Unprivileged => context.el0_execute(ADDRESS),
            };
            if execute_allowed {
                vmsa_test_harness::expect_value(observed, 1)
            } else {
                vmsa_test_harness::expect_matching_fault(
                    observed,
                    FaultMatcher::new(ExpectedFault {
                        status: Some(FaultStatus::Permission),
                        access: Some(AccessKind::Execute),
                        stage: Some(FaultStage::Stage1),
                        level: None,
                    })
                    .with_class(FaultClass::InstructionAbort)
                    .at_address(ADDRESS),
                )
            }
        }
    };
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    live.restore()?;
    TestResult::Pass
}

macro_rules! two_data_case {
    ($name:ident, $pd:ident, $ud:ident, $privilege:ident, $observation:ident) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            two_privilege_case(
                context,
                aarch64_vmsa::attrs::DataAccess::$pd,
                aarch64_vmsa::attrs::DataAccess::$ud,
                false,
                false,
                LowerPrivilege::$privilege,
                LowerObservation::$observation,
            )
        }
    };
}

two_data_case!(p_rw_u_none_pr, ReadWrite, None, Privileged, Read);
two_data_case!(p_rw_u_none_pw, ReadWrite, None, Privileged, Write);
two_data_case!(p_rw_u_none_ur, ReadWrite, None, Unprivileged, Read);
two_data_case!(p_rw_u_none_uw, ReadWrite, None, Unprivileged, Write);
two_data_case!(p_rw_u_rw_pr, ReadWrite, ReadWrite, Privileged, Read);
two_data_case!(p_rw_u_rw_pw, ReadWrite, ReadWrite, Privileged, Write);
two_data_case!(p_rw_u_rw_ur, ReadWrite, ReadWrite, Unprivileged, Read);
two_data_case!(p_rw_u_rw_uw, ReadWrite, ReadWrite, Unprivileged, Write);
two_data_case!(p_ro_u_none_pr, ReadOnly, None, Privileged, Read);
two_data_case!(p_ro_u_none_pw, ReadOnly, None, Privileged, Write);
two_data_case!(p_ro_u_none_ur, ReadOnly, None, Unprivileged, Read);
two_data_case!(p_ro_u_none_uw, ReadOnly, None, Unprivileged, Write);
two_data_case!(p_ro_u_ro_pr, ReadOnly, ReadOnly, Privileged, Read);
two_data_case!(p_ro_u_ro_pw, ReadOnly, ReadOnly, Privileged, Write);
two_data_case!(p_ro_u_ro_ur, ReadOnly, ReadOnly, Unprivileged, Read);
two_data_case!(p_ro_u_ro_uw, ReadOnly, ReadOnly, Unprivileged, Write);

macro_rules! two_execute_case {
    ($name:ident, $px:literal, $ux:literal, $privilege:ident) => {
        pub(super) fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            two_privilege_case(
                context,
                aarch64_vmsa::attrs::DataAccess::ReadOnly,
                aarch64_vmsa::attrs::DataAccess::ReadOnly,
                $px,
                $ux,
                LowerPrivilege::$privilege,
                LowerObservation::Execute,
            )
        }
    };
}

two_execute_case!(px0_ux0_pe, false, false, Privileged);
two_execute_case!(px0_ux0_ue, false, false, Unprivileged);
two_execute_case!(px0_ux1_pe, false, true, Privileged);
two_execute_case!(px0_ux1_ue, false, true, Unprivileged);
two_execute_case!(px1_ux0_pe, true, false, Privileged);
two_execute_case!(px1_ux0_ue, true, false, Unprivileged);
two_execute_case!(px1_ux1_pe, true, true, Privileged);
two_execute_case!(px1_ux1_ue, true, true, Unprivileged);
