use crate::{CurrentEnvironment, HostRegime};
use vmsa_test_harness::{TestContext, TestResult};

fn host_vmsa64_leaf<G, P, Q>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    pas: P,
    table_pas: Q,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    P: Copy + core::fmt::Debug + Eq + PartialEq,
    Q: Copy + core::fmt::Debug + Eq + PartialEq,
    HostRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, HostRegime, G>: Copy + PartialEq,
    aarch64_vmsa::config::format::Vmsa64: vmsa_test_harness::AttributeCodecCompat<
            HostRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<P>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::TwoPrivilegeLeafPermissions,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::TwoPrivilegeTablePermissionLimits,
                Q,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
            >,
            RawLeaf = crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, HostRegime, G>,
            RawTable = crate::TableFieldsOf<aarch64_vmsa::config::format::Vmsa64, HostRegime, G>,
        >,
{
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SoftwareMetadata, Stage2MemoryMode, TwoPrivilegeLeafPermissions,
        TwoPrivilegeTablePermissionLimits,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use vmsa_test_harness::{AddressBits, LookupLevel, PhysicalAddress};

    const VALUE: u64 = 0x484f_5354_5345_4d41;
    let page = context.allocate_granule(granule)?;
    let target = page
        .phys_addr()
        .checked_add(8)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64 + 8, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let covered =
        aarch64_vmsa::table::TableGeometry::<Vmsa64, G>::offset_at_level_raw(u64::MAX, leaf_level)
            .and_then(|mask| mask.checked_add(1))
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output = target & !(covered - 1);
    let offset = target - output;
    let input = ((1u64 << 40) & !(covered - 1)) + offset;
    let input_base = input - offset;
    let width = match granule {
        vmsa_test_harness::Granule::Size4KiB => 48,
        vmsa_test_harness::Granule::Size16KiB => 47,
        vmsa_test_harness::Granule::Size64KiB => 42,
    };
    let input_bits =
        AddressBits::new(width).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(48).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: pas,
    };
    let permissions = TwoPrivilegeLeafPermissions {
        privileged_data: DataAccess::ReadWrite,
        unprivileged_data: DataAccess::ReadWrite,
        privileged_execute: false,
        unprivileged_execute: false,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions,
        pas,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: false,
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
            privileged_execute_limit: false,
            unprivileged_execute_limit: false,
        },
        pas: table_pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let offline;
    let sandbox;
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<HostRegime, G, Vmsa64>(
            &mut root,
            start_level,
            width,
            48,
        )?;
        mapper.map_semantic_leaf::<_>(
            &config,
            input_base,
            output,
            LookupLevel::new(leaf_level.as_i8())
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        )?;
        offline = mapper
            .inspect_semantic_leaf::<_>(input, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if offline != leaf
            || mapper
                .translate(input)?
                .is_none_or(|mapping| mapping.output != target)
        {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            host_vmsa64_leaf::<G, P, Q> as *const () as u64,
            true,
        )?;
    }
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls(granule, input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned_in_sandbox(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: LookupLevel::new(start_level.as_i8()),
            asid: Some(vmsa_test_harness::Asid(0x48)),
            vmid: None,
            controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: crate::host_regime_attributes(),
        },
        &sandbox,
    )?;
    let live = translation
        .inspect_semantic_for::<HostRegime, Vmsa64, G, _>(input, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live != offline || live.permissions != permissions {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El0UnderEl2)?;
    let result = match execution.translate(input, vmsa_test_harness::TranslationQueryAccess::Read) {
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } if physical_address == target => TestResult::Pass,
        vmsa_test_harness::TranslationQueryResult::Success {
            physical_address, ..
        } => TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: target,
            actual: physical_address,
        }),
        vmsa_test_harness::TranslationQueryResult::Fault { raw, .. } => {
            TestResult::Fail(vmsa_test_harness::TestFailure {
                kind: vmsa_test_harness::FailureKind::WrongValue,
                expected: target,
                actual: raw,
            })
        }
        vmsa_test_harness::TranslationQueryResult::Unsupported => {
            vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into()
        }
    };
    execution.finish()?;
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::Cleanup.into();
    }
    result
}

macro_rules! host_case {
    ($name:ident, $granule:ty, $allocate:ident, $kind:expr, $start:expr, $leaf:expr) => {
        pub fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            let root = context.$allocate()?;
            host_vmsa64_leaf::<$granule, crate::HostPas, crate::HostTablePas>(
                context,
                root,
                $kind,
                $start,
                $leaf,
                crate::host_pas(),
                crate::host_table_pas(),
            )
        }
    };
}

host_case!(
    host_4k_l1,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L1
);
host_case!(
    host_4k_l2,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L2
);
host_case!(
    host_4k_l3,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L3
);
host_case!(
    host_16k_l2,
    aarch64_vmsa::config::granule::Granule16KiB,
    allocate_root_16k,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L2
);
host_case!(
    host_16k_l3,
    aarch64_vmsa::config::granule::Granule16KiB,
    allocate_root_16k,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L3
);
host_case!(
    host_64k_l2,
    aarch64_vmsa::config::granule::Granule64KiB,
    allocate_root_64k,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L2,
    aarch64_vmsa::address::Level::L2
);
host_case!(
    host_64k_l3,
    aarch64_vmsa::config::granule::Granule64KiB,
    allocate_root_64k,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L2,
    aarch64_vmsa::address::Level::L3
);
