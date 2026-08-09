use crate::{CurrentEnvironment, LowerRegime};
use vmsa_test_harness::{TestContext, TestResult};

fn lower_vmsa64_leaf<G, P>(
    context: &mut TestContext<'_, CurrentEnvironment>,
    mut root: vmsa_test_harness::RootTableMemory,
    granule: vmsa_test_harness::Granule,
    start_level: aarch64_vmsa::address::Level,
    leaf_level: aarch64_vmsa::address::Level,
    pas: P,
) -> TestResult
where
    G: vmsa_test_harness::adapter::TestGranule,
    P: Copy + core::fmt::Debug + Eq + PartialEq,
    LowerRegime: vmsa_test_harness::adapter::TestRegimeFor<G>,
    aarch64_vmsa::config::format::Vmsa64:
        aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::translation::Stage1, G>,
    crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, LowerRegime, G>: Copy,
    aarch64_vmsa::config::format::Vmsa64: vmsa_test_harness::AttributeCodecCompat<
            LowerRegime,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<P>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
                aarch64_vmsa::attrs::TwoPrivilegeLeafPermissions,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticStage1TableAttrs<
                aarch64_vmsa::attrs::TwoPrivilegeTablePermissionLimits,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
            >,
            RawLeaf = crate::LeafFieldsOf<aarch64_vmsa::config::format::Vmsa64, LowerRegime, G>,
            RawTable = crate::TableFieldsOf<aarch64_vmsa::config::format::Vmsa64, LowerRegime, G>,
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

    const VALUE: u64 = 0x4c4f_5745_5253_454d;
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
    // Block mappings must not cover the firmware's lower-EL runtime window.
    // A 1-TiB test window is representable for every VMSA64 granule while
    // remaining separate from the identity-mapped payload and transition code.
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
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let offline;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<LowerRegime, G, Vmsa64>(
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
    }
    let controls = vmsa_test_harness::vmsa64_el1_stage1_controls(granule, input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let live_root = context.allocate_root_in(context.native_pas(), granule)?;
    let root_address = PhysicalAddress::new(live_root.phys_addr());
    let mut translation = context.install_lower_owned(
        live_root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
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
    let installed = context
        .infrastructure_lower_stage1_snapshot()
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    const OWNED_TCR_MASK: u64 = 0x0000_003f_0000_ffff;
    if installed.tcr & OWNED_TCR_MASK != controls.bits() & OWNED_TCR_MASK
        || installed.ttbr0 & 0x0000_ffff_ffff_f000 != root_address.get() & 0x0000_ffff_ffff_f000
    {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: controls.bits() & OWNED_TCR_MASK,
            actual: installed.tcr & OWNED_TCR_MASK,
        });
    }
    translation.map_semantic_for::<LowerRegime, Vmsa64, G, _>(
        &config,
        input_base,
        output,
        LookupLevel::new(leaf_level.as_i8())
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let live = translation
        .inspect_semantic_for::<LowerRegime, Vmsa64, G, _>(input, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live != offline || live.permissions != permissions {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = if granule == vmsa_test_harness::Granule::Size16KiB {
        match context.translate_lower_stage1(input, vmsa_test_harness::TranslationQueryAccess::Read)
        {
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
        }
    } else {
        vmsa_test_harness::expect_value(context.lower_read_u64(input), VALUE)
    };
    drop(translation);
    result
}

macro_rules! lower_case {
    ($name:ident, $granule:ty, $allocate:ident, $kind:expr, $start:expr, $leaf:expr) => {
        pub fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            let root = context.$allocate()?;
            lower_vmsa64_leaf::<$granule, crate::LowerPas>(
                context,
                root,
                $kind,
                $start,
                $leaf,
                crate::lower_pas(),
            )
        }
    };
}

lower_case!(
    lower_4k_l1,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L1
);

lower_case!(
    lower_4k_l2,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L2
);
lower_case!(
    lower_4k_l3,
    aarch64_vmsa::config::granule::Granule4KiB,
    allocate_root,
    vmsa_test_harness::Granule::Size4KiB,
    aarch64_vmsa::address::Level::L0,
    aarch64_vmsa::address::Level::L3
);
lower_case!(
    lower_16k_l2,
    aarch64_vmsa::config::granule::Granule16KiB,
    allocate_root_16k,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L2
);
lower_case!(
    lower_16k_l3,
    aarch64_vmsa::config::granule::Granule16KiB,
    allocate_root_16k,
    vmsa_test_harness::Granule::Size16KiB,
    aarch64_vmsa::address::Level::L1,
    aarch64_vmsa::address::Level::L3
);
lower_case!(
    lower_64k_l2,
    aarch64_vmsa::config::granule::Granule64KiB,
    allocate_root_64k,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L2,
    aarch64_vmsa::address::Level::L2
);
lower_case!(
    lower_64k_l3,
    aarch64_vmsa::config::granule::Granule64KiB,
    allocate_root_64k,
    vmsa_test_harness::Granule::Size64KiB,
    aarch64_vmsa::address::Level::L2,
    aarch64_vmsa::address::Level::L3
);
