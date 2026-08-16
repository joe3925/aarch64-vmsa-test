use crate::{CurrentEnvironment, CurrentRegime};
use vmsa_test_harness::{TestContext, TestResult};

pub fn lpa2_stage1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, RootExtendedPa, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SinglePrivilegeTablePermissionLimits, SoftwareMetadata, Stage1EffectivePermissions,
        Stage2MemoryMode,
    };
    use aarch64_vmsa::config::format::Vmsa64Lpa2;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, MemoryAttributeSlot, PhysicalAddress,
        Stage1MemoryControls, TranslationFormat, TranslationSetup, TranslationStage,
    };

    const ADDRESS: u64 = 0x1_2000_0000;
    const VALUE: u64 = 0x524f_4f54_4c50_4132;
    let page = context.allocate_page()?;
    if !matches!(
        context.write_u64(page.virtual_address() as u64, VALUE),
        vmsa_test_harness::AccessResult::Completed { .. }
    ) {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonSecureExtension,
        shareability: Shareability::InnerShareable,
        output_pas: RootExtendedPa::Root,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: aarch64_vmsa::attrs::Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: RootExtendedPa::Root,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
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
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let final_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    let offline;
    let sandbox;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<CurrentRegime, Granule4KiB, Vmsa64Lpa2>(
                &mut root,
                Level::NEG1,
                52,
                52,
            )?;
        mapper.map_semantic_leaf::<_>(
            &config,
            ADDRESS,
            page.phys_addr(),
            final_level,
            leaf,
            table,
        )?;
        offline = mapper
            .inspect_semantic_leaf::<_>(ADDRESS, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if offline != leaf {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
        sandbox = context.prepare_transition_runtime(
            &mut mapper,
            lpa2_stage1 as *const () as u64,
            false,
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned_in_sandbox(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64Lpa2,
            input_bits: bits,
            output_bits: bits,
            start_level: Some(start),
            asid: None,
            vmid: None,
            controls: vmsa_test_harness::lpa2_el3_stage1_controls_4k(bits, bits)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_memory: Stage1MemoryControls::empty().with_raw_attribute(
                MemoryAttributeSlot::new(0).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                0x44,
            ),
            regime: vmsa_test_harness::RegimeAttributes::Root,
        },
        &sandbox,
    )?;
    let live = translation
        .inspect_semantic_for::<CurrentRegime, Vmsa64Lpa2, Granule4KiB, _>(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live != offline {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
}
