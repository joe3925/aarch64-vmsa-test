use crate::{CurrentEnvironment, CurrentPas, CurrentTablePas, D128Regime};
use vmsa_test_harness::{TestContext, TestResult};

pub fn current_stage1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    current_stage1_case(
        context,
        crate::current_pas(),
        crate::current_table_pas(),
        true,
    )
}

pub fn current_stage1_alternate_leaf_pas(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let Some(pas) = crate::alternate_current_pas() else {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    };
    current_stage1_case(context, pas, crate::current_table_pas(), false)
}

pub fn current_stage1_alternate_table_pas(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    let Some(pas) = crate::alternate_current_table_pas() else {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    };
    current_stage1_case(context, crate::current_pas(), pas, false)
}

fn current_stage1_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    leaf_pas: CurrentPas,
    table_pas: CurrentTablePas,
    expect_access: bool,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        Cacheability, DataAccess, DirtyState, LiveVmsaConfig, MemoryAttributes,
        SemanticStage1LeafAttrs, SemanticVmsa128Stage1LeafControls,
        SemanticVmsa128Stage1TableAttrs, Shareability, SoftwareMetadata,
        Stage1EffectivePermissions, Stage1PermissionRegisterPair, Stage1PermissionRegisters,
        Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa128;
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, MemoryAttributeSlot, PhysicalAddress,
        Stage1MemoryControls, TranslationFormat, TranslationSetup, TranslationStage,
    };

    // Keep the semantic probe in a distinct level -1 branch from payload
    // text, stacks, vectors, and reporting state.  Table-PAS tests mutate the
    // descriptors leading to this address and must not simultaneously change
    // the PAS used to fetch the harness infrastructure that observes the
    // resulting fault.
    const ADDRESS: u64 = 0x1000_0000_0000;
    const VALUE: u64 = 0x4431_3238_4355_5252;
    let page = context.allocate_page()?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let permission_pair = Stage1PermissionRegisterPair {
        base: 0xcccc_cccc_cccc_ccca,
        overlay: None,
    };
    let config = LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: Some(Stage1PermissionRegisters {
            privileged: permission_pair,
            unprivileged: None,
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: crate::current_d128_alias(),
        shareability: Shareability::InnerShareable,
        output_pas: crate::current_config_pas(),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: leaf_pas,
        controls: SemanticVmsa128Stage1LeafControls {
            bbm_nt: false,
            dirty_state: DirtyState::Dirty,
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            contiguous: false,
            guarded: false,
            protected: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table = SemanticVmsa128Stage1TableAttrs {
        table_nt: false,
        access_flag: false,
        disch: false,
        protected: false,
        pas: table_pas,
        software: SoftwareMetadata::new(0),
    };
    let bits = AddressBits::new(52).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start = LookupLevel::new(-1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let final_level = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let mut root = context.allocate_root()?;
    let offline;
    let sandbox;
    {
        let mut mapper = context
            .offline_mapper_for_format_with_geometry::<D128Regime, Granule4KiB, Vmsa128>(
                &mut root,
                Level::new(-1),
                52,
                52,
            )?;
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            ADDRESS,
            page.phys_addr(),
            final_level,
            leaf,
            table,
        )?;
        offline = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(ADDRESS, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if offline != leaf {
            return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
        }
        sandbox = context.prepare_d128_transition_runtime::<D128Regime>(
            &mut mapper,
            current_stage1_case as *const () as u64,
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let mut translation = context.install_owned_in_sandbox(
        root,
        TranslationSetup {
            root: root_address,
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa128,
            input_bits: bits,
            output_bits: bits,
            start_level: Some(start),
            asid: crate::current_d128_asid(),
            vmid: None,
            controls: crate::current_d128_controls(bits)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_memory: Stage1MemoryControls::empty().with_raw_attribute(
                MemoryAttributeSlot::new(0)
                    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                0x44,
            ),
            regime: crate::current_regime_attributes(),
        },
        &sandbox,
    )?;
    let live = translation
        .inspect_semantic_for::<D128Regime, Vmsa128, Granule4KiB, VmsaAttributeCodec, _>(
            ADDRESS, &config,
        )?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live != offline {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let result = if expect_access {
        vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
    } else {
        vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            crate::alternate_stage1_pas_fault(ADDRESS),
        )
    };
    drop(translation);
    if !context.transition_sandbox_restored(&sandbox) {
        return vmsa_test_harness::HarnessError::Cleanup.into();
    }
    result
}
