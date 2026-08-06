use crate::{CurrentEnvironment, CurrentRegime};
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn semantic_codec(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    let config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0x0000_ff44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    const ADDRESS: u64 = 0x6400_0000;
    let page = context.allocate_page()?;
    let mut offline_root = context.allocate_root()?;
    let leaf = semantic_leaf();
    let table = semantic_table();
    let semantic = {
        let mut mapper = context.offline_mapper(&mut offline_root)?;
        mapper.map_semantic_leaf::<_>(
            &config,
            ADDRESS,
            page.phys_addr(),
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf,
            table,
        )?;
        mapper
            .inspect_semantic_leaf::<_>(ADDRESS, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
    };
    let capabilities = context.capabilities();
    let input_bits = vmsa_test_harness::AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = vmsa_test_harness::AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root()?;
    let root_address = vmsa_test_harness::PhysicalAddress::new(root.phys_addr());
    let mut live = context.install_owned(
        root,
        vmsa_test_harness::TranslationSetup {
            root: root_address,
            stage: vmsa_test_harness::TranslationStage::Stage1,
            granule: vmsa_test_harness::Granule::Size4KiB,
            format: vmsa_test_harness::TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: vmsa_test_harness::LookupLevel::new(0),
            asid: None,
            vmid: None,
            controls: vmsa_test_harness::TranslationControls::PRESERVE_CURRENT,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        },
    )?;
    live.map_semantic_for::<
        CurrentRegime,
        aarch64_vmsa::descriptor::Vmsa64,
        aarch64_vmsa::address::Granule4KiB,
        _,
    >(
        &config,
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let live_mapping = live
        .inspect_for::<
            CurrentRegime,
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::address::Granule4KiB,
        >(ADDRESS)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_mapping.output != page.phys_addr() {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    let live_semantic = live
        .inspect_semantic_for::<
            CurrentRegime,
            aarch64_vmsa::descriptor::Vmsa64,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if live_semantic != semantic {
        return vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into();
    }
    live.restore()?;
    let observations =
        u64::from(semantic.permissions.data == aarch64_vmsa::attrs::DataAccess::ReadWrite)
            | (u64::from(!semantic.permissions.execute) << 1)
            | (u64::from(semantic.controls.access_flag) << 2)
            | (u64::from(
                semantic.controls.shareability == aarch64_vmsa::attrs::Shareability::InnerShareable,
            ) << 3);
    if observations != 0xf {
        return TestResult::Fail(vmsa_test_harness::TestFailure {
            kind: vmsa_test_harness::FailureKind::WrongValue,
            expected: 0xf,
            actual: observations,
        });
    }
    TestResult::Pass
}
pub(super) fn missing_memory_attribute(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    const ADDRESS: u64 = 0x6400_0000;
    let page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper(&mut root)?;
    let config = aarch64_vmsa::attrs::LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
        output_pas: (),
    };
    if mapper.map_semantic_leaf::<_>(
        &config,
        ADDRESS,
        page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        semantic_leaf(),
        semantic_table(),
    ) == Err(vmsa_test_harness::HarnessError::Attribute(
        vmsa_test_harness::AttributeError::MemoryAttributeNotConfigured,
    )) {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into()
    }
}

fn semantic_leaf() -> aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
    aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
    (),
    aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
> {
    aarch64_vmsa::attrs::SemanticStage1LeafAttrs {
        memory: aarch64_vmsa::attrs::MemoryAttributes::Normal {
            inner: aarch64_vmsa::attrs::Cacheability::Cacheable {
                policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
                transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
                allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
            },
            outer: aarch64_vmsa::attrs::Cacheability::Cacheable {
                policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
                transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
                allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
            },
        },
        permissions: aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions {
            data: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute: false,
        },
        pas: (),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls {
            shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: aarch64_vmsa::attrs::SoftwareMetadata::new(0),
        },
    }
}

fn semantic_table() -> aarch64_vmsa::attrs::SemanticStage1TableAttrs<
    aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits,
    (),
    aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
> {
    aarch64_vmsa::attrs::SemanticStage1TableAttrs {
        permission_limits: aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits {
            data_limit: aarch64_vmsa::attrs::DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls::default(),
    }
}
