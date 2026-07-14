use vmsa_test_harness::{TestContext, TestResult};

pub fn secure_semantics<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::regime::SecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
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
    use aarch64_vmsa::address::Granule4KiB;
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience, SecureSelectablePa,
        SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissionLimits, SoftwareMetadata,
        Stage2LeafPermissions, Stage2MemoryAttributes, Stage2MemoryMode, VmsaAttributeCodec,
    };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::{SecureEl2NonSecureIpaStage2, SecureEl2SecureIpaStage2};

    const SECURE_VA: u64 = 0x5000_0000;
    const NON_SECURE_VA: u64 = 0x5000_1000;
    let cacheability = Cacheability::Cacheable {
        policy: CachePolicy::WriteBack,
        transience: MemoryTransience::NonTransient,
        allocation: AllocationHints::ReadWriteAllocate,
    };
    let memory = MemoryAttributes::Normal {
        inner: cacheability,
        outer: cacheability,
    };
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
    let stage1_leaf = |pas| SemanticStage1LeafAttrs {
        memory,
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
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
    let stage1_table = |pas| SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let secure_page = context.allocate_page()?;
    let non_secure_page = context.allocate_page()?;
    let mut root = context.allocate_root()?;
    let mut mapper = context.offline_mapper(&mut root)?;
    for (address, output, pas) in [
        (
            SECURE_VA,
            secure_page.phys_addr(),
            SecureSelectablePa::Secure,
        ),
        (
            NON_SECURE_VA,
            non_secure_page.phys_addr(),
            SecureSelectablePa::NonSecure,
        ),
    ] {
        mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
            &config,
            address,
            output,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_leaf(pas),
            stage1_table(pas),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<VmsaAttributeCodec, _>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.pas != pas {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
    }

    let stage2_leaf = |output_address_space| SemanticStage2LeafAttrs {
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
    let stage2_config = |output_pas| LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas,
    };
    let secure_config = stage2_config(SecureSelectablePa::Secure);
    let non_secure_config = stage2_config(SecureSelectablePa::NonSecure);
    let mut secure_root = context.allocate_root()?;
    let mut secure_mapper = context
        .offline_mapper_for_format_with_geometry::<SecureEl2SecureIpaStage2, Granule4KiB, Vmsa64>(
            &mut secure_root,
            aarch64_vmsa::address::Level::L0,
            48,
            48,
        )?;
    secure_mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &secure_config,
        SECURE_VA,
        secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::Secure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if secure_mapper
        .inspect_semantic_leaf::<VmsaAttributeCodec, _>(SECURE_VA, &secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::Secure
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }

    let mut non_secure_root = context.allocate_root()?;
    let mut non_secure_mapper = context.offline_mapper_for_format_with_geometry::<
        SecureEl2NonSecureIpaStage2,
        Granule4KiB,
        Vmsa64,
    >(
        &mut non_secure_root,
        aarch64_vmsa::address::Level::L0,
        48,
        48,
    )?;
    non_secure_mapper.map_semantic_leaf::<VmsaAttributeCodec, _>(
        &non_secure_config,
        NON_SECURE_VA,
        non_secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::NonSecure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if non_secure_mapper
        .inspect_semantic_leaf::<VmsaAttributeCodec, _>(NON_SECURE_VA, &non_secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::NonSecure
    {
        return vmsa_test_harness::HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

pub fn realm_semantics<E: vmsa_test_harness::adapter::Environment>(
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
