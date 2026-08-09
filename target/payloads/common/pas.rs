use vmsa_test_harness::{TestContext, TestResult};

fn direct_memory() -> aarch64_vmsa::attrs::MemoryAttributes {
    aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    }
}

fn direct_config<P: Copy>(output_pas: P) -> aarch64_vmsa::attrs::LiveVmsaConfig<P> {
    use aarch64_vmsa::attrs::{
        D128Stage1AliasKind, LiveVmsaConfig, Shareability, Stage2MemoryMode,
    };
    LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas,
    }
}

fn direct_stage1_controls() -> aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls {
    use aarch64_vmsa::attrs::{
        DirtyBitManagement, SemanticVmsa64Stage1LeafControls, Shareability, SoftwareMetadata,
    };
    SemanticVmsa64Stage1LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        global: true,
        dirty_management: DirtyBitManagement::SoftwareManaged,
        contiguous: false,
        guarded: false,
        software: SoftwareMetadata::new(0),
    }
}

fn secure_stage1_isolated(pas: aarch64_vmsa::attrs::SecureSelectablePa) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::SecureEl2Stage1;
    let config = direct_config(());
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let raw_leaf = <Vmsa64 as AttributeCodec<SecureEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    );
    let raw_table = <Vmsa64 as AttributeCodec<SecureEl2Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L2,
        table,
    );
    let valid = raw_leaf.and_then(|raw| {
        if raw.ns != matches!(pas, aarch64_vmsa::attrs::SecureSelectablePa::NonSecure)
            || raw.alias_bit
        {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<SecureEl2Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    }) == Ok(leaf)
        && raw_table.and_then(|raw| {
            if raw.ns_table != matches!(pas, aarch64_vmsa::attrs::SecureSelectablePa::NonSecure) {
                return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
            }
            <Vmsa64 as AttributeCodec<SecureEl2Stage1, Granule4KiB, _>>::decode_table(
                &config,
                Level::L2,
                raw,
            )
        }) == Ok(table);
    if valid {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

pub fn secure_stage1_secure<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage1_isolated(aarch64_vmsa::attrs::SecureSelectablePa::Secure)
}

pub fn secure_stage1_non_secure<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage1_isolated(aarch64_vmsa::attrs::SecureSelectablePa::NonSecure)
}

fn secure_stage1_active_case<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::SecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
    pas: aarch64_vmsa::attrs::SecureSelectablePa,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };
    const ADDRESS: u64 = 0x6a00_0000;
    const VALUE: u64 = 0x5345_4355_5245_5041;
    let page = context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::Secure)?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let config = direct_config(());
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas,
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let capabilities = context.capabilities();
    let input_bits = AddressBits::new(capabilities.va_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = AddressBits::new(capabilities.pa_bits.min(48))
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let root = context.allocate_root_in(
        vmsa_test_harness::PhysicalAddressSpace::Secure,
        Granule::Size4KiB,
    )?;
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
            regime: vmsa_test_harness::RegimeAttributes::Secure,
        },
    )?;
    live.map_semantic_for::<
        aarch64_vmsa::config::regime::SecureEl2Stage1,
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
            aarch64_vmsa::config::regime::SecureEl2Stage1,
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
    let result = if pas == aarch64_vmsa::attrs::SecureSelectablePa::Secure {
        vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
    } else {
        vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            vmsa_test_harness::FaultMatcher::new(vmsa_test_harness::ExpectedFault {
                status: Some(vmsa_test_harness::FaultStatus::External),
                access: Some(vmsa_test_harness::AccessKind::Read),
                stage: Some(vmsa_test_harness::FaultStage::Stage1),
                level: None,
            })
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(ADDRESS),
        )
    };
    live.restore()?;
    result
}

pub fn secure_stage1_secure_access<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::SecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage1_active_case(context, aarch64_vmsa::attrs::SecureSelectablePa::Secure)
}

pub fn secure_stage1_non_secure_fault<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::SecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage1_active_case(context, aarch64_vmsa::attrs::SecureSelectablePa::NonSecure)
}

macro_rules! secure_stage2_isolated {
    ($regime:ty, $configured:expr, $requested:expr $(,)?) => {{
        use aarch64_vmsa::address::Level;
        use aarch64_vmsa::attrs::{
            AttrError, AttributeCodec, DataAccess, DirtyBitManagement, SemanticStage2LeafAttrs,
            SemanticVmsa64Stage2LeafControls, Shareability, SoftwareMetadata,
            Stage2LeafPermissions, Stage2MemoryAttributes,
        };
        use aarch64_vmsa::config::format::Vmsa64;
        use aarch64_vmsa::config::granule::Granule4KiB;
        let configured = $configured;
        let requested = $requested;
        let config = direct_config(configured);
        let leaf = SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Combined(direct_memory()),
            permissions: Stage2LeafPermissions {
                data: DataAccess::ReadWrite,
                privileged_execute: false,
                unprivileged_execute: false,
            },
            output_address_space: requested,
            controls: SemanticVmsa64Stage2LeafControls {
                shareability: Shareability::InnerShareable,
                access_flag: true,
                dirty_management: DirtyBitManagement::SoftwareManaged,
                contiguous: false,
                software: SoftwareMetadata::new(0),
            },
        };
        let resolved = <Vmsa64 as AttributeCodec<$regime, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            leaf,
        );
        let expected = if configured == requested {
            resolved.and_then(|raw| {
                <Vmsa64 as AttributeCodec<$regime, Granule4KiB, _>>::decode_leaf(
                    &config,
                    Level::L3,
                    raw,
                )
            }) == Ok(leaf)
        } else {
            matches!(resolved, Err(AttrError::InvalidOutputAddressSpace))
        };
        if expected {
            TestResult::Pass
        } else {
            vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into()
        }
    }};
}

pub fn secure_ipa_stage2_configured<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage2_isolated!(
        aarch64_vmsa::config::regime::SecureEl2SecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
    )
}

pub fn non_secure_ipa_stage2_configured<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage2_isolated!(
        aarch64_vmsa::config::regime::SecureEl2NonSecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa::NonSecure,
        aarch64_vmsa::attrs::SecureSelectablePa::NonSecure,
    )
}

pub fn secure_ipa_stage2_mismatch<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage2_isolated!(
        aarch64_vmsa::config::regime::SecureEl2SecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
        aarch64_vmsa::attrs::SecureSelectablePa::NonSecure,
    )
}

pub fn non_secure_ipa_stage2_mismatch<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    secure_stage2_isolated!(
        aarch64_vmsa::config::regime::SecureEl2NonSecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa::NonSecure,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
    )
}

fn realm_stage1_isolated(pas: aarch64_vmsa::attrs::RealmOrNonSecurePa) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::RealmEl2Stage1;
    let config = direct_config(());
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let raw_leaf = <Vmsa64 as AttributeCodec<RealmEl2Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    );
    let raw_table = <Vmsa64 as AttributeCodec<RealmEl2Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L2,
        table,
    );
    let valid = raw_leaf.and_then(|raw| {
        if raw.ns != matches!(pas, aarch64_vmsa::attrs::RealmOrNonSecurePa::NonSecure)
            || raw.alias_bit
        {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<RealmEl2Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    }) == Ok(leaf)
        && raw_table.and_then(|raw| {
            if raw.ns_table {
                return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
            }
            <Vmsa64 as AttributeCodec<RealmEl2Stage1, Granule4KiB, _>>::decode_table(
                &config,
                Level::L2,
                raw,
            )
        }) == Ok(table);
    if valid {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

pub fn realm_stage1_realm<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage1_isolated(aarch64_vmsa::attrs::RealmOrNonSecurePa::Realm)
}

pub fn realm_stage1_non_secure<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage1_isolated(aarch64_vmsa::attrs::RealmOrNonSecurePa::NonSecure)
}

fn realm_stage2_isolated(pas: aarch64_vmsa::attrs::RealmOrNonSecurePa) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, DirtyBitManagement, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, Shareability, SoftwareMetadata, Stage2LeafPermissions,
        Stage2MemoryAttributes,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::RealmEl2Stage2;
    let config = direct_config(pas);
    let leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(direct_memory()),
        permissions: Stage2LeafPermissions {
            data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: pas,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let decoded = <Vmsa64 as AttributeCodec<RealmEl2Stage2, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    )
    .and_then(|raw| {
        <Vmsa64 as AttributeCodec<RealmEl2Stage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    });
    if decoded == Ok(leaf) {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

pub fn realm_stage2_realm<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage2_isolated(aarch64_vmsa::attrs::RealmOrNonSecurePa::Realm)
}

pub fn realm_stage2_non_secure<E: vmsa_test_harness::adapter::Environment>(
    _: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage2_isolated(aarch64_vmsa::attrs::RealmOrNonSecurePa::NonSecure)
}

fn realm_stage1_active_case<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::RealmEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
    pas: aarch64_vmsa::attrs::RealmOrNonSecurePa,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };
    const ADDRESS: u64 = 0x6b00_0000;
    const VALUE: u64 = 0x5245_414c_4d50_4153;
    let page = context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::Realm)?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let config = direct_config(());
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
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
    let root = context.allocate_root_in(
        vmsa_test_harness::PhysicalAddressSpace::Realm,
        Granule::Size4KiB,
    )?;
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
            regime: vmsa_test_harness::RegimeAttributes::Realm,
        },
    )?;
    live.map_semantic_for::<
        aarch64_vmsa::config::regime::RealmEl2Stage1,
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
            aarch64_vmsa::config::regime::RealmEl2Stage1,
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
    let result = if pas == aarch64_vmsa::attrs::RealmOrNonSecurePa::Realm {
        vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
    } else {
        vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            vmsa_test_harness::FaultMatcher::new(
                vmsa_test_harness::ExpectedFault::granule_protection_read_stage1(),
            )
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(ADDRESS),
        )
    };
    live.restore()?;
    result
}

pub fn realm_stage1_realm_access<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::RealmEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage1_active_case(context, aarch64_vmsa::attrs::RealmOrNonSecurePa::Realm)
}

pub fn realm_stage1_non_secure_fault<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::RealmEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    realm_stage1_active_case(context, aarch64_vmsa::attrs::RealmOrNonSecurePa::NonSecure)
}

fn root_config() -> aarch64_vmsa::attrs::LiveVmsaConfig<()> {
    let mut config = direct_config(());
    config.d128_stage1_alias = aarch64_vmsa::attrs::D128Stage1AliasKind::NonSecureExtension;
    config
}

fn root_stage1_isolated(pas: aarch64_vmsa::attrs::RootExtendedPa) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::RootEl3Stage1;
    let config = root_config();
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
    };
    let table = SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };
    let (ns, nse) = match pas {
        aarch64_vmsa::attrs::RootExtendedPa::Secure => (false, false),
        aarch64_vmsa::attrs::RootExtendedPa::NonSecure => (true, false),
        aarch64_vmsa::attrs::RootExtendedPa::Root => (false, true),
        aarch64_vmsa::attrs::RootExtendedPa::Realm => (true, true),
    };
    let raw_leaf = <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    );
    let raw_table = <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L2,
        table,
    );
    let valid = raw_leaf.and_then(|raw| {
        if raw.ns != ns || raw.alias_bit != nse {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    }) == Ok(leaf)
        && raw_table.and_then(|raw| {
            if raw.ns_table {
                return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
            }
            <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_table(
                &config,
                Level::L2,
                raw,
            )
        }) == Ok(table);
    if valid {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

macro_rules! root_codec_case {
    ($name:ident, $pas:ident) => {
        pub fn $name<E: vmsa_test_harness::adapter::Environment>(
            _: &mut TestContext<'_, E>,
        ) -> TestResult {
            root_stage1_isolated(aarch64_vmsa::attrs::RootExtendedPa::$pas)
        }
    };
}

root_codec_case!(root_stage1_secure, Secure);
root_codec_case!(root_stage1_non_secure, NonSecure);
root_codec_case!(root_stage1_root, Root);
root_codec_case!(root_stage1_realm, Realm);

fn root_stage1_active_case<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::RootEl3Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
    pas: aarch64_vmsa::attrs::RootExtendedPa,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        DataAccess, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1TableControls, SinglePrivilegeLeafPermissions,
        SinglePrivilegeTablePermissionLimits,
    };
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };
    const ADDRESS: u64 = 0x6d00_0000;
    const VALUE: u64 = 0x524f_4f54_5041_5353;
    let page = context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::Root)?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let config = root_config();
    let leaf = SemanticStage1LeafAttrs {
        memory: direct_memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadWrite,
            execute: false,
        },
        pas,
        controls: direct_stage1_controls(),
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
    let root = context.allocate_root_in(
        vmsa_test_harness::PhysicalAddressSpace::Root,
        Granule::Size4KiB,
    )?;
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
            regime: vmsa_test_harness::RegimeAttributes::Root,
        },
    )?;
    live.map_semantic_for::<
        aarch64_vmsa::config::regime::RootEl3Stage1,
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
            aarch64_vmsa::config::regime::RootEl3Stage1,
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
    let result = if pas == aarch64_vmsa::attrs::RootExtendedPa::Root {
        vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
    } else {
        vmsa_test_harness::expect_matching_fault(
            context.read_u64(ADDRESS),
            vmsa_test_harness::FaultMatcher::new(
                vmsa_test_harness::ExpectedFault::granule_protection_read_stage1(),
            )
            .with_class(vmsa_test_harness::FaultClass::DataAbort)
            .at_address(ADDRESS),
        )
    };
    live.restore()?;
    result
}

macro_rules! root_active_case {
    ($name:ident, $pas:ident) => {
        pub fn $name<
            E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
                    Regime = aarch64_vmsa::config::regime::RootEl3Stage1,
                >,
        >(
            context: &mut TestContext<'_, E>,
        ) -> TestResult {
            root_stage1_active_case(context, aarch64_vmsa::attrs::RootExtendedPa::$pas)
        }
    };
}

root_active_case!(root_stage1_secure_fault, Secure);
root_active_case!(root_stage1_non_secure_fault, NonSecure);
root_active_case!(root_stage1_root_access, Root);
root_active_case!(root_stage1_realm_fault, Realm);

pub fn secure_semantics<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment<
            Regime = aarch64_vmsa::config::regime::SecureEl2Stage1,
        >,
>(
    context: &mut TestContext<'_, E>,
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
{
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience, SecureSelectablePa,
        SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissionLimits, SoftwareMetadata,
        Stage2LeafPermissions, Stage2MemoryAttributes, Stage2MemoryMode,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::{SecureEl2NonSecureIpaStage2, SecureEl2SecureIpaStage2};

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
        mapper.map_semantic_leaf::<_>(
            &config,
            address,
            output,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            stage1_leaf(pas),
            stage1_table(pas),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<_>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.pas != pas {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
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
    secure_mapper.map_semantic_leaf::<_>(
        &secure_config,
        SECURE_VA,
        secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::Secure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if secure_mapper
        .inspect_semantic_leaf::<_>(SECURE_VA, &secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::Secure
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
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
    non_secure_mapper.map_semantic_leaf::<_>(
        &non_secure_config,
        NON_SECURE_VA,
        non_secure_page.phys_addr(),
        vmsa_test_harness::LookupLevel::new(3)
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        stage2_leaf(SecureSelectablePa::NonSecure),
        SemanticVmsa64Stage2TableAttrs::default(),
    )?;
    if non_secure_mapper
        .inspect_semantic_leaf::<_>(NON_SECURE_VA, &non_secure_config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
        .output_address_space
        != SecureSelectablePa::NonSecure
    {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    TestResult::Pass
}

pub fn realm_semantics<E: vmsa_test_harness::adapter::Environment>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, D128Stage1AliasKind, DataAccess,
        DirtyBitManagement, LiveVmsaConfig, MemoryAttributes, MemoryTransience, RealmOrNonSecurePa,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
        Shareability, SoftwareMetadata, Stage2LeafPermissions, Stage2MemoryAttributes,
        Stage2MemoryMode,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::RealmEl2Stage2;

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
        mapper.map_semantic_leaf::<_>(
            &config,
            address,
            output.phys_addr() + index as u64 * 4096,
            vmsa_test_harness::LookupLevel::new(3)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            leaf(pas),
            SemanticVmsa64Stage2TableAttrs::default(),
        )?;
        let decoded = mapper
            .inspect_semantic_leaf::<_>(address, &config)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
        if decoded.output_address_space != pas {
            return vmsa_test_harness::HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            }
            .into();
        }
    }
    TestResult::Pass
}

pub fn fixed_realm_ipa_stage1_semantic_access<
    E: vmsa_test_harness::adapter::TranslationRegimeEnvironment,
>(
    context: &mut TestContext<'_, E>,
) -> TestResult {
    use aarch64_vmsa::attrs::{
        Cacheability, D128Stage1AliasKind, DataAccess, DirtyBitManagement, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SoftwareMetadata, Stage2MemoryMode, TwoPrivilegeLeafPermissions,
        TwoPrivilegeTablePermissionLimits,
    };
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, MappingAttributes, PhysicalAddress, RegimeAttributes,
        TranslationFormat, TranslationSetup, TranslationStage, Vmid,
    };

    const ADDRESS: u64 = 0x5300_0000;
    const VALUE: u64 = 0x5245_414c_4d49_5041;
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
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        },
        permissions: TwoPrivilegeLeafPermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
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
    let input_bits = AddressBits::new(48).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_bits = input_bits;
    let root = context.allocate_root()?;
    let mut stage2_root = context.allocate_root()?;
    let physical_region = root.phys_addr() & !0x3fff_ffff;
    let target_region = physical_region ^ 0x4000_0000;
    let target_ipa = target_region | (page.phys_addr() & 0x3fff_ffff);
    {
        let mut mapper = context.offline_mapper_for_format_with_geometry::<
            aarch64_vmsa::config::regime::RealmEl2Stage2,
            aarch64_vmsa::config::granule::Granule4KiB,
            aarch64_vmsa::config::format::Vmsa64,
        >(
            &mut stage2_root,
            aarch64_vmsa::address::Level::L0,
            48,
            48,
        )?;
        let recovery = MappingAttributes {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        mapper.map_leaf(
            physical_region,
            physical_region,
            LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            recovery,
        )?;
        if physical_region != 0 {
            mapper.map_leaf(
                0,
                0,
                LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
                recovery,
            )?;
        }
        mapper.map_leaf(
            target_ipa,
            page.phys_addr(),
            LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            MappingAttributes::READ_WRITE,
        )?;
    }
    let root_address = PhysicalAddress::new(root.phys_addr());
    let stage1_setup = TranslationSetup {
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
        regime: RegimeAttributes::Realm,
    };
    let stage2_controls = vmsa_test_harness::vmsa64_stage2_controls_4k(
        input_bits,
        output_bits,
        LookupLevel::new(0).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
    )
    .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_setup = TranslationSetup {
        root: PhysicalAddress::new(stage2_root.phys_addr()),
        stage: TranslationStage::Stage2,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64,
        input_bits,
        output_bits,
        start_level: LookupLevel::new(0),
        asid: None,
        vmid: Some(Vmid(0x5a)),
        controls: stage2_controls,
        stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
        regime: RegimeAttributes::Realm,
    };
    let mut live = context.install_combined_owned(root, stage1_setup, stage2_root, stage2_setup)?;
    live.stage1_mut()?.map_semantic_for::<
        aarch64_vmsa::config::regime::RealmEl1Stage1,
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule4KiB,
        _,
    >(
        &config,
        ADDRESS,
        target_ipa,
        LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
        leaf,
        table,
    )?;
    let installed = live
        .stage1_mut()?
        .inspect_semantic_for::<
            aarch64_vmsa::config::regime::RealmEl1Stage1,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
            _,
        >(ADDRESS, &config)?
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    if installed != leaf {
        return vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into();
    }
    let result = vmsa_test_harness::expect_value(live.read_u64(ADDRESS), VALUE);
    if !matches!(result, TestResult::Pass) {
        return result;
    }
    live.restore()?;
    TestResult::Pass
}
