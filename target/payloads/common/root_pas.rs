use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

fn memory() -> aarch64_vmsa::attrs::MemoryAttributes {
    aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    }
}

fn config() -> aarch64_vmsa::attrs::LiveVmsaConfig<()> {
    use aarch64_vmsa::attrs::{
        D128Stage1AliasKind, LiveVmsaConfig, Shareability, Stage2MemoryMode,
    };
    LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: None,
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: D128Stage1AliasKind::NonSecureExtension,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    }
}

fn leaf(
    pas: aarch64_vmsa::attrs::RootExtendedPa,
) -> aarch64_vmsa::attrs::SemanticStage1LeafAttrs<
    aarch64_vmsa::attrs::SinglePrivilegeLeafPermissions,
    aarch64_vmsa::attrs::RootExtendedPa,
    aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls,
> {
    use aarch64_vmsa::attrs::{
        DataAccess, DirtyBitManagement, SemanticStage1LeafAttrs, SemanticVmsa64Stage1LeafControls,
        Shareability, SinglePrivilegeLeafPermissions, SoftwareMetadata,
    };
    SemanticStage1LeafAttrs {
        memory: memory(),
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
    }
}

fn table() -> aarch64_vmsa::attrs::SemanticStage1TableAttrs<
    aarch64_vmsa::attrs::SinglePrivilegeTablePermissionLimits,
    (),
    aarch64_vmsa::attrs::SemanticVmsa64Stage1TableControls,
> {
    use aarch64_vmsa::attrs::{
        DataAccess, SemanticStage1TableAttrs, SemanticVmsa64Stage1TableControls,
        SinglePrivilegeTablePermissionLimits,
    };
    SemanticStage1TableAttrs {
        permission_limits: SinglePrivilegeTablePermissionLimits {
            data_limit: DataAccess::ReadWrite,
            execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    }
}

fn codec_case(pas: aarch64_vmsa::attrs::RootExtendedPa) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::AttributeCodec;
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::RootEl3Stage1;
    let config = config();
    let leaf = leaf(pas);
    let table = table();
    let (ns, nse) = match pas {
        aarch64_vmsa::attrs::RootExtendedPa::Secure => (false, false),
        aarch64_vmsa::attrs::RootExtendedPa::NonSecure => (true, false),
        aarch64_vmsa::attrs::RootExtendedPa::Root => (false, true),
        aarch64_vmsa::attrs::RootExtendedPa::Realm => (true, true),
    };
    let leaf_ok = <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        leaf,
    )
    .and_then(|raw| {
        if raw.ns != ns || raw.alias_bit != nse {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    }) == Ok(leaf);
    let table_ok = <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::encode_table(
        &config,
        Level::L2,
        table,
    )
    .and_then(|raw| {
        if raw.ns_table {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_table(
            &config,
            Level::L2,
            raw,
        )
    }) == Ok(table);
    if leaf_ok && table_ok {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

fn active_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    pas: aarch64_vmsa::attrs::RootExtendedPa,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };
    const ADDRESS: u64 = 0x6d00_0000;
    const VALUE: u64 = 0x524f_4f54_5041_5353;
    let backing_pas = match pas {
        aarch64_vmsa::attrs::RootExtendedPa::Secure => {
            vmsa_test_harness::PhysicalAddressSpace::Secure
        }
        aarch64_vmsa::attrs::RootExtendedPa::NonSecure => {
            vmsa_test_harness::PhysicalAddressSpace::NonSecure
        }
        aarch64_vmsa::attrs::RootExtendedPa::Root => vmsa_test_harness::PhysicalAddressSpace::Root,
        aarch64_vmsa::attrs::RootExtendedPa::Realm => {
            vmsa_test_harness::PhysicalAddressSpace::Realm
        }
    };
    let page = context.allocate_page_in(backing_pas)?;
    let seeded = context.write_u64(page.virtual_address() as u64, VALUE);
    if !matches!(seeded, vmsa_test_harness::AccessResult::Completed { .. }) {
        return vmsa_test_harness::expect_completed(seeded);
    }
    let config = config();
    let leaf = leaf(pas);
    let table = table();
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
    let result = vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE);
    live.restore()?;
    result
}

fn delegated_realm_case(
    context: &mut TestContext<'_, CurrentEnvironment>,
    pas: aarch64_vmsa::attrs::RootExtendedPa,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Granule, LookupLevel, PhysicalAddress, TranslationFormat, TranslationSetup,
        TranslationStage,
    };
    const ADDRESS: u64 = 0x6d10_0000;
    const VALUE: u64 = 0x5245_414c_4d50_4153;
    let page = context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::DelegatedRealm)?;
    let config = config();
    let leaf = leaf(pas);
    let table = table();
    let capabilities = context.capabilities();
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
            input_bits: AddressBits::new(capabilities.va_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            output_bits: AddressBits::new(capabilities.pa_bits.min(48))
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
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
    let result = if pas == aarch64_vmsa::attrs::RootExtendedPa::Realm {
        let write = vmsa_test_harness::expect_completed(context.write_u64(ADDRESS, VALUE));
        if matches!(write, TestResult::Pass) {
            vmsa_test_harness::expect_value(context.read_u64(ADDRESS), VALUE)
        } else {
            write
        }
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

pub(super) fn delegated_realm_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    delegated_realm_case(context, aarch64_vmsa::attrs::RootExtendedPa::Realm)
}

pub(super) fn delegated_realm_secure_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    delegated_realm_case(context, aarch64_vmsa::attrs::RootExtendedPa::Secure)
}

pub(super) fn delegated_realm_non_secure_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    delegated_realm_case(context, aarch64_vmsa::attrs::RootExtendedPa::NonSecure)
}

pub(super) fn delegated_realm_root_fault(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    delegated_realm_case(context, aarch64_vmsa::attrs::RootExtendedPa::Root)
}

pub(super) fn unavailable_firmware_shared_pool_rejected(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    if context.allocate_page_in(vmsa_test_harness::PhysicalAddressSpace::FirmwareShared)
        == Err(vmsa_test_harness::HarnessError::InvalidState)
    {
        TestResult::Pass
    } else {
        vmsa_test_harness::HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
        .into()
    }
}

macro_rules! cases {
    ($(($codec:ident, $active:ident, $pas:ident)),* $(,)?) => {
        $(
            pub(super) fn $codec(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
                codec_case(aarch64_vmsa::attrs::RootExtendedPa::$pas)
            }
            pub(super) fn $active(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
                active_case(context, aarch64_vmsa::attrs::RootExtendedPa::$pas)
            }
        )*
    };
}

cases!(
    (root_stage1_secure, root_stage1_secure_access, Secure),
    (
        root_stage1_non_secure,
        root_stage1_non_secure_access,
        NonSecure
    ),
    (root_stage1_root, root_stage1_root_access, Root),
    (root_stage1_realm, root_stage1_realm_access, Realm),
);
