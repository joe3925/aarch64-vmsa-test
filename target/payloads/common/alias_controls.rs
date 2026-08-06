use crate::CurrentEnvironment;
use vmsa_test_harness::{TestContext, TestResult};

fn result(failed: bool) -> TestResult {
    if failed {
        vmsa_test_harness::HarnessError::CrateBehavior { expected: 1, actual: 0 }.into()
    } else {
        TestResult::Pass
    }
}

fn config(alias: aarch64_vmsa::attrs::D128Stage1AliasKind) -> aarch64_vmsa::attrs::LiveVmsaConfig {
    use aarch64_vmsa::attrs::{
        LiveVmsaConfig, Shareability, Stage1PermissionRegisterPair, Stage1PermissionRegisters,
        Stage2MemoryMode,
    };
    let pair = Stage1PermissionRegisterPair {
        base: 0xcccc_cccc_cccc_ccca,
        overlay: None,
    };
    LiveVmsaConfig {
        mair: 0x44,
        mair2: None,
        stage1_permissions: Some(Stage1PermissionRegisters {
            privileged: pair,
            unprivileged: Some(pair),
            gcs_implemented: false,
        }),
        stage2_permissions: None,
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: alias,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    }
}

fn vmsa64_controls(global: bool) -> aarch64_vmsa::attrs::SemanticVmsa64Stage1LeafControls {
    use aarch64_vmsa::attrs::{
        DirtyBitManagement, SemanticVmsa64Stage1LeafControls, Shareability, SoftwareMetadata,
    };
    SemanticVmsa64Stage1LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        global,
        dirty_management: DirtyBitManagement::SoftwareManaged,
        contiguous: false,
        guarded: false,
        software: SoftwareMetadata::new(0),
    }
}

fn memory() -> aarch64_vmsa::attrs::MemoryAttributes {
    aarch64_vmsa::attrs::MemoryAttributes::Normal {
        inner: aarch64_vmsa::attrs::Cacheability::NonCacheable,
        outer: aarch64_vmsa::attrs::Cacheability::NonCacheable,
    }
}

fn vmsa64_two_privilege(global: bool) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, TwoPrivilegeLeafPermissions,
        };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::NonSecureEl1Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: TwoPrivilegeLeafPermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::ReadWrite,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        pas: (),
        controls: vmsa64_controls(global),
    };
    let raw = <Vmsa64 as AttributeCodec<NonSecureEl1Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, Level::L3, leaf);
    let decoded = raw.and_then(|raw| {
        if raw.alias_bit != !global {
            return Err(aarch64_vmsa::attrs::AttrError::ConflictingSemanticAttributes);
        }
        <Vmsa64 as AttributeCodec<NonSecureEl1Stage1,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, Level::L3, raw)
    });
    result(decoded != Ok(leaf))
}

pub(super) fn vmsa64_global(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_two_privilege(true)
}

pub(super) fn vmsa64_non_global(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_two_privilege(false)
}

pub(super) fn vmsa64_single_non_global_conflict(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttrError, AttributeCodec, DataAccess, SemanticStage1LeafAttrs,
        SinglePrivilegeLeafPermissions, };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadOnly,
            execute: false,
        },
        pas: (),
        controls: vmsa64_controls(false),
    };
    result(
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1,
            Granule4KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, leaf)
            != Err(AttrError::ConflictingSemanticAttributes),
    )
}

fn root_pas_bits(pas: aarch64_vmsa::attrs::RootExtendedPa) -> (bool, bool) {
    use aarch64_vmsa::attrs::RootExtendedPa;
    match pas {
        RootExtendedPa::Secure => (false, false),
        RootExtendedPa::NonSecure => (true, false),
        RootExtendedPa::Root => (false, true),
        RootExtendedPa::Realm => (true, true),
    }
}

fn vmsa64_root_pas(pas: aarch64_vmsa::attrs::RootExtendedPa) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, SinglePrivilegeLeafPermissions,
        };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::RootEl3Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonSecureExtension);
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadOnly,
            execute: false,
        },
        pas,
        controls: vmsa64_controls(true),
    };
    let (ns, nse) = root_pas_bits(pas);
    let raw =
        <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::resolve_leaf(
            &config,
            Level::L3,
            leaf,
        );
    let decoded = raw.and_then(|raw| {
        if raw.ns != ns || raw.alias_bit != nse {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidOutputAddressSpace);
        }
        <Vmsa64 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    });
    result(decoded != Ok(leaf))
}

macro_rules! root_pas_cases {
    ($secure:ident, $non_secure:ident, $root:ident, $realm:ident, $helper:ident) => {
        pub(super) fn $secure(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(aarch64_vmsa::attrs::RootExtendedPa::Secure)
        }
        pub(super) fn $non_secure(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(aarch64_vmsa::attrs::RootExtendedPa::NonSecure)
        }
        pub(super) fn $root(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(aarch64_vmsa::attrs::RootExtendedPa::Root)
        }
        pub(super) fn $realm(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            $helper(aarch64_vmsa::attrs::RootExtendedPa::Realm)
        }
    };
}

root_pas_cases!(
    vmsa64_root_secure,
    vmsa64_root_non_secure,
    vmsa64_root_root,
    vmsa64_root_realm,
    vmsa64_root_pas
);

fn d128_controls(global: bool) -> aarch64_vmsa::attrs::SemanticVmsa128Stage1LeafControls {
    use aarch64_vmsa::attrs::{
        DirtyState, SemanticVmsa128Stage1LeafControls, Shareability, SoftwareMetadata,
    };
    SemanticVmsa128Stage1LeafControls {
        bbm_nt: false,
        dirty_state: DirtyState::Clean,
        shareability: Shareability::InnerShareable,
        access_flag: true,
        global,
        contiguous: false,
        guarded: false,
        protected: false,
        software: SoftwareMetadata::new(0),
    }
}

fn effective_permissions() -> aarch64_vmsa::attrs::Stage1EffectivePermissions {
    use aarch64_vmsa::attrs::{DataAccess, Stage1EffectivePermissions};
    Stage1EffectivePermissions {
        privileged_data: DataAccess::ReadWrite,
        unprivileged_data: DataAccess::ReadWrite,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    }
}

fn d128_two_privilege(global: bool) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{AttributeCodec, SemanticStage1LeafAttrs, };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::NonSecureEl1Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: effective_permissions(),
        pas: (),
        controls: d128_controls(global),
    };
    let raw = <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, Level::L3, leaf);
    let decoded = raw.and_then(|raw| {
        if raw.alias_bit != !global {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Alias);
        }
        <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, Level::L3, raw)
    });
    result(decoded != Ok(leaf))
}

pub(super) fn d128_global(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_two_privilege(true)
}

pub(super) fn d128_non_global(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_two_privilege(false)
}

pub(super) fn d128_wrong_non_secure_extension_mode(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttrError, AttributeCodec, SemanticStage1LeafAttrs, };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::NonSecureEl1Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonSecureExtension);
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: effective_permissions(),
        pas: (),
        controls: d128_controls(true),
    };
    result(
        <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
            Granule4KiB,
            _,
        >>::resolve_leaf(&config, Level::L3, leaf)
            != Err(AttrError::InvalidD128Alias),
    )
}

fn d128_root_pas(pas: aarch64_vmsa::attrs::RootExtendedPa) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{AttributeCodec, SemanticStage1LeafAttrs, };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::RootEl3Stage1;
    let mut config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonSecureExtension);
    config.stage1_permissions = Some(aarch64_vmsa::attrs::Stage1PermissionRegisters {
        privileged: aarch64_vmsa::attrs::Stage1PermissionRegisterPair {
            base: 0x5555_5555_5555_5555,
            overlay: Some(0x1111_1111_1111_1111),
        },
        unprivileged: None,
        gcs_implemented: false,
    });
    let permissions = aarch64_vmsa::attrs::Stage1EffectivePermissions {
        privileged_data: aarch64_vmsa::attrs::DataAccess::ReadOnly,
        unprivileged_data: aarch64_vmsa::attrs::DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
        privileged_gcs: false,
        unprivileged_gcs: false,
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions,
        pas,
        controls: d128_controls(true),
    };
    let (ns, nse) = root_pas_bits(pas);
    let raw = <Vmsa128 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::resolve_leaf(
        &config,
        Level::L3,
        leaf,
    );
    let decoded = raw.and_then(|raw| {
        if raw.ns != ns || raw.alias_bit != nse {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Alias);
        }
        <Vmsa128 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        )
    });
    result(decoded != Ok(leaf))
}

root_pas_cases!(
    d128_root_secure,
    d128_root_non_secure,
    d128_root_root,
    d128_root_realm,
    d128_root_pas
);

pub(super) fn d128_root_wrong_non_global_mode(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttrError, AttributeCodec, DataAccess, SemanticStage1LeafAttrs, Stage1EffectivePermissions,
        };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::RootEl3Stage1;
    let mut config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    config.stage1_permissions = Some(aarch64_vmsa::attrs::Stage1PermissionRegisters {
        privileged: aarch64_vmsa::attrs::Stage1PermissionRegisterPair {
            base: 0x5555_5555_5555_5555,
            overlay: Some(0x1111_1111_1111_1111),
        },
        unprivileged: None,
        gcs_implemented: false,
    });
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadOnly,
            unprivileged_data: DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: aarch64_vmsa::attrs::RootExtendedPa::Root,
        controls: d128_controls(true),
    };
    result(
        <Vmsa128 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::resolve_leaf(
            &config,
            Level::L3,
            leaf,
        ) != Err(AttrError::InvalidD128Alias),
    )
}

pub(super) fn d128_root_non_global_conflict(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttrError, AttributeCodec, DataAccess, SemanticStage1LeafAttrs, Stage1EffectivePermissions,
        };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::RootEl3Stage1;
    let mut config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonSecureExtension);
    config.stage1_permissions = Some(aarch64_vmsa::attrs::Stage1PermissionRegisters {
        privileged: aarch64_vmsa::attrs::Stage1PermissionRegisterPair {
            base: 0x5555_5555_5555_5555,
            overlay: Some(0x1111_1111_1111_1111),
        },
        unprivileged: None,
        gcs_implemented: false,
    });
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: Stage1EffectivePermissions {
            privileged_data: DataAccess::ReadOnly,
            unprivileged_data: DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: aarch64_vmsa::attrs::RootExtendedPa::Secure,
        controls: d128_controls(false),
    };
    result(
        <Vmsa128 as AttributeCodec<RootEl3Stage1, Granule4KiB, _>>::resolve_leaf(
            &config,
            Level::L3,
            leaf,
        ) != Err(AttrError::InvalidD128Alias),
    )
}

#[derive(Clone, Copy)]
enum Vmsa64LeafControl {
    Contiguous,
    Guarded,
}

fn vmsa64_leaf_control(control: Vmsa64LeafControl) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttributeCodec, DataAccess, SemanticStage1LeafAttrs, SinglePrivilegeLeafPermissions,
        };
    use aarch64_vmsa::descriptor::Vmsa64;
    use aarch64_vmsa::regime::NonSecureEl2Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let mut controls = vmsa64_controls(true);
    match control {
        Vmsa64LeafControl::Contiguous => controls.contiguous = true,
        Vmsa64LeafControl::Guarded => controls.guarded = true,
    }
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: SinglePrivilegeLeafPermissions {
            data: DataAccess::ReadOnly,
            execute: false,
        },
        pas: (),
        controls,
    };
    let raw = <Vmsa64 as AttributeCodec<NonSecureEl2Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, Level::L3, leaf);
    let decoded = raw.and_then(|raw| {
        let set = match control {
            Vmsa64LeafControl::Contiguous => raw.contiguous,
            Vmsa64LeafControl::Guarded => raw.guarded,
        };
        if !set {
            return Err(aarch64_vmsa::attrs::AttrError::ConflictingSemanticAttributes);
        }
        <Vmsa64 as AttributeCodec<NonSecureEl2Stage1,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, Level::L3, raw)
    });
    result(decoded != Ok(leaf))
}

pub(super) fn vmsa64_contiguous(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf_control(Vmsa64LeafControl::Contiguous)
}

pub(super) fn vmsa64_guarded(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    vmsa64_leaf_control(Vmsa64LeafControl::Guarded)
}

#[derive(Clone, Copy)]
enum D128LeafControl {
    BbmNt,
    Contiguous,
    Guarded,
    Protected,
}

fn d128_leaf_control(control: D128LeafControl) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{AttributeCodec, SemanticStage1LeafAttrs, };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::NonSecureEl1Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let mut controls = d128_controls(true);
    match control {
        D128LeafControl::BbmNt => controls.bbm_nt = true,
        D128LeafControl::Contiguous => controls.contiguous = true,
        D128LeafControl::Guarded => controls.guarded = true,
        D128LeafControl::Protected => controls.protected = true,
    }
    let leaf = SemanticStage1LeafAttrs {
        memory: memory(),
        permissions: effective_permissions(),
        pas: (),
        controls,
    };
    let level = if matches!(control, D128LeafControl::BbmNt) {
        Level::L2
    } else {
        Level::L3
    };
    let raw = <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, level, leaf);
    let decoded = raw.and_then(|raw| {
        let set = match control {
            D128LeafControl::BbmNt => raw.bbm_nt,
            D128LeafControl::Contiguous => raw.contiguous,
            D128LeafControl::Guarded => raw.guarded,
            D128LeafControl::Protected => raw.protected,
        };
        if !set {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Configuration);
        }
        <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, level, raw)
    });
    result(decoded != Ok(leaf))
}

macro_rules! d128_leaf_control_cases {
    ($($name:ident => $control:ident),+ $(,)?) => {
        $(
            pub(super) fn $name(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
                d128_leaf_control(D128LeafControl::$control)
            }
        )+
    };
}

d128_leaf_control_cases!(
    d128_bbm_nt => BbmNt,
    d128_contiguous => Contiguous,
    d128_guarded => Guarded,
    d128_protected => Protected,
);

#[derive(Clone, Copy)]
enum D128TableControl {
    TableNt,
    AccessFlag,
    Disch,
    Protected,
}

fn d128_table_control(control: D128TableControl) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        AttributeCodec, SemanticVmsa128Stage1TableAttrs, SoftwareMetadata, };
    use aarch64_vmsa::descriptor::{DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::regime::NonSecureEl1Stage1;
    use aarch64_vmsa::table::{TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage1;
    let config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    let table = SemanticVmsa128Stage1TableAttrs {
        table_nt: matches!(control, D128TableControl::TableNt),
        access_flag: matches!(control, D128TableControl::AccessFlag),
        disch: matches!(control, D128TableControl::Disch),
        protected: matches!(control, D128TableControl::Protected),
        pas: (),
        software: SoftwareMetadata::new(0),
    };
    let raw = <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
        Granule4KiB,
        _,
    >>::resolve_table(&config, Level::L1, table);
    let decoded = raw.and_then(|raw| {
        let set = match control {
            D128TableControl::TableNt => raw.table_nt,
            D128TableControl::AccessFlag => raw.access_flag,
            D128TableControl::Disch => raw.disch,
            D128TableControl::Protected => raw.protected,
        };
        if !set {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Configuration);
        }
        if matches!(control, D128TableControl::TableNt) {
            type Layout = <Vmsa128 as HasLayout<Stage1, Granule4KiB>>::Layout;
            let transition = TableTransition::new(
                TableShape::<Vmsa128, Granule4KiB>::root(Level::L0),
                TableShape::<Vmsa128, Granule4KiB>::new(Level::L2, 2)
                    .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?,
            )
            .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?;
            <Layout as DescriptorLayout<Stage1, Granule4KiB>>::table_descriptor(
                PhysAddr(0x4000),
                transition,
                raw,
            )
            .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?;
        }
        <Vmsa128 as AttributeCodec<NonSecureEl1Stage1,
            Granule4KiB,
            _,
        >>::decode_table(&config, Level::L1, raw)
    });
    result(decoded != Ok(table))
}

macro_rules! d128_table_control_cases {
    ($($name:ident => $control:ident),+ $(,)?) => {
        $(
            pub(super) fn $name(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
                d128_table_control(D128TableControl::$control)
            }
        )+
    };
}

d128_table_control_cases!(
    d128_table_nt => TableNt,
    d128_table_access_flag => AccessFlag,
    d128_table_disch => Disch,
    d128_table_protected => Protected,
);

fn d128_stage2_config() -> aarch64_vmsa::attrs::LiveVmsaConfig {
    let mut config = config(aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal);
    config.stage2_permissions = Some(aarch64_vmsa::attrs::Stage2PermissionRegisters {
        s2pir_el2: 0x0000_0000_0000_fb8c,
        s2por_el1: None,
    });
    config
}

#[derive(Clone, Copy)]
enum D128Stage2LeafControl {
    ForceNoExecute,
    Contiguous,
    AssuredOnly,
    BbmNt,
}

fn d128_stage2_leaf_control(control: D128Stage2LeafControl) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level};
    use aarch64_vmsa::attrs::{
        AttributeCodec, DirtyState, SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        Shareability, SoftwareMetadata, Stage2MemoryAttributes, Stage2Permission,
        Stage2Permissions, };
    use aarch64_vmsa::descriptor::Vmsa128;
    use aarch64_vmsa::regime::NonSecureEl2Stage2;
    let config = d128_stage2_config();
    let mut controls = SemanticVmsa128Stage2LeafControls {
        bbm_nt: false,
        dirty_state: DirtyState::Clean,
        shareability: Shareability::InnerShareable,
        access_flag: true,
        force_no_execute: false,
        contiguous: false,
        assured_only: false,
        software: SoftwareMetadata::new(0),
    };
    match control {
        D128Stage2LeafControl::ForceNoExecute => controls.force_no_execute = true,
        D128Stage2LeafControl::Contiguous => controls.contiguous = true,
        D128Stage2LeafControl::AssuredOnly => controls.assured_only = true,
        D128Stage2LeafControl::BbmNt => controls.bbm_nt = true,
    }
    let leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(memory()),
        permissions: Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: (),
        controls,
    };
    let level = if matches!(control, D128Stage2LeafControl::BbmNt) {
        Level::L2
    } else {
        Level::L3
    };
    let raw = <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::resolve_leaf(&config, level, leaf);
    let decoded = raw.and_then(|raw| {
        let set = match control {
            D128Stage2LeafControl::ForceNoExecute => raw.force_no_execute,
            D128Stage2LeafControl::Contiguous => raw.contiguous,
            D128Stage2LeafControl::AssuredOnly => raw.assured_only,
            D128Stage2LeafControl::BbmNt => raw.bbm_nt,
        };
        if !set {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Configuration);
        }
        <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
            Granule4KiB,
            _,
        >>::decode_leaf(&config, level, raw)
    });
    result(decoded != Ok(leaf))
}

macro_rules! d128_stage2_leaf_control_cases {
    ($($name:ident => $control:ident),+ $(,)?) => {
        $(
            pub(super) fn $name(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
                d128_stage2_leaf_control(D128Stage2LeafControl::$control)
            }
        )+
    };
}

d128_stage2_leaf_control_cases!(
    d128_stage2_force_no_execute => ForceNoExecute,
    d128_stage2_contiguous => Contiguous,
    d128_stage2_assured_only => AssuredOnly,
    d128_stage2_bbm_nt => BbmNt,
);

#[derive(Clone, Copy)]
enum D128Stage2TableControl {
    TableNt,
    AccessFlag,
}

fn d128_stage2_table_control(control: D128Stage2TableControl) -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        AttributeCodec, SemanticVmsa128Stage2TableAttrs, SoftwareMetadata, Stage2Permissions,
        };
    use aarch64_vmsa::descriptor::{DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::regime::NonSecureEl2Stage2;
    use aarch64_vmsa::table::{TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage2;
    let config = d128_stage2_config();
    let table = SemanticVmsa128Stage2TableAttrs {
        table_nt: matches!(control, D128Stage2TableControl::TableNt),
        access_flag: matches!(control, D128Stage2TableControl::AccessFlag),
        software: SoftwareMetadata::new(0),
    };
    let raw = <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
        Granule4KiB,
        _,
    >>::resolve_table(&config, Level::L1, table);
    let decoded = raw.and_then(|raw| {
        let set = match control {
            D128Stage2TableControl::TableNt => raw.table_nt,
            D128Stage2TableControl::AccessFlag => raw.access_flag,
        };
        if !set {
            return Err(aarch64_vmsa::attrs::AttrError::InvalidD128Configuration);
        }
        if matches!(control, D128Stage2TableControl::TableNt) {
            type Layout = <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout;
            let transition = TableTransition::new(
                TableShape::<Vmsa128, Granule4KiB>::root(Level::L0),
                TableShape::<Vmsa128, Granule4KiB>::new(Level::L2, 2)
                    .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?,
            )
            .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?;
            <Layout as DescriptorLayout<Stage2, Granule4KiB>>::table_descriptor(
                PhysAddr(0x4000),
                transition,
                raw,
            )
            .map_err(|_| aarch64_vmsa::attrs::AttrError::InvalidD128Configuration)?;
        }
        <Vmsa128 as AttributeCodec<NonSecureEl2Stage2<Stage2Permissions>,
            Granule4KiB,
            _,
        >>::decode_table(&config, Level::L1, raw)
    });
    result(decoded != Ok(table))
}

pub(super) fn d128_stage2_table_nt(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    d128_stage2_table_control(D128Stage2TableControl::TableNt)
}

pub(super) fn d128_stage2_table_access_flag(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    d128_stage2_table_control(D128Stage2TableControl::AccessFlag)
}
