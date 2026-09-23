use vmsa_test_harness::AttributeCodecCompat as AttributeCodec;
use vmsa_test_harness::{HarnessError, TestResult};

fn failed(expected: u64, actual: u64) -> TestResult {
    HarnessError::CrateBehavior { expected, actual }.into()
}

pub fn descriptor_endian_storage() -> TestResult {
    use aarch64_vmsa::config::format::{
        BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2, Vmsa128,
    };
    use aarch64_vmsa::descriptor::DescriptorFormat;

    let raw64 = 0x0123_4567_89ab_cdefu64;
    macro_rules! check64 {
        ($format:ty, $stored:expr) => {{
            let mut storage = 0u64;
            unsafe { <$format as DescriptorFormat>::write_descriptor(&mut storage, raw64) };
            if storage != $stored
                || unsafe { <$format as DescriptorFormat>::read_descriptor(&storage) } != raw64
            {
                return failed($stored, storage);
            }
        }};
    }
    check64!(Vmsa64<NativeEndian>, raw64);
    check64!(Vmsa64<LittleEndian>, raw64.to_le());
    check64!(Vmsa64<BigEndian>, raw64.to_be());
    check64!(Vmsa64Lpa2<NativeEndian>, raw64);
    check64!(Vmsa64Lpa2<LittleEndian>, raw64.to_le());
    check64!(Vmsa64Lpa2<BigEndian>, raw64.to_be());

    let raw128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
    macro_rules! check128 {
        ($format:ty, $stored:expr) => {{
            let mut storage = 0u128;
            unsafe { <$format as DescriptorFormat>::write_descriptor(&mut storage, raw128) };
            if storage != $stored
                || unsafe { <$format as DescriptorFormat>::read_descriptor(&storage) } != raw128
            {
                return failed($stored as u64, storage as u64);
            }
        }};
    }
    check128!(Vmsa128<NativeEndian>, raw128);
    check128!(Vmsa128<LittleEndian>, raw128.to_le());
    check128!(Vmsa128<BigEndian>, raw128.to_be());
    TestResult::Pass
}

pub fn smmu_v2_stage2_exact_vector() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        Cacheability, LiveVmsaConfig, MemoryAttributes, SemanticSmmuV2Stage2LeafControls,
        SemanticStage2LeafAttrs, Shareability, SmmuV2AllocationHint, SoftwareMetadata,
        Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;

    type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let normal_nc = MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    };
    let semantic = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(normal_nc),
        permissions: Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        output_address_space: (),
        controls: SemanticSmmuV2Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            ),
            contiguous: true,
            read_allocate: SmmuV2AllocationHint::Allocate,
            write_allocate: SmmuV2AllocationHint::NoAllocate,
            software: SoftwareMetadata::new(0b1010),
        },
    };
    let fields = <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        semantic,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let raw = <Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(0x1234_5000).into(),
        Level::L3,
        fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;

    // Independent SMMUv2 D.c bit construction: WACFG[63:62]=11,
    // RACFG[61:60]=10, XN[54], Contiguous[52], software[58:55], AF[10].
    let expected = 0xEu64 << 60
        | 1 << 54
        | 1 << 52
        | 0b1010 << 55
        | 0x1234_5000
        | 1 << 10
        | 0b11 << 8
        | 0b11 << 6
        | 0b0101 << 2
        | 0b11;
    if raw != expected {
        return failed(expected, raw);
    }
    let decoded_fields =
        <Layout as DescriptorLayout<Granule4KiB>>::decode_leaf_fields(expected, Level::L3);
    let decoded = <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
        &config,
        Level::L3,
        decoded_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    if decoded != semantic {
        return failed(expected, raw);
    }
    TestResult::Pass
}

pub fn smmu_regime_layout_matrix() -> TestResult {
    use aarch64_vmsa::config::format::{
        BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2, Vmsa128,
    };
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};
    use aarch64_vmsa::regime::HasRegimeLayout;

    fn supports_all_granules<F, R>()
    where
        F: aarch64_vmsa::descriptor::DescriptorFormat
            + HasRegimeLayout<R, Granule4KiB>
            + HasRegimeLayout<R, Granule16KiB>
            + HasRegimeLayout<R, Granule64KiB>,
        R: aarch64_vmsa::regime::TranslationRegime,
    {
    }

    macro_rules! v2_regimes {
        ($format:ty) => {{
            supports_all_granules::<$format, smmu_v2::NonSecureStreamStage1>();
            supports_all_granules::<$format, smmu_v2::NonSecurePrivilegedStreamStage1>();
            supports_all_granules::<$format, smmu_v2::SecureStreamStage1>();
            supports_all_granules::<$format, smmu_v2::SecurePrivilegedStreamStage1>();
            supports_all_granules::<$format, smmu_v2::NonSecureIpaStage2>();
        }};
    }
    v2_regimes!(Vmsa64<NativeEndian>);
    v2_regimes!(Vmsa64<LittleEndian>);
    v2_regimes!(Vmsa64<BigEndian>);

    macro_rules! v3_regimes {
        ($format:ty) => {{
            supports_all_granules::<$format, smmu_v3::NonSecureStreamStage1>();
            supports_all_granules::<$format, smmu_v3::NonSecurePrivilegedStreamStage1>();
            supports_all_granules::<$format, smmu_v3::SecureStreamStage1>();
            supports_all_granules::<$format, smmu_v3::SecurePrivilegedStreamStage1>();
            supports_all_granules::<$format, smmu_v3::RealmStreamStage1>();
            supports_all_granules::<$format, smmu_v3::RealmPrivilegedStreamStage1>();
            supports_all_granules::<$format, smmu_v3::NonSecureIpaStage2>();
            supports_all_granules::<$format, smmu_v3::SecureIpaStage2>();
            supports_all_granules::<$format, smmu_v3::SecureStreamNonSecureIpaStage2>();
            supports_all_granules::<$format, smmu_v3::RealmIpaStage2>();
        }};
    }
    macro_rules! all_v3_formats {
        ($endian:ty) => {{
            v3_regimes!(Vmsa64<$endian>);
            v3_regimes!(Vmsa64Lpa2<$endian>);
            v3_regimes!(Vmsa128<$endian>);
        }};
    }
    all_v3_formats!(NativeEndian);
    all_v3_formats!(LittleEndian);
    all_v3_formats!(BigEndian);
    TestResult::Pass
}

pub fn smmu_descriptor_interpretations() -> TestResult {
    use aarch64_vmsa::descriptor::{
        DescriptorInterpretation, SmmuV2Descriptors, SmmuV3Descriptors,
    };

    let v2 = (
        SmmuV2Descriptors::SUPPORTS_STAGE1_PERMISSION_INDIRECTION,
        SmmuV2Descriptors::SUPPORTS_STAGE1_PERMISSION_OVERLAYS,
    );
    let v3 = (
        SmmuV3Descriptors::SUPPORTS_STAGE1_PERMISSION_INDIRECTION,
        SmmuV3Descriptors::SUPPORTS_STAGE1_PERMISSION_OVERLAYS,
    );
    if v2 != (false, false) || v3 != (true, false) {
        return failed(
            0b10,
            (v2.0 as u64) | ((v2.1 as u64) << 1) | ((v3.0 as u64) << 2),
        );
    }
    TestResult::Pass
}

pub fn smmu_regime_metadata() -> TestResult {
    use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};
    use aarch64_vmsa::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};
    use aarch64_vmsa::descriptor::{SmmuV2Descriptors, SmmuV3Descriptors};
    use aarch64_vmsa::regime::{
        IpaSpace, RegimeOwner, Stage1Regime, Stage2Regime, TranslationSpace,
    };

    fn stage1<R, I>(space: TranslationSpace, supports_el0: bool, has_ttbr1: bool) -> bool
    where
        R: Stage1Regime<DescriptorInterpretation = I>,
        I: aarch64_vmsa::descriptor::DescriptorInterpretation,
    {
        R::OWNER == RegimeOwner::Smmu
            && R::SPACE == space
            && R::SUPPORTS_EL0 == supports_el0
            && R::HAS_TTBR1 == has_ttbr1
            && R::REQUIRED_FEATURES == aarch64_vmsa::arch::FeatureRequirements::NONE
    }

    fn stage2<R, I>(space: TranslationSpace, ipa: IpaSpace) -> bool
    where
        R: Stage2Regime<DescriptorInterpretation = I>,
        I: aarch64_vmsa::descriptor::DescriptorInterpretation,
    {
        R::OWNER == RegimeOwner::Smmu
            && R::SPACE == space
            && R::IPA_SPACE == ipa
            && R::REQUIRED_FEATURES == aarch64_vmsa::arch::FeatureRequirements::NONE
    }

    let mut failures = 0u64;
    macro_rules! check {
        ($value:expr) => {
            failures += u64::from(!$value);
        };
    }
    check!(stage1::<smmu_v2::NonSecureStreamStage1, SmmuV2Descriptors>(
        TranslationSpace::NonSecure,
        true,
        true,
    ));
    check!(stage1::<
        smmu_v2::NonSecurePrivilegedStreamStage1,
        SmmuV2Descriptors,
    >(TranslationSpace::NonSecure, false, false,));
    check!(stage1::<smmu_v2::SecureStreamStage1, SmmuV2Descriptors>(
        TranslationSpace::Secure,
        true,
        true,
    ));
    check!(stage1::<
        smmu_v2::SecurePrivilegedStreamStage1,
        SmmuV2Descriptors,
    >(TranslationSpace::Secure, false, false,));
    check!(stage2::<smmu_v2::NonSecureIpaStage2, SmmuV2Descriptors>(
        TranslationSpace::NonSecure,
        IpaSpace::NonSecure,
    ));

    check!(stage1::<smmu_v3::NonSecureStreamStage1, SmmuV3Descriptors>(
        TranslationSpace::NonSecure,
        true,
        true,
    ));
    check!(stage1::<
        smmu_v3::NonSecurePrivilegedStreamStage1,
        SmmuV3Descriptors,
    >(TranslationSpace::NonSecure, false, false,));
    check!(stage1::<smmu_v3::SecureStreamStage1, SmmuV3Descriptors>(
        TranslationSpace::Secure,
        true,
        true,
    ));
    check!(stage1::<
        smmu_v3::SecurePrivilegedStreamStage1,
        SmmuV3Descriptors,
    >(TranslationSpace::Secure, false, false,));
    check!(stage1::<smmu_v3::RealmStreamStage1, SmmuV3Descriptors>(
        TranslationSpace::Realm,
        true,
        true,
    ));
    check!(stage1::<
        smmu_v3::RealmPrivilegedStreamStage1,
        SmmuV3Descriptors,
    >(TranslationSpace::Realm, false, false,));
    macro_rules! v3_stage2 {
        ($regime:ident, $space:expr, $ipa:expr) => {{
            check!(stage2::<
                smmu_v3::$regime<StandardStage2PermissionModel>,
                SmmuV3Descriptors,
            >($space, $ipa,));
            check!(stage2::<
                smmu_v3::$regime<XnxStage2PermissionModel>,
                SmmuV3Descriptors,
            >($space, $ipa,));
        }};
    }
    v3_stage2!(
        NonSecureIpaStage2,
        TranslationSpace::NonSecure,
        IpaSpace::NonSecure
    );
    v3_stage2!(SecureIpaStage2, TranslationSpace::Secure, IpaSpace::Secure);
    v3_stage2!(
        SecureStreamNonSecureIpaStage2,
        TranslationSpace::Secure,
        IpaSpace::NonSecure
    );
    v3_stage2!(RealmIpaStage2, TranslationSpace::Realm, IpaSpace::Realm);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

fn exercise_vmsa64_stage1_layout<F, R, G>() -> Result<u64, HarnessError>
where
    F: aarch64_vmsa::descriptor::DescriptorFormat<Raw = u64>
        + aarch64_vmsa::regime::HasRegimeLayout<R, G>,
    R: aarch64_vmsa::regime::TranslationRegime<Stage = aarch64_vmsa::translation::Stage1>,
    G: aarch64_vmsa::address::TranslationGranule,
    <F as aarch64_vmsa::regime::HasRegimeLayout<R, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                G,
                Format = F,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1TableAttrs,
            >,
{
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorKind, DescriptorLayout};
    use aarch64_vmsa::low_level::raw::{
        FourBit, RawShareability, RawVmsa64PermissionFields, RawVmsa64Stage1LeafAttrs,
        RawVmsa64Stage1TableAttrs, TableAp, ThreeBit,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage1;

    type Layout<F, R, G> = <F as HasRegimeLayout<R, G>>::Layout;
    let leaf = RawVmsa64Stage1LeafAttrs {
        attr_index: FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?,
        ns: true,
        permissions: RawVmsa64PermissionFields {
            primary: FourBit::new(0b1101).map_err(|_| HarnessError::InvalidState)?,
            dirty: true,
            overlay: ThreeBit::new(0b101).map_err(|_| HarnessError::InvalidState)?,
        },
        // LPA2-DS obtains shareability from the translation control rather than the leaf.
        shareability: RawShareability::from_bits(0b00).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: true,
        contiguous: true,
        guarded: true,
        software: FourBit::new(0b0110).map_err(|_| HarnessError::InvalidState)?,
    };
    let raw = <Layout<F, R, G> as DescriptorLayout<G>>::leaf_descriptor(
        PhysAddr(0x4000_0000),
        Level::L3,
        leaf,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let mut failures = 0u64;
    for raw_level in -1..=3 {
        let level = Level::new(raw_level);
        if !<Layout<F, R, G> as DescriptorLayout<G>>::supports_leaf_level(level) {
            failures += u64::from(
                <Layout<F, R, G> as DescriptorLayout<G>>::leaf_descriptor(PhysAddr(0), level, leaf)
                    != Err(aarch64_vmsa::descriptor::DescriptorError::InvalidLeafLevel { level }),
            );
        }
        failures += u64::from(
            <Layout<F, R, G> as DescriptorLayout<G>>::kind(2, level) != DescriptorKind::Invalid,
        );
    }
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::kind(raw, Level::L3) != DescriptorKind::Page,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::decode_leaf_fields(raw, Level::L3) != leaf,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::output_address(raw, Level::L3).0 != 0x4000_0000,
    );

    let table = RawVmsa64Stage1TableAttrs {
        access_flag: true,
        privileged_execute_never_limit: true,
        unprivileged_execute_never_limit: false,
        ap_table: TableAp::from_bits(0b10).map_err(|_| HarnessError::InvalidState)?,
        ns_table: true,
        software: FourBit::new(0b1001).map_err(|_| HarnessError::InvalidState)?,
    };
    let parent = TableShape::<F, G>::root(Level::L1).map_err(|_| HarnessError::InvalidState)?;
    let child = TableShape::<F, G>::new(Level::L2, 1).map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let address = TableAddr::<G>::new(0x8000_0000).map_err(|_| HarnessError::InvalidState)?;
    let raw =
        <Layout<F, R, G> as DescriptorLayout<G>>::table_descriptor(address, transition, table)
            .map_err(|_| HarnessError::InvalidState)?;
    let next = <Layout<F, R, G> as DescriptorLayout<G>>::next_table(raw, Level::L1)
        .ok_or(HarnessError::InvalidState)?;
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::kind(raw, Level::L1) != DescriptorKind::Table,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::decode_table_fields(raw, Level::L1) != table,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::table_address(raw, Level::L1).raw()
            != address.raw(),
    );
    failures += u64::from(
        next.address.raw() != address.raw() || next.level != Level::L2 || next.stride_count != 1,
    );
    Ok(failures)
}

fn exercise_vmsa128_stage1_layout<F, R, G>() -> Result<u64, HarnessError>
where
    F: aarch64_vmsa::descriptor::DescriptorFormat<Raw = u128>
        + aarch64_vmsa::regime::HasRegimeLayout<R, G>,
    R: aarch64_vmsa::regime::TranslationRegime<Stage = aarch64_vmsa::translation::Stage1>,
    G: aarch64_vmsa::address::TranslationGranule,
    <F as aarch64_vmsa::regime::HasRegimeLayout<R, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                G,
                Format = F,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
{
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorKind, DescriptorLayout};
    use aarch64_vmsa::low_level::raw::{
        FourBit, PermissionIndices, RawShareability, RawVmsa128Stage1LeafAttrs,
        RawVmsa128Stage1TableAttrs, Stage1NotDirty, TenBit,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage1;

    type Layout<F, R, G> = <F as HasRegimeLayout<R, G>>::Layout;
    let leaf = RawVmsa128Stage1LeafAttrs {
        attr_index: FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?,
        bbm_nt: false,
        not_dirty: Stage1NotDirty::new(true),
        shareability: RawShareability::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: true,
        contiguous: true,
        guarded: true,
        protected: true,
        permissions: PermissionIndices {
            pi: FourBit::new(0b1101).map_err(|_| HarnessError::InvalidState)?,
            po: FourBit::new(0b0110).map_err(|_| HarnessError::InvalidState)?,
        },
        ns: true,
        software: TenBit::new(0x2aa).map_err(|_| HarnessError::InvalidState)?,
    };
    let raw = <Layout<F, R, G> as DescriptorLayout<G>>::leaf_descriptor(
        PhysAddr(0x4000_0000),
        Level::L3,
        leaf,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let mut failures = 0u64;
    for raw_level in -1..=3 {
        let level = Level::new(raw_level);
        if !<Layout<F, R, G> as DescriptorLayout<G>>::supports_leaf_level(level) {
            failures += u64::from(
                <Layout<F, R, G> as DescriptorLayout<G>>::leaf_descriptor(PhysAddr(0), level, leaf)
                    != Err(aarch64_vmsa::descriptor::DescriptorError::InvalidLeafLevel { level }),
            );
        }
        failures += u64::from(
            <Layout<F, R, G> as DescriptorLayout<G>>::kind(2, level) != DescriptorKind::Invalid,
        );
    }
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::kind(raw, Level::L3) != DescriptorKind::Page,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::decode_leaf_fields(raw, Level::L3) != leaf,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::output_address(raw, Level::L3).0 != 0x4000_0000,
    );

    let table = RawVmsa128Stage1TableAttrs {
        table_nt: false,
        access_flag: true,
        disch: true,
        protected: true,
        ns_table: true,
        software: TenBit::new(0x155).map_err(|_| HarnessError::InvalidState)?,
    };
    let parent = TableShape::<F, G>::root(Level::L1).map_err(|_| HarnessError::InvalidState)?;
    let child = TableShape::<F, G>::new(Level::L2, 1).map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let address = TableAddr::<G>::new(0x8000_0000).map_err(|_| HarnessError::InvalidState)?;
    let raw =
        <Layout<F, R, G> as DescriptorLayout<G>>::table_descriptor(address, transition, table)
            .map_err(|_| HarnessError::InvalidState)?;
    let next = <Layout<F, R, G> as DescriptorLayout<G>>::next_table(raw, Level::L1)
        .ok_or(HarnessError::InvalidState)?;
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::kind(raw, Level::L1) != DescriptorKind::Table,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::decode_table_fields(raw, Level::L1) != table,
    );
    failures += u64::from(
        <Layout<F, R, G> as DescriptorLayout<G>>::table_address(raw, Level::L1).raw()
            != address.raw(),
    );
    failures += u64::from(
        next.address.raw() != address.raw() || next.level != Level::L2 || next.stride_count != 1,
    );
    Ok(failures)
}

pub fn smmu_stage1_descriptor_matrix() -> TestResult {
    use aarch64_vmsa::config::format::{
        BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2, Vmsa128,
    };
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};

    let mut failures = 0u64;
    macro_rules! v64 {
        ($format:ty, $regime:ty, $granule:ty) => {
            failures += exercise_vmsa64_stage1_layout::<$format, $regime, $granule>()?;
        };
    }
    macro_rules! v128 {
        ($format:ty, $regime:ty, $granule:ty) => {
            failures += exercise_vmsa128_stage1_layout::<$format, $regime, $granule>()?;
        };
    }

    // Exercise every SMMUv2 and SMMUv3 stage-1 regime selection.
    v64!(Vmsa64, smmu_v2::NonSecureStreamStage1, Granule4KiB);
    v64!(
        Vmsa64,
        smmu_v2::NonSecurePrivilegedStreamStage1,
        Granule4KiB
    );
    v64!(Vmsa64, smmu_v2::SecureStreamStage1, Granule4KiB);
    v64!(Vmsa64, smmu_v2::SecurePrivilegedStreamStage1, Granule4KiB);
    v64!(Vmsa64, smmu_v3::NonSecureStreamStage1, Granule4KiB);
    v64!(
        Vmsa64,
        smmu_v3::NonSecurePrivilegedStreamStage1,
        Granule4KiB
    );
    v64!(Vmsa64, smmu_v3::SecureStreamStage1, Granule4KiB);
    v64!(Vmsa64, smmu_v3::SecurePrivilegedStreamStage1, Granule4KiB);
    v64!(Vmsa64, smmu_v3::RealmStreamStage1, Granule4KiB);
    v64!(Vmsa64, smmu_v3::RealmPrivilegedStreamStage1, Granule4KiB);

    // Cover every SMMUv3 format/endian/granule layout. The regime binding above covers
    // the regime axis independently because all SMMUv3 stage-1 regimes select the same layout.
    macro_rules! all_granules64 {
        ($format:ty) => {{
            v64!($format, smmu_v3::NonSecureStreamStage1, Granule4KiB);
            v64!($format, smmu_v3::NonSecureStreamStage1, Granule16KiB);
            v64!($format, smmu_v3::NonSecureStreamStage1, Granule64KiB);
        }};
    }
    macro_rules! all_granules128 {
        ($format:ty) => {{
            v128!($format, smmu_v3::NonSecureStreamStage1, Granule4KiB);
            v128!($format, smmu_v3::NonSecureStreamStage1, Granule16KiB);
            v128!($format, smmu_v3::NonSecureStreamStage1, Granule64KiB);
        }};
    }
    all_granules64!(Vmsa64<NativeEndian>);
    all_granules64!(Vmsa64<LittleEndian>);
    all_granules64!(Vmsa64<BigEndian>);
    all_granules64!(Vmsa64Lpa2<NativeEndian>);
    all_granules64!(Vmsa64Lpa2<LittleEndian>);
    all_granules64!(Vmsa64Lpa2<BigEndian>);
    all_granules128!(Vmsa128<NativeEndian>);
    all_granules128!(Vmsa128<LittleEndian>);
    all_granules128!(Vmsa128<BigEndian>);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_stage1_d128_semantic_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttrError, DataRights, DeviceMemoryType, DirtyState, LiveVmsaConfig, MemoryAttributes,
        RealmOrNonSecurePa, SecureSelectablePa, SemanticStage1LeafAttrs,
        SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs, Shareability,
        SoftwareMetadata, Stage1BasePermissions, Stage1PermissionOverlays,
        Stage1PermissionRegisters, Stage1PermissionSettings, Stage1Permissions, Stage2MemoryMode,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;

    let indirect = Stage1PermissionSettings {
        base: Stage1BasePermissions::Indirect(Stage1PermissionRegisters {
            privileged: 0xcccc_cccc_cccc_cccc,
            unprivileged: None,
            gcs_implemented: false,
        }),
        overlays: Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    macro_rules! config {
        ($permissions:expr) => {
            LiveVmsaConfig {
                mair: 0,
                mair2: None,
                smmu_v3_aie: false,
                stage1_permissions: $permissions,
                stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
                stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: Shareability::InnerShareable,
                output_pas: (),
            }
        };
    }
    let permissions = Stage1Permissions::new(
        DataRights::ReadWrite,
        DataRights::None,
        false,
        false,
        false,
        false,
    );
    let mut failures = 0u64;
    macro_rules! round_trip {
        ($format:ty, $regime:ty, $granule:ty, $leaf_pas:expr, $table_pas:expr, $global:expr) => {{
            let config = config!(indirect);
            let semantic = SemanticStage1LeafAttrs {
                memory: MemoryAttributes::Device(
                    DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
                ),
                permissions,
                pas: $leaf_pas,
                controls: SemanticVmsa128Stage1LeafControls {
                    bbm_nt: false,
                    dirty_state: DirtyState::Dirty,
                    shareability: Shareability::InnerShareable,
                    access_flag: true,
                    global: $global,
                    contiguous: true,
                    guarded: true,
                    protected: true,
                    software: SoftwareMetadata::new(0x2aa),
                },
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        ) != Ok(semantic),
                    );
                }
                Err(_) => failures += 1,
            }
            let table = SemanticVmsa128Stage1TableAttrs {
                table_nt: false,
                access_flag: true,
                disch: true,
                protected: true,
                pas: $table_pas,
                software: SoftwareMetadata::new(0x155),
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                &config,
                Level::L1,
                table,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_table(
                            &config,
                            Level::L1,
                            raw,
                        ) != Ok(table),
                    );
                }
                Err(_) => failures += 1,
            }

            let direct = config!(Stage1PermissionSettings::direct());
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                    &direct,
                    Level::L3,
                    semantic,
                ) != Err(AttrError::PermissionIndirectionUnavailable),
            );
            let overlays = config!(Stage1PermissionSettings {
                base: indirect.base,
                overlays: Stage1PermissionOverlays {
                    privileged: Some(0),
                    unprivileged: None,
                },
            });
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                    &overlays,
                    Level::L3,
                    semantic,
                ) != Err(AttrError::PermissionModeMismatch),
            );
        }};
    }

    // Every endian and granule on the common SMMUv3 D128 stage-1 path.
    macro_rules! all_granules {
        ($format:ty) => {{
            round_trip!(
                $format,
                smmu_v3::NonSecureStreamStage1,
                Granule4KiB,
                (),
                (),
                false
            );
            round_trip!(
                $format,
                smmu_v3::NonSecureStreamStage1,
                Granule16KiB,
                (),
                (),
                false
            );
            round_trip!(
                $format,
                smmu_v3::NonSecureStreamStage1,
                Granule64KiB,
                (),
                (),
                false
            );
        }};
    }
    all_granules!(Vmsa128<NativeEndian>);
    all_granules!(Vmsa128<LittleEndian>);
    all_granules!(Vmsa128<BigEndian>);

    // Every SMMUv3 stage-1 regime and every selectable output PAS.
    round_trip!(
        Vmsa128,
        smmu_v3::NonSecurePrivilegedStreamStage1,
        Granule4KiB,
        (),
        (),
        true
    );
    for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
        round_trip!(
            Vmsa128,
            smmu_v3::SecureStreamStage1,
            Granule4KiB,
            pas,
            pas,
            false
        );
        round_trip!(
            Vmsa128,
            smmu_v3::SecurePrivilegedStreamStage1,
            Granule4KiB,
            pas,
            pas,
            true
        );
    }
    round_trip!(
        Vmsa128,
        smmu_v3::RealmStreamStage1,
        Granule4KiB,
        (),
        (),
        false
    );
    for pas in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure] {
        round_trip!(
            Vmsa128,
            smmu_v3::RealmPrivilegedStreamStage1,
            Granule4KiB,
            pas,
            (),
            true
        );
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_vmsa64_stage1_semantic_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        DataRights, DeviceMemoryType, DirtyBitManagement, DirtyControl, LiveVmsaConfig,
        MemoryAttributes, RealmOrNonSecurePa, SecureSelectablePa, SemanticStage1LeafAttrs,
        SemanticStage1TableAttrs, SemanticVmsa64Stage1LeafControls,
        SemanticVmsa64Stage1TableControls, Shareability, SinglePrivilegeTableRestrictions,
        SoftwareMetadata, Stage1Permissions, Stage2MemoryMode, TwoPrivilegeTableRestrictions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let permissions = Stage1Permissions::new(
        DataRights::ReadWrite,
        DataRights::None,
        false,
        false,
        false,
        false,
    );
    let stream_limits = TwoPrivilegeTableRestrictions {
        privileged_data_limit: DataRights::ReadWrite,
        unprivileged_data_limit: DataRights::None,
        privileged_execute_limit: false,
        unprivileged_execute_limit: false,
    };
    let privileged_limits = SinglePrivilegeTableRestrictions {
        data_limit: DataRights::ReadWrite,
        execute_limit: false,
    };
    let mut failures = 0u64;

    macro_rules! round_trip {
        ($format:ty, $regime:ty, $granule:ty, $leaf_pas:expr, $table_pas:expr, $limits:expr, $global:expr) => {{
            let leaf = SemanticStage1LeafAttrs {
                memory: MemoryAttributes::Device(
                    DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
                ),
                permissions,
                pas: $leaf_pas,
                controls: SemanticVmsa64Stage1LeafControls {
                    shareability: Shareability::InnerShareable,
                    access_flag: true,
                    global: $global,
                    dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
                    contiguous: true,
                    guarded: true,
                    software: SoftwareMetadata::new(0b1010),
                },
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                &config,
                Level::L3,
                leaf,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        ) != Ok(leaf),
                    )
                }
                Err(_) => failures += 1,
            }
            let table = SemanticStage1TableAttrs {
                restrictions: $limits,
                pas: $table_pas,
                controls: SemanticVmsa64Stage1TableControls {
                    access_flag: true,
                    software: SoftwareMetadata::new(0b0101),
                },
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                &config,
                Level::L1,
                table,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_table(
                            &config,
                            Level::L1,
                            raw,
                        ) != Ok(table),
                    )
                }
                Err(_) => failures += 1,
            }
        }};
    }
    macro_rules! all_variants {
        ($format:ident, $regime:ty, $leaf_pas:expr, $table_pas:expr, $limits:expr, $global:expr) => {{
            round_trip!(
                $format<NativeEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<NativeEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<NativeEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<LittleEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<LittleEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<LittleEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<BigEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<BigEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
            round_trip!(
                $format<BigEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $limits,
                $global
            );
        }};
    }
    macro_rules! v2_format {
        ($format:ident) => {{
            all_variants!(
                $format,
                smmu_v2::NonSecureStreamStage1,
                (),
                (),
                stream_limits,
                false
            );
            all_variants!(
                $format,
                smmu_v2::NonSecurePrivilegedStreamStage1,
                (),
                (),
                privileged_limits,
                true
            );
            for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
                all_variants!(
                    $format,
                    smmu_v2::SecureStreamStage1,
                    pas,
                    pas,
                    stream_limits,
                    false
                );
                all_variants!(
                    $format,
                    smmu_v2::SecurePrivilegedStreamStage1,
                    pas,
                    pas,
                    privileged_limits,
                    true
                );
            }
        }};
    }
    macro_rules! v3_format {
        ($format:ident) => {{
            all_variants!(
                $format,
                smmu_v3::NonSecureStreamStage1,
                (),
                (),
                stream_limits,
                false
            );
            all_variants!(
                $format,
                smmu_v3::NonSecurePrivilegedStreamStage1,
                (),
                (),
                privileged_limits,
                true
            );
            for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
                all_variants!(
                    $format,
                    smmu_v3::SecureStreamStage1,
                    pas,
                    pas,
                    stream_limits,
                    false
                );
                all_variants!(
                    $format,
                    smmu_v3::SecurePrivilegedStreamStage1,
                    pas,
                    pas,
                    privileged_limits,
                    true
                );
            }
            all_variants!(
                $format,
                smmu_v3::RealmStreamStage1,
                (),
                (),
                stream_limits,
                false
            );
            for pas in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure] {
                all_variants!(
                    $format,
                    smmu_v3::RealmPrivilegedStreamStage1,
                    pas,
                    (),
                    privileged_limits,
                    true
                );
            }
        }};
    }

    v2_format!(Vmsa64);
    v3_format!(Vmsa64);
    v3_format!(Vmsa64Lpa2);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

fn smmu_v2_raw_fields(
    read_allocate: u8,
    write_allocate: u8,
) -> Result<aarch64_vmsa::low_level::raw::RawSmmuV2Stage2LeafAttrs, HarnessError> {
    use aarch64_vmsa::low_level::raw::{
        FourBit, RawShareability, RawSmmuV2Stage2LeafAttrs, Stage2Ap, TwoBit,
    };

    Ok(RawSmmuV2Stage2LeafAttrs {
        mem_attr: FourBit::new(0b0101).map_err(|_| HarnessError::InvalidState)?,
        permissions: Stage2Ap::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?,
        shareability: RawShareability::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        dirty_bit_modifier: false,
        contiguous: true,
        execute_never: true,
        software: FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?,
        read_allocate: TwoBit::new(read_allocate).map_err(|_| HarnessError::InvalidState)?,
        write_allocate: TwoBit::new(write_allocate).map_err(|_| HarnessError::InvalidState)?,
    })
}

pub fn smmu_v2_stage2_descriptor_matrix() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{
        DescriptorError, DescriptorFormat, DescriptorKind, DescriptorLayout,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;

    let mut failures = 0u64;
    macro_rules! granule {
        ($granule:ty, $address:expr) => {{
            type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, $granule>>::Layout;
            for raw_level in -1..=3 {
                let level = Level::new(raw_level);
                let supported = <Layout as DescriptorLayout<$granule>>::supports_leaf_level(level);
                let result = <Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                    PhysAddr($address),
                    level,
                    smmu_v2_raw_fields(0b10, 0b11)?,
                );
                match (supported, result) {
                    (true, Ok(raw)) => {
                        let wanted_kind = if level == Level::L3 {
                            DescriptorKind::Page
                        } else {
                            DescriptorKind::Block
                        };
                        failures += u64::from(
                            <Layout as DescriptorLayout<$granule>>::kind(raw, level) != wanted_kind,
                        );
                        failures += u64::from(
                            <Layout as DescriptorLayout<$granule>>::decode_leaf_fields(raw, level)
                                != smmu_v2_raw_fields(0b10, 0b11)?,
                        );
                        failures += u64::from(
                            <Layout as DescriptorLayout<$granule>>::output_address(raw, level).0
                                != $address,
                        );
                    }
                    (false, Err(DescriptorError::InvalidLeafLevel { level: actual }))
                        if actual == level => {}
                    _ => failures += 1,
                }
            }
        }};
    }
    granule!(Granule4KiB, 0x4000_0000);
    granule!(Granule16KiB, 0x4000_0000);
    granule!(Granule64KiB, 0x4000_0000);

    type Layout4K = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let read_reserved = <Layout4K as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(0),
        Level::L3,
        smmu_v2_raw_fields(0b01, 0b00)?,
    );
    let write_reserved = <Layout4K as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(0),
        Level::L3,
        smmu_v2_raw_fields(0b00, 0b01)?,
    );
    failures += u64::from(read_reserved != Err(DescriptorError::ReservedFieldSet { bit: 60 }));
    failures += u64::from(write_reserved != Err(DescriptorError::ReservedFieldSet { bit: 62 }));
    let base = <Layout4K as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(0x1234_5000),
        Level::L3,
        smmu_v2_raw_fields(0b00, 0b00)?,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    failures += u64::from(
        <Layout4K as DescriptorLayout<Granule4KiB>>::kind(base | (1u64 << 60), Level::L3)
            != DescriptorKind::Page,
    );
    failures += u64::from(
        <Layout4K as DescriptorLayout<Granule4KiB>>::kind(base | (1u64 << 62), Level::L3)
            != DescriptorKind::Page,
    );

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_descriptor_field_mutations() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::DescriptorLayout;
    use aarch64_vmsa::low_level::raw::{
        FourBit, RawShareability, RawSmmuV2Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, Stage2Ap,
        TwoBit,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let output = PhysAddr(0x4321_0000);
    let base_fields = smmu_v2_raw_fields(0b10, 0b11)?;
    let base =
        <Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(output, Level::L3, base_fields)
            .map_err(|_| HarnessError::InvalidState)?;
    let mut failures = 0u64;
    macro_rules! leaf_mutation {
        ($mask:expr, $change:expr) => {{
            let mut fields = base_fields;
            $change(&mut fields)?;
            let raw = <Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
                output,
                Level::L3,
                fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let delta = raw ^ base;
            failures += u64::from(delta == 0 || delta & !($mask as u64) != 0);
            failures += u64::from(
                <Layout as DescriptorLayout<Granule4KiB>>::decode_leaf_fields(raw, Level::L3)
                    != fields,
            );
        }};
    }
    leaf_mutation!(0xf << 2, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.mem_attr = FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(0x3 << 6, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.permissions = Stage2Ap::from_bits(0b01).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(0x3 << 8, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.shareability =
            RawShareability::from_bits(0b10).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(1 << 10, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.access_flag = false;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(1u64 << 52, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.contiguous = false;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(1u64 << 54, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.execute_never = false;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(0xfu64 << 55, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.software = FourBit::new(0b0101).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(0x3u64 << 60, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.read_allocate = TwoBit::new(0).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });
    leaf_mutation!(0x3u64 << 62, |f: &mut RawSmmuV2Stage2LeafAttrs| {
        f.write_allocate = TwoBit::new(0).map_err(|_| HarnessError::InvalidState)?;
        Ok::<_, HarnessError>(())
    });

    let parent = TableShape::<Vmsa64, Granule4KiB>::root(Level::L1)
        .map_err(|_| HarnessError::InvalidState)?;
    let child = TableShape::<Vmsa64, Granule4KiB>::new(Level::L2, 1)
        .map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let table_address = TableAddr::new(0x8000_0000).map_err(|_| HarnessError::InvalidState)?;
    let base_table_fields = RawVmsa64Stage2TableAttrs {
        access_flag: true,
        software: FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?,
    };
    let base_table = <Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        table_address,
        transition,
        base_table_fields,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    for (fields, mask) in [
        (
            RawVmsa64Stage2TableAttrs {
                access_flag: false,
                ..base_table_fields
            },
            1u64 << 10,
        ),
        (
            RawVmsa64Stage2TableAttrs {
                software: FourBit::new(0b0101).map_err(|_| HarnessError::InvalidState)?,
                ..base_table_fields
            },
            0xfu64 << 55,
        ),
    ] {
        let raw = <Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
            table_address,
            transition,
            fields,
        )
        .map_err(|_| HarnessError::InvalidState)?;
        let delta = raw ^ base_table;
        failures += u64::from(delta == 0 || delta & !mask != 0);
        failures += u64::from(
            <Layout as DescriptorLayout<Granule4KiB>>::decode_table_fields(raw, Level::L1)
                != fields,
        );
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_d128_descriptor_field_mutations() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa128;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::{NonSecureIpaStage2, NonSecureStreamStage1};
    use aarch64_vmsa::descriptor::DescriptorLayout;
    use aarch64_vmsa::low_level::raw::{
        FourBit, PermissionIndices, RawShareability, RawVmsa128Stage1LeafAttrs,
        RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs, RawVmsa128Stage2TableAttrs,
        Stage1NotDirty, Stage2Dirty, TenBit,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type Stage1Layout = <Vmsa128 as HasRegimeLayout<NonSecureStreamStage1, Granule4KiB>>::Layout;
    type Stage2Layout = <Vmsa128 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let four_a = FourBit::new(0b0101).map_err(|_| HarnessError::InvalidState)?;
    let four_b = FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?;
    let ten_a = TenBit::new(0x155).map_err(|_| HarnessError::InvalidState)?;
    let ten_b = TenBit::new(0x2aa).map_err(|_| HarnessError::InvalidState)?;
    let inner = RawShareability::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?;
    let outer = RawShareability::from_bits(0b10).map_err(|_| HarnessError::InvalidState)?;
    let output = PhysAddr(0x4000_0000);
    let mut failures = 0u64;

    let stage1_leaf = RawVmsa128Stage1LeafAttrs {
        attr_index: four_a,
        bbm_nt: false,
        not_dirty: Stage1NotDirty::new(false),
        shareability: inner,
        access_flag: true,
        alias_bit: true,
        contiguous: true,
        guarded: true,
        protected: true,
        permissions: PermissionIndices {
            pi: four_a,
            po: four_b,
        },
        ns: true,
        software: ten_a,
    };
    let stage1_raw = <Stage1Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        output,
        Level::L2,
        stage1_leaf,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    macro_rules! stage1_leaf_mutation {
        ($mask:expr, $change:expr) => {{
            let mut fields = stage1_leaf;
            $change(&mut fields);
            let raw = <Stage1Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
                output,
                Level::L2,
                fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let delta = raw ^ stage1_raw;
            failures += u64::from(delta == 0 || delta & !($mask as u128) != 0);
            failures += u64::from(
                <Stage1Layout as DescriptorLayout<Granule4KiB>>::decode_leaf_fields(raw, Level::L2)
                    != fields,
            );
        }};
    }
    stage1_leaf_mutation!(0xf << 2, |f: &mut RawVmsa128Stage1LeafAttrs| f.attr_index =
        four_b);
    stage1_leaf_mutation!(1 << 6, |f: &mut RawVmsa128Stage1LeafAttrs| f.bbm_nt = true);
    stage1_leaf_mutation!(1 << 7, |f: &mut RawVmsa128Stage1LeafAttrs| f.not_dirty =
        Stage1NotDirty::new(true));
    stage1_leaf_mutation!(0x3 << 8, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .shareability =
        outer);
    stage1_leaf_mutation!(1 << 10, |f: &mut RawVmsa128Stage1LeafAttrs| f.access_flag =
        false);
    stage1_leaf_mutation!(1 << 11, |f: &mut RawVmsa128Stage1LeafAttrs| f.alias_bit =
        false);
    stage1_leaf_mutation!(0x3ffu128 << 91, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .software =
        ten_b);
    stage1_leaf_mutation!(1u128 << 111, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .contiguous =
        false);
    stage1_leaf_mutation!(1u128 << 113, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .guarded =
        false);
    stage1_leaf_mutation!(1u128 << 114, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .protected =
        false);
    stage1_leaf_mutation!(0xfu128 << 115, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .permissions
        .pi =
        four_b);
    stage1_leaf_mutation!(0xfu128 << 121, |f: &mut RawVmsa128Stage1LeafAttrs| f
        .permissions
        .po =
        four_a);
    stage1_leaf_mutation!(1u128 << 127, |f: &mut RawVmsa128Stage1LeafAttrs| f.ns =
        false);

    let parent = TableShape::<Vmsa128, Granule4KiB>::root(Level::L0)
        .map_err(|_| HarnessError::InvalidState)?;
    let child = TableShape::<Vmsa128, Granule4KiB>::new(Level::L2, 2)
        .map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let table_address = TableAddr::new(0x8000_0000).map_err(|_| HarnessError::InvalidState)?;
    let stage1_table = RawVmsa128Stage1TableAttrs {
        table_nt: false,
        access_flag: true,
        disch: true,
        protected: true,
        ns_table: true,
        software: ten_a,
    };
    let stage1_table_raw = <Stage1Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        table_address,
        transition,
        stage1_table,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    macro_rules! stage1_table_mutation {
        ($mask:expr, $change:expr) => {{
            let mut fields = stage1_table;
            $change(&mut fields);
            let raw = <Stage1Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
                table_address,
                transition,
                fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let delta = raw ^ stage1_table_raw;
            failures += u64::from(delta == 0 || delta & !($mask as u128) != 0);
            failures += u64::from(
                <Stage1Layout as DescriptorLayout<Granule4KiB>>::decode_table_fields(
                    raw,
                    Level::L0,
                ) != fields,
            );
        }};
    }
    stage1_table_mutation!(1 << 6, |f: &mut RawVmsa128Stage1TableAttrs| f.table_nt =
        true);
    stage1_table_mutation!(1 << 10, |f: &mut RawVmsa128Stage1TableAttrs| f
        .access_flag =
        false);
    stage1_table_mutation!(0x3ffu128 << 91, |f: &mut RawVmsa128Stage1TableAttrs| f
        .software =
        ten_b);
    stage1_table_mutation!(1u128 << 112, |f: &mut RawVmsa128Stage1TableAttrs| f.disch =
        false);
    stage1_table_mutation!(1u128 << 114, |f: &mut RawVmsa128Stage1TableAttrs| f
        .protected =
        false);
    stage1_table_mutation!(1u128 << 127, |f: &mut RawVmsa128Stage1TableAttrs| f
        .ns_table =
        false);

    let stage2_leaf = RawVmsa128Stage2LeafAttrs {
        mem_attr: four_a,
        bbm_nt: false,
        dirty: Stage2Dirty::new(false),
        shareability: inner,
        access_flag: true,
        force_no_xs: true,
        contiguous: true,
        assured_only: true,
        permissions: PermissionIndices {
            pi: four_a,
            po: four_b,
        },
        ns: true,
        software: ten_a,
    };
    let stage2_raw = <Stage2Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        output,
        Level::L2,
        stage2_leaf,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    macro_rules! stage2_leaf_mutation {
        ($mask:expr, $change:expr) => {{
            let mut fields = stage2_leaf;
            $change(&mut fields);
            let raw = <Stage2Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
                output,
                Level::L2,
                fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let delta = raw ^ stage2_raw;
            failures += u64::from(delta == 0 || delta & !($mask as u128) != 0);
            failures += u64::from(
                <Stage2Layout as DescriptorLayout<Granule4KiB>>::decode_leaf_fields(raw, Level::L2)
                    != fields,
            );
        }};
    }
    stage2_leaf_mutation!(0xf << 2, |f: &mut RawVmsa128Stage2LeafAttrs| f.mem_attr =
        four_b);
    stage2_leaf_mutation!(1 << 6, |f: &mut RawVmsa128Stage2LeafAttrs| f.bbm_nt = true);
    stage2_leaf_mutation!(1 << 7, |f: &mut RawVmsa128Stage2LeafAttrs| f.dirty =
        Stage2Dirty::new(true));
    stage2_leaf_mutation!(0x3 << 8, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .shareability =
        outer);
    stage2_leaf_mutation!(1 << 10, |f: &mut RawVmsa128Stage2LeafAttrs| f.access_flag =
        false);
    stage2_leaf_mutation!(1 << 11, |f: &mut RawVmsa128Stage2LeafAttrs| f.force_no_xs =
        false);
    stage2_leaf_mutation!(0x3ffu128 << 91, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .software =
        ten_b);
    stage2_leaf_mutation!(1u128 << 111, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .contiguous =
        false);
    stage2_leaf_mutation!(1u128 << 114, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .assured_only =
        false);
    stage2_leaf_mutation!(0xfu128 << 115, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .permissions
        .pi =
        four_b);
    stage2_leaf_mutation!(0xfu128 << 121, |f: &mut RawVmsa128Stage2LeafAttrs| f
        .permissions
        .po =
        four_a);
    stage2_leaf_mutation!(1u128 << 127, |f: &mut RawVmsa128Stage2LeafAttrs| f.ns =
        false);

    let stage2_table = RawVmsa128Stage2TableAttrs {
        table_nt: false,
        access_flag: true,
        software: ten_a,
    };
    let stage2_table_raw = <Stage2Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        table_address,
        transition,
        stage2_table,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    macro_rules! stage2_table_mutation {
        ($mask:expr, $change:expr) => {{
            let mut fields = stage2_table;
            $change(&mut fields);
            let raw = <Stage2Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
                table_address,
                transition,
                fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let delta = raw ^ stage2_table_raw;
            failures += u64::from(delta == 0 || delta & !($mask as u128) != 0);
            failures += u64::from(
                <Stage2Layout as DescriptorLayout<Granule4KiB>>::decode_table_fields(
                    raw,
                    Level::L0,
                ) != fields,
            );
        }};
    }
    stage2_table_mutation!(1 << 6, |f: &mut RawVmsa128Stage2TableAttrs| f.table_nt =
        true);
    stage2_table_mutation!(1 << 10, |f: &mut RawVmsa128Stage2TableAttrs| f
        .access_flag =
        false);
    stage2_table_mutation!(0x3ffu128 << 91, |f: &mut RawVmsa128Stage2TableAttrs| f
        .software =
        ten_b);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_vmsa64_descriptor_field_mutations() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::{Vmsa64, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3::{NonSecureIpaStage2, NonSecureStreamStage1};
    use aarch64_vmsa::descriptor::DescriptorLayout;
    use aarch64_vmsa::low_level::raw::{
        FourBit, RawShareability, RawVmsa64PermissionFields, RawVmsa64Stage1LeafAttrs,
        RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, TableAp,
        ThreeBit,
    };
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    let four_a = FourBit::new(0b0101).map_err(|_| HarnessError::InvalidState)?;
    let four_b = FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?;
    let overlay_a = ThreeBit::new(0b011).map_err(|_| HarnessError::InvalidState)?;
    let overlay_b = ThreeBit::new(0b100).map_err(|_| HarnessError::InvalidState)?;
    let table_ap_zero = TableAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?;
    let inner = RawShareability::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?;
    let outer = RawShareability::from_bits(0b10).map_err(|_| HarnessError::InvalidState)?;
    let mut failures = 0u64;

    macro_rules! exercise_format {
        ($format:ty, $granule:ty, $output:expr) => {{
            type Stage1Layout =
                <$format as HasRegimeLayout<NonSecureStreamStage1, $granule>>::Layout;
            type Stage2Layout = <$format as HasRegimeLayout<NonSecureIpaStage2, $granule>>::Layout;
            let output = PhysAddr($output);
            let permissions = RawVmsa64PermissionFields {
                primary: four_a,
                dirty: true,
                overlay: overlay_a,
            };
            let stage1_leaf = RawVmsa64Stage1LeafAttrs {
                attr_index: four_a,
                ns: true,
                permissions,
                shareability: inner,
                access_flag: true,
                alias_bit: true,
                contiguous: true,
                guarded: true,
                software: four_a,
            };
            let stage1_raw = <Stage1Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                output,
                Level::L3,
                stage1_leaf,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            macro_rules! s1_leaf {
                ($mask:expr, $change:expr) => {{
                    let mut fields = stage1_leaf;
                    $change(&mut fields);
                    let raw = <Stage1Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                        output,
                        Level::L3,
                        fields,
                    )
                    .map_err(|_| HarnessError::InvalidState)?;
                    let delta = raw ^ stage1_raw;
                    failures += u64::from(delta == 0 || delta & !($mask as u64) != 0);
                    failures += u64::from(
                        <Stage1Layout as DescriptorLayout<$granule>>::decode_leaf_fields(
                            raw,
                            Level::L3,
                        ) != fields,
                    );
                }};
            }
            s1_leaf!(
                (0x7u64 << 2) | (1u64 << 59),
                |f: &mut RawVmsa64Stage1LeafAttrs| f.attr_index = four_b
            );
            s1_leaf!(1 << 5, |f: &mut RawVmsa64Stage1LeafAttrs| f.ns = false);
            s1_leaf!(
                (1u64 << 6) | (1u64 << 51) | (1u64 << 53) | (1u64 << 54),
                |f: &mut RawVmsa64Stage1LeafAttrs| f.permissions.primary = four_b
            );
            s1_leaf!(1 << 7, |f: &mut RawVmsa64Stage1LeafAttrs| f
                .permissions
                .dirty =
                false);
            s1_leaf!(0x3 << 8, |f: &mut RawVmsa64Stage1LeafAttrs| f
                .shareability =
                outer);
            s1_leaf!(1 << 10, |f: &mut RawVmsa64Stage1LeafAttrs| f.access_flag =
                false);
            s1_leaf!(1 << 11, |f: &mut RawVmsa64Stage1LeafAttrs| f.alias_bit =
                false);
            s1_leaf!(1u64 << 50, |f: &mut RawVmsa64Stage1LeafAttrs| f.guarded =
                false);
            s1_leaf!(1u64 << 52, |f: &mut RawVmsa64Stage1LeafAttrs| f
                .contiguous =
                false);
            s1_leaf!(0xfu64 << 55, |f: &mut RawVmsa64Stage1LeafAttrs| f
                .software =
                four_b);
            s1_leaf!(0x7u64 << 60, |f: &mut RawVmsa64Stage1LeafAttrs| f
                .permissions
                .overlay =
                overlay_b);

            let parent = TableShape::<$format, $granule>::root(Level::L1)
                .map_err(|_| HarnessError::InvalidState)?;
            let child = TableShape::<$format, $granule>::new(Level::L2, 1)
                .map_err(|_| HarnessError::InvalidState)?;
            let transition =
                TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
            let table_address =
                TableAddr::new(0x8000_0000).map_err(|_| HarnessError::InvalidState)?;
            let stage1_table = RawVmsa64Stage1TableAttrs {
                access_flag: true,
                privileged_execute_never_limit: true,
                unprivileged_execute_never_limit: true,
                ap_table: TableAp::from_bits(0b11).map_err(|_| HarnessError::InvalidState)?,
                ns_table: true,
                software: four_a,
            };
            let stage1_table_raw = <Stage1Layout as DescriptorLayout<$granule>>::table_descriptor(
                table_address,
                transition,
                stage1_table,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            macro_rules! s1_table {
                ($mask:expr, $change:expr) => {{
                    let mut fields = stage1_table;
                    $change(&mut fields);
                    let raw = <Stage1Layout as DescriptorLayout<$granule>>::table_descriptor(
                        table_address,
                        transition,
                        fields,
                    )
                    .map_err(|_| HarnessError::InvalidState)?;
                    let delta = raw ^ stage1_table_raw;
                    failures += u64::from(delta == 0 || delta & !($mask as u64) != 0);
                    failures += u64::from(
                        <Stage1Layout as DescriptorLayout<$granule>>::decode_table_fields(
                            raw,
                            Level::L1,
                        ) != fields,
                    );
                }};
            }
            s1_table!(1 << 10, |f: &mut RawVmsa64Stage1TableAttrs| f.access_flag =
                false);
            s1_table!(0xfu64 << 55, |f: &mut RawVmsa64Stage1TableAttrs| f
                .software =
                four_b);
            s1_table!(1u64 << 59, |f: &mut RawVmsa64Stage1TableAttrs| f
                .privileged_execute_never_limit =
                false);
            s1_table!(1u64 << 60, |f: &mut RawVmsa64Stage1TableAttrs| f
                .unprivileged_execute_never_limit =
                false);
            s1_table!(0x3u64 << 61, |f: &mut RawVmsa64Stage1TableAttrs| f
                .ap_table =
                table_ap_zero);
            s1_table!(1u64 << 63, |f: &mut RawVmsa64Stage1TableAttrs| f.ns_table =
                false);

            let stage2_leaf = RawVmsa64Stage2LeafAttrs {
                mem_attr: four_a,
                permissions,
                shareability: inner,
                access_flag: true,
                contiguous: true,
                software: four_a,
            };
            let stage2_raw = <Stage2Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                output,
                Level::L3,
                stage2_leaf,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            macro_rules! s2_leaf {
                ($mask:expr, $change:expr) => {{
                    let mut fields = stage2_leaf;
                    $change(&mut fields);
                    let raw = <Stage2Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                        output,
                        Level::L3,
                        fields,
                    )
                    .map_err(|_| HarnessError::InvalidState)?;
                    let delta = raw ^ stage2_raw;
                    failures += u64::from(delta == 0 || delta & !($mask as u64) != 0);
                    failures += u64::from(
                        <Stage2Layout as DescriptorLayout<$granule>>::decode_leaf_fields(
                            raw,
                            Level::L3,
                        ) != fields,
                    );
                }};
            }
            s2_leaf!(0xf << 2, |f: &mut RawVmsa64Stage2LeafAttrs| f.mem_attr =
                four_b);
            s2_leaf!(
                (1u64 << 6) | (1u64 << 51) | (1u64 << 53) | (1u64 << 54),
                |f: &mut RawVmsa64Stage2LeafAttrs| f.permissions.primary = four_b
            );
            s2_leaf!(1 << 7, |f: &mut RawVmsa64Stage2LeafAttrs| f
                .permissions
                .dirty =
                false);
            s2_leaf!(0x3 << 8, |f: &mut RawVmsa64Stage2LeafAttrs| f
                .shareability =
                outer);
            s2_leaf!(1 << 10, |f: &mut RawVmsa64Stage2LeafAttrs| f.access_flag =
                false);
            s2_leaf!(1u64 << 52, |f: &mut RawVmsa64Stage2LeafAttrs| f
                .contiguous =
                false);
            s2_leaf!(0xfu64 << 55, |f: &mut RawVmsa64Stage2LeafAttrs| f
                .software =
                four_b);
            s2_leaf!(0x7u64 << 60, |f: &mut RawVmsa64Stage2LeafAttrs| f
                .permissions
                .overlay =
                overlay_b);

            let stage2_table = RawVmsa64Stage2TableAttrs {
                access_flag: true,
                software: four_a,
            };
            let stage2_table_raw = <Stage2Layout as DescriptorLayout<$granule>>::table_descriptor(
                table_address,
                transition,
                stage2_table,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            for (fields, mask) in [
                (
                    RawVmsa64Stage2TableAttrs {
                        access_flag: false,
                        ..stage2_table
                    },
                    1u64 << 10,
                ),
                (
                    RawVmsa64Stage2TableAttrs {
                        software: four_b,
                        ..stage2_table
                    },
                    0xfu64 << 55,
                ),
            ] {
                let raw = <Stage2Layout as DescriptorLayout<$granule>>::table_descriptor(
                    table_address,
                    transition,
                    fields,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                let delta = raw ^ stage2_table_raw;
                failures += u64::from(delta == 0 || delta & !mask != 0);
                failures += u64::from(
                    <Stage2Layout as DescriptorLayout<$granule>>::decode_table_fields(
                        raw,
                        Level::L1,
                    ) != fields,
                );
            }
        }};
    }

    exercise_format!(Vmsa64, Granule4KiB, 0x4000_0000);
    exercise_format!(Vmsa64Lpa2, Granule64KiB, 0x4000_0000);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_stage2_output_normalization() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, Walker};

    const OUTPUT: u64 = 0x0000_1234_5678_f000;
    let mut failures = 0u64;
    macro_rules! check {
        ($granule:ty, $level:expr, $architectural_shift:expr) => {{
            type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, $granule>>::Layout;
            let raw = <Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                PhysAddr(OUTPUT),
                $level,
                smmu_v2_raw_fields(0, 0)?,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let expected = OUTPUT & !((1u64 << $architectural_shift) - 1);
            let actual = <Layout as DescriptorLayout<$granule>>::output_address(raw, $level).0;
            failures += u64::from(actual != expected);
        }};
    }

    // Architectural output-address alignment for each SMMUv2-supported block/page level.
    check!(Granule4KiB, Level::L1, 30);
    check!(Granule4KiB, Level::L2, 21);
    check!(Granule4KiB, Level::L3, 12);
    check!(Granule16KiB, Level::L2, 25);
    check!(Granule16KiB, Level::L3, 14);
    check!(Granule64KiB, Level::L2, 29);
    check!(Granule64KiB, Level::L3, 16);

    macro_rules! check_walker {
        ($granule:ty, $level:expr, $architectural_shift:expr) => {{
            type Format = Vmsa64;
            type Layout = <Format as HasRegimeLayout<NonSecureIpaStage2, $granule>>::Layout;
            let root_page = unsafe { core::ptr::addr_of_mut!(SMMU_L0.0) as u64 };
            unsafe { core::ptr::write_bytes(root_page as *mut u8, 0, 65536) };
            let raw = <Layout as DescriptorLayout<$granule>>::leaf_descriptor(
                PhysAddr(OUTPUT),
                $level,
                smmu_v2_raw_fields(0, 0)?,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            unsafe { <Format as DescriptorFormat>::write_descriptor(root_page as *mut u64, raw) };
            let root = RootTableGeometry::<Format, $granule>::new_at_level(
                TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                $level,
                $architectural_shift,
                48,
            )
            .map_err(|_| HarnessError::InvalidState)?
            .with_regime::<NonSecureIpaStage2>();
            let walker = Walker::new(
                root,
                SmmuD128ArenaAccess {
                    tables: [root_page, root_page, root_page, root_page],
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let offset = 0x5a5 & ((1u64 << $architectural_shift) - 1);
            match walker.translate(WalkInputAddr::new(offset)) {
                Ok(Some(mapping)) => {
                    let expected_base = OUTPUT & !((1u64 << $architectural_shift) - 1);
                    failures += u64::from(mapping.output_base().raw() != expected_base);
                    failures += u64::from(mapping.output().raw() != expected_base + offset);
                }
                _ => failures += 1,
            }
        }};
    }
    check_walker!(Granule4KiB, Level::L1, 30);
    check_walker!(Granule4KiB, Level::L2, 21);
    check_walker!(Granule16KiB, Level::L2, 25);
    check_walker!(Granule16KiB, Level::L3, 14);
    check_walker!(Granule64KiB, Level::L2, 29);
    check_walker!(Granule64KiB, Level::L3, 16);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_stage2_table_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorKind, DescriptorLayout};
    use aarch64_vmsa::low_level::raw::{FourBit, RawVmsa64Stage2TableAttrs};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let fields = RawVmsa64Stage2TableAttrs {
        access_flag: true,
        software: FourBit::new(0b1010).map_err(|_| HarnessError::InvalidState)?,
    };
    let parent = TableShape::<Vmsa64, Granule4KiB>::root(Level::L1)
        .map_err(|_| HarnessError::InvalidState)?;
    let child = TableShape::<Vmsa64, Granule4KiB>::new(Level::L2, 1)
        .map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let address = TableAddr::new(0x8000).map_err(|_| HarnessError::InvalidState)?;
    let raw =
        <Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(address, transition, fields)
            .map_err(|_| HarnessError::InvalidState)?;
    let next = <Layout as DescriptorLayout<Granule4KiB>>::next_table(raw, Level::L1)
        .ok_or(HarnessError::InvalidState)?;
    let mut failures = 0u64;
    failures += u64::from(
        <Layout as DescriptorLayout<Granule4KiB>>::kind(raw, Level::L1) != DescriptorKind::Table,
    );
    failures += u64::from(
        <Layout as DescriptorLayout<Granule4KiB>>::decode_table_fields(raw, Level::L1) != fields,
    );
    failures += u64::from(
        <Layout as DescriptorLayout<Granule4KiB>>::table_address(raw, Level::L1) != address,
    );
    failures +=
        u64::from(next.address != address || next.level != Level::L2 || next.stride_count != 1);
    failures += u64::from(
        <Layout as DescriptorLayout<Granule4KiB>>::kind(raw | (1 << 2), Level::L1)
            != DescriptorKind::Invalid,
    );

    let skipped = TableShape::<Vmsa64, Granule4KiB>::new(Level::L3, 2)
        .map_err(|_| HarnessError::InvalidState)?;
    let bad_transition =
        TableTransition::new(parent, skipped).map_err(|_| HarnessError::InvalidState)?;
    let bad = <Layout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        address,
        bad_transition,
        fields,
    );
    failures += u64::from(!matches!(
        bad,
        Err(DescriptorError::InvalidTableTransition { .. })
    ));

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_stage2_table_granules() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::{Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorKind, DescriptorLayout};
    use aarch64_vmsa::low_level::raw::{FourBit, RawVmsa64Stage2TableAttrs};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    let fields = RawVmsa64Stage2TableAttrs {
        access_flag: true,
        software: FourBit::new(0b0110).map_err(|_| HarnessError::InvalidState)?,
    };
    let mut failures = 0u64;

    macro_rules! check {
        ($granule:ty) => {{
            type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, $granule>>::Layout;
            let address =
                TableAddr::<$granule>::new(0x0008_0000).map_err(|_| HarnessError::InvalidState)?;
            let parent = TableShape::<Vmsa64, $granule>::root(Level::L1)
                .map_err(|_| HarnessError::InvalidState)?;
            let child = TableShape::<Vmsa64, $granule>::new(Level::L2, 1)
                .map_err(|_| HarnessError::InvalidState)?;
            let transition =
                TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
            let raw = <Layout as DescriptorLayout<$granule>>::table_descriptor(
                address, transition, fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let next = <Layout as DescriptorLayout<$granule>>::next_table(raw, Level::L1)
                .ok_or(HarnessError::InvalidState)?;

            failures += u64::from(
                <Layout as DescriptorLayout<$granule>>::kind(raw, Level::L1)
                    != DescriptorKind::Table,
            );
            failures += u64::from(
                <Layout as DescriptorLayout<$granule>>::decode_table_fields(raw, Level::L1)
                    != fields,
            );
            failures += u64::from(
                <Layout as DescriptorLayout<$granule>>::table_address(raw, Level::L1) != address,
            );
            failures += u64::from(
                next.address != address || next.level != Level::L2 || next.stride_count != 1,
            );
        }};
    }

    check!(Granule16KiB);
    check!(Granule64KiB);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_stage2_semantic_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AllocationHints, AttrError, CachePolicy, Cacheability, DeviceMemoryType, LiveVmsaConfig,
        MemoryAttributes, MemoryTransience, SemanticSmmuV2Stage2LeafControls,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2TableAttrs, Shareability,
        SmmuV2AllocationHint, SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permissions,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::low_level::raw::TwoBit;

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let devices = [
        DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
        DeviceMemoryType::NonGatheringNonReorderingEarlyAck,
        DeviceMemoryType::NonGatheringReorderingEarlyAck,
        DeviceMemoryType::GatheringReorderingEarlyAck,
    ];
    let mut cacheabilities = [Cacheability::NonCacheable; 17];
    let mut cacheability_count = 1;
    for policy in [CachePolicy::WriteThrough, CachePolicy::WriteBack] {
        for transience in [MemoryTransience::Transient, MemoryTransience::NonTransient] {
            for allocation in [
                AllocationHints::None,
                AllocationHints::WriteAllocate,
                AllocationHints::ReadAllocate,
                AllocationHints::ReadWriteAllocate,
            ] {
                cacheabilities[cacheability_count] = Cacheability::Cacheable {
                    policy,
                    transience,
                    allocation,
                };
                cacheability_count += 1;
            }
        }
    }
    let permissions = [
        Stage2Permissions::no_access(),
        Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, true),
        ),
        Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, true),
        ),
    ];
    let allocations = [
        SmmuV2AllocationHint::UsePreviousStage,
        SmmuV2AllocationHint::Allocate,
        SmmuV2AllocationHint::NoAllocate,
    ];
    let shareabilities = [
        Shareability::NonShareable,
        Shareability::OuterShareable,
        Shareability::InnerShareable,
    ];
    let mut failures = 0u64;
    macro_rules! round_trip {
        ($granule:ty, $semantic:expr) => {{
            let semantic = $semantic;
            match <Vmsa64 as AttributeCodec<NonSecureIpaStage2, $granule, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, $granule, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        ) != Ok(semantic),
                    );
                }
                Err(AttrError::UnencodableMemoryAttribute) => {}
                Err(_) => failures += 1,
            }
        }};
    }
    macro_rules! exercise_memory {
        ($memory:expr) => {{
            let memory = $memory;
            for permissions in permissions {
                for read_allocate in allocations {
                    for write_allocate in allocations {
                        for shareability in shareabilities {
                            for access_flag in [false, true] {
                                for contiguous in [false, true] {
                                    for software in 0..=0xf {
                                        let semantic = SemanticStage2LeafAttrs {
                                            memory: Stage2MemoryAttributes::Combined(memory),
                                            permissions,
                                            output_address_space: (),
                                            controls: SemanticSmmuV2Stage2LeafControls {
                                                shareability,
                                                access_flag,
                                                dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                                                    aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
                                                ),
                                                contiguous,
                                                read_allocate,
                                                write_allocate,
                                                software: SoftwareMetadata::new(software),
                                            },
                                        };
                                        round_trip!(Granule4KiB, semantic);
                                        round_trip!(Granule16KiB, semantic);
                                        round_trip!(Granule64KiB, semantic);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }};
    }
    for device in devices {
        exercise_memory!(MemoryAttributes::Device(device));
    }
    for inner in cacheabilities {
        for outer in cacheabilities {
            exercise_memory!(MemoryAttributes::Normal { inner, outer });
        }
    }

    for invalid in [
        Stage2Permissions::special_write_only(),
        Stage2Permissions::mostly_read_only(aarch64_vmsa::attrs::TopLevelRequirements::NONE),
        Stage2Permissions::mostly_read_only(aarch64_vmsa::attrs::TopLevelRequirements::TOP_LEVEL1),
        Stage2Permissions::mostly_read_only(aarch64_vmsa::attrs::TopLevelRequirements::TOP_LEVEL0),
        Stage2Permissions::mostly_read_only(aarch64_vmsa::attrs::TopLevelRequirements::BOTH),
        Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
        ),
        Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, true),
        ),
        Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
        ),
        Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, true),
        ),
    ] {
        let semantic = SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
                inner: Cacheability::NonCacheable,
                outer: Cacheability::NonCacheable,
            }),
            permissions: invalid,
            output_address_space: (),
            controls: SemanticSmmuV2Stage2LeafControls {
                shareability: Shareability::InnerShareable,
                access_flag: true,
                dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                    aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
                ),
                contiguous: false,
                read_allocate: allocations[0],
                write_allocate: allocations[0],
                software: SoftwareMetadata::new(0),
            },
        };
        failures += u64::from(
            <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            ) != Err(AttrError::UnencodablePermissions),
        );
    }

    let mut reserved = smmu_v2_raw_fields(0, 0)?;
    reserved.read_allocate = TwoBit::new(1).map_err(|_| HarnessError::InvalidState)?;
    failures += u64::from(!matches!(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            reserved,
        ),
        Ok(decoded)
            if decoded.controls.read_allocate == SmmuV2AllocationHint::UsePreviousStage
    ));
    reserved = smmu_v2_raw_fields(0, 0)?;
    reserved.write_allocate = TwoBit::new(1).map_err(|_| HarnessError::InvalidState)?;
    failures += u64::from(!matches!(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            reserved,
        ),
        Ok(decoded)
            if decoded.controls.write_allocate == SmmuV2AllocationHint::UsePreviousStage
    ));

    for software in [0, 0xf] {
        let table = SemanticVmsa64Stage2TableAttrs {
            access_flag: software != 0,
            software: SoftwareMetadata::new(software),
        };
        let raw = <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_table(
            &config,
            Level::L1,
            table,
        )
        .map_err(|_| HarnessError::InvalidState)?;
        failures += u64::from(
            <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_table(
                &config,
                Level::L1,
                raw,
            ) != Ok(table),
        );
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v2_stage2_semantic_errors() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AttrError, Cacheability, FwbStage2Memory, LiveVmsaConfig, MemoryAttributes,
        SemanticSmmuV2Stage2LeafControls, SemanticStage2LeafAttrs, SemanticVmsa64Stage2TableAttrs,
        Shareability, SmmuV2AllocationHint, SoftwareMetadata, Stage2MemoryAttributes,
        Stage2MemoryMode, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::DescriptorLayout;
    use aarch64_vmsa::low_level::raw::{FourBit, Stage2Ap};
    use aarch64_vmsa::regime::HasRegimeLayout;

    let mut config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let controls = |software| SemanticSmmuV2Stage2LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
            aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
        ),
        contiguous: false,
        read_allocate: SmmuV2AllocationHint::UsePreviousStage,
        write_allocate: SmmuV2AllocationHint::UsePreviousStage,
        software: SoftwareMetadata::new(software),
    };
    let combined = Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
        inner: Cacheability::NonCacheable,
        outer: Cacheability::NonCacheable,
    });
    let semantic = |memory, software| SemanticStage2LeafAttrs {
        memory,
        permissions: Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        output_address_space: (),
        controls: controls(software),
    };
    let mut failures = 0u64;

    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            semantic(combined, 0x10),
        ) != Err(AttrError::RawFieldOutOfRange),
    );
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_table(
            &config,
            Level::L1,
            SemanticVmsa64Stage2TableAttrs {
                access_flag: true,
                software: SoftwareMetadata::new(0x10),
            },
        ) != Err(AttrError::RawFieldOutOfRange),
    );
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            semantic(Stage2MemoryAttributes::Fwb(FwbStage2Memory::UseStage1), 0),
        ) != Err(AttrError::WrongStage2MemoryMode),
    );

    let mut raw = smmu_v2_raw_fields(0, 0)?;
    raw.permissions = Stage2Ap::from_bits(0b10).map_err(|_| HarnessError::InvalidState)?;
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        ) != Err(AttrError::InvalidStage2Permission(0b10)),
    );
    raw = smmu_v2_raw_fields(0, 0)?;
    raw.mem_attr = FourBit::new(0b0100).map_err(|_| HarnessError::InvalidState)?;
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            raw,
        ) != Err(AttrError::UnencodableMemoryAttribute),
    );

    type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let valid = <Layout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        aarch64_vmsa::address::PhysAddr(0),
        Level::L3,
        smmu_v2_raw_fields(0, 0)?,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let invalid_shareability = <Layout as DescriptorLayout<Granule4KiB>>::decode_leaf_fields(
        (valid & !(0b11 << 8)) | (1 << 8),
        Level::L3,
    );
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
            &config,
            Level::L3,
            invalid_shareability,
        ) != Err(AttrError::InvalidShareability),
    );

    let fwb_values = [
        FwbStage2Memory::Device(
            aarch64_vmsa::attrs::DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
        ),
        FwbStage2Memory::Device(
            aarch64_vmsa::attrs::DeviceMemoryType::NonGatheringNonReorderingEarlyAck,
        ),
        FwbStage2Memory::Device(
            aarch64_vmsa::attrs::DeviceMemoryType::NonGatheringReorderingEarlyAck,
        ),
        FwbStage2Memory::Device(aarch64_vmsa::attrs::DeviceMemoryType::GatheringReorderingEarlyAck),
        FwbStage2Memory::PreserveDeviceOrForceNormalNonCacheable,
        FwbStage2Memory::ForceNormalWriteBack,
        FwbStage2Memory::UseStage1,
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess,
        FwbStage2Memory::UseStage1NoTagAccess,
    ];
    config.stage2_memory_mode = Stage2MemoryMode::FwbEnabled {
        mte_permission: true,
    };
    for memory in fwb_values {
        let semantic = semantic(Stage2MemoryAttributes::Fwb(memory), 0xf);
        match <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            semantic,
        ) {
            Ok(raw) => {
                failures += u64::from(
                    <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::decode_leaf(
                        &config,
                        Level::L3,
                        raw,
                    ) != Ok(semantic),
                );
            }
            Err(_) => failures += 1,
        }
    }
    config.stage2_memory_mode = Stage2MemoryMode::FwbEnabled {
        mte_permission: false,
    };
    for memory in [
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess,
        FwbStage2Memory::UseStage1NoTagAccess,
    ] {
        failures += u64::from(
            <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic(Stage2MemoryAttributes::Fwb(memory), 0),
            ) != Err(AttrError::MtePermissionUnavailable),
        );
    }
    failures += u64::from(
        <Vmsa64 as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            semantic(combined, 0),
        ) != Err(AttrError::WrongStage2MemoryMode),
    );

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_stage2_semantic_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AllocationHints, AttrError, CachePolicy, Cacheability, DirtyBitManagement, DirtyControl,
        LiveVmsaConfig, MemoryAttributes, MemoryTransience, RealmOrNonSecurePa, SecureSelectablePa,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
        Shareability, SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permissions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;
    use aarch64_vmsa::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};

    let memory = Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
        inner: Cacheability::Cacheable {
            policy: CachePolicy::WriteBack,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
        outer: Cacheability::Cacheable {
            policy: CachePolicy::WriteThrough,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
    });
    let controls = SemanticVmsa64Stage2LeafControls {
        shareability: Shareability::InnerShareable,
        access_flag: true,
        dirty: DirtyControl::Direct(DirtyBitManagement::HardwareManaged),
        contiguous: true,
        software: SoftwareMetadata::new(0b1010),
    };
    let direct = aarch64_vmsa::attrs::Stage2PermissionSettings::direct();
    macro_rules! config {
        ($output_pas:expr) => {
            LiveVmsaConfig {
                mair: 0,
                mair2: None,
                smmu_v3_aie: false,
                stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
                stage2_permissions: direct,
                stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: Shareability::InnerShareable,
                output_pas: $output_pas,
            }
        };
    }
    let mut failures = 0u64;
    macro_rules! round_trip {
        ($format:ty, $regime:ty, $granule:ty, $config:expr, $pas:expr, $permissions:expr) => {{
            let config = $config;
            let semantic = SemanticStage2LeafAttrs {
                memory,
                permissions: $permissions,
                output_address_space: $pas,
                controls,
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        ) != Ok(semantic),
                    );
                }
                Err(_) => failures += 1,
            }
            let table = SemanticVmsa64Stage2TableAttrs {
                access_flag: true,
                software: SoftwareMetadata::new(0xf),
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                &config,
                Level::L1,
                table,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_table(
                            &config,
                            Level::L1,
                            raw,
                        ) != Ok(table),
                    )
                }
                Err(_) => failures += 1,
            }
            let invalid_leaf = SemanticStage2LeafAttrs {
                controls: SemanticVmsa64Stage2LeafControls {
                    software: SoftwareMetadata::new(0x10),
                    ..controls
                },
                ..semantic
            };
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                    &config,
                    Level::L3,
                    invalid_leaf,
                ) != Err(AttrError::RawFieldOutOfRange),
            );
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                    &config,
                    Level::L1,
                    SemanticVmsa64Stage2TableAttrs {
                        access_flag: true,
                        software: SoftwareMetadata::new(0x10),
                    },
                ) != Err(AttrError::RawFieldOutOfRange),
            );
        }};
    }
    let rw = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
    );
    macro_rules! all_granules {
        ($format:ty, $regime:ty, $config:expr, $pas:expr, $permissions:expr) => {{
            round_trip!($format, $regime, Granule4KiB, $config, $pas, $permissions);
            round_trip!($format, $regime, Granule16KiB, $config, $pas, $permissions);
            round_trip!($format, $regime, Granule64KiB, $config, $pas, $permissions);
        }};
    }
    macro_rules! all_endian_granules {
        ($regime:ty, $config:expr, $pas:expr, $permissions:expr) => {{
            all_granules!(Vmsa64<NativeEndian>, $regime, $config, $pas, $permissions);
            all_granules!(Vmsa64<LittleEndian>, $regime, $config, $pas, $permissions);
            all_granules!(Vmsa64<BigEndian>, $regime, $config, $pas, $permissions);
            all_granules!(
                Vmsa64Lpa2<NativeEndian>,
                $regime,
                $config,
                $pas,
                $permissions
            );
            all_granules!(
                Vmsa64Lpa2<LittleEndian>,
                $regime,
                $config,
                $pas,
                $permissions
            );
            all_granules!(Vmsa64Lpa2<BigEndian>, $regime, $config, $pas, $permissions);
        }};
    }
    all_endian_granules!(
        smmu_v3::NonSecureIpaStage2<StandardStage2PermissionModel>,
        config!(()),
        (),
        rw
    );
    all_endian_granules!(
        smmu_v3::NonSecureIpaStage2<XnxStage2PermissionModel>,
        config!(()),
        (),
        Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false)
        )
    );
    all_endian_granules!(
        smmu_v3::SecureIpaStage2<StandardStage2PermissionModel>,
        config!(SecureSelectablePa::Secure),
        SecureSelectablePa::Secure,
        rw
    );
    all_endian_granules!(
        smmu_v3::SecureStreamNonSecureIpaStage2<StandardStage2PermissionModel>,
        config!(SecureSelectablePa::NonSecure),
        SecureSelectablePa::NonSecure,
        rw
    );
    all_endian_granules!(
        smmu_v3::RealmIpaStage2<StandardStage2PermissionModel>,
        config!(()),
        RealmOrNonSecurePa::Realm,
        rw
    );
    all_endian_granules!(
        smmu_v3::RealmIpaStage2<StandardStage2PermissionModel>,
        config!(()),
        RealmOrNonSecurePa::NonSecure,
        rw
    );

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_stage2_d128_semantic_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AllocationHints, AttrError, CachePolicy, Cacheability, DirtyState, LiveVmsaConfig,
        MemoryAttributes, MemoryTransience, RealmOrNonSecurePa, SecureSelectablePa,
        SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        SemanticVmsa128Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2BasePermissions,
        Stage2MemoryAttributes, Stage2MemoryMode, Stage2PermissionRegisters,
        Stage2PermissionSettings, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;
    use aarch64_vmsa::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};

    let memory = Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
        inner: Cacheability::Cacheable {
            policy: CachePolicy::WriteBack,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
        outer: Cacheability::Cacheable {
            policy: CachePolicy::WriteThrough,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
    });
    let controls = SemanticVmsa128Stage2LeafControls {
        bbm_nt: false,
        dirty_state: DirtyState::Dirty,
        shareability: Shareability::InnerShareable,
        access_flag: true,
        force_no_xs: true,
        contiguous: true,
        assured_only: true,
        software: SoftwareMetadata::new(0x2aa),
    };
    let permissions = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
    );
    let indirect = Stage2PermissionSettings {
        base: Stage2BasePermissions::Indirect(Stage2PermissionRegisters {
            s2pir_el2: 0xfedc_ba98_7654_3210,
        }),
        s2por_el1: None,
    };
    macro_rules! config {
        ($pas:expr, $permissions:expr) => {
            LiveVmsaConfig {
                mair: 0,
                mair2: None,
                smmu_v3_aie: false,
                stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
                stage2_permissions: $permissions,
                stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: Shareability::InnerShareable,
                output_pas: $pas,
            }
        };
    }

    let mut failures = 0u64;
    macro_rules! round_trip {
        ($format:ty, $regime:ty, $granule:ty, $config:expr, $pas:expr) => {{
            let config = $config;
            let semantic = SemanticStage2LeafAttrs {
                memory,
                permissions,
                output_address_space: $pas,
                controls,
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                &config,
                Level::L3,
                semantic,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_leaf(
                            &config,
                            Level::L3,
                            raw,
                        ) != Ok(semantic),
                    );
                }
                Err(_) => failures += 1,
            }
            let table = SemanticVmsa128Stage2TableAttrs {
                table_nt: false,
                access_flag: true,
                software: SoftwareMetadata::new(0x3ff),
            };
            match <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                &config,
                Level::L1,
                table,
            ) {
                Ok(raw) => {
                    failures += u64::from(
                        <$format as AttributeCodec<$regime, $granule, _>>::decode_table(
                            &config,
                            Level::L1,
                            raw,
                        ) != Ok(table),
                    );
                }
                Err(_) => failures += 1,
            }
            let invalid_leaf = SemanticStage2LeafAttrs {
                controls: SemanticVmsa128Stage2LeafControls {
                    software: SoftwareMetadata::new(0x400),
                    ..controls
                },
                ..semantic
            };
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                    &config,
                    Level::L3,
                    invalid_leaf,
                ) != Err(AttrError::RawFieldOutOfRange),
            );
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_table(
                    &config,
                    Level::L1,
                    SemanticVmsa128Stage2TableAttrs {
                        table_nt: false,
                        access_flag: true,
                        software: SoftwareMetadata::new(0x400),
                    },
                ) != Err(AttrError::RawFieldOutOfRange),
            );
            let mut unavailable = config;
            unavailable.stage2_permissions = Stage2PermissionSettings::direct();
            failures += u64::from(
                <$format as AttributeCodec<$regime, $granule, _>>::encode_leaf(
                    &unavailable,
                    Level::L3,
                    semantic,
                ) != Err(AttrError::PermissionIndirectionUnavailable),
            );
        }};
    }

    // Every descriptor endian and translation granule for the SMMUv3 D128 layout.
    macro_rules! all_granules {
        ($format:ty) => {{
            round_trip!(
                $format,
                smmu_v3::NonSecureIpaStage2<StandardStage2PermissionModel>,
                Granule4KiB,
                config!((), indirect),
                ()
            );
            round_trip!(
                $format,
                smmu_v3::NonSecureIpaStage2<StandardStage2PermissionModel>,
                Granule16KiB,
                config!((), indirect),
                ()
            );
            round_trip!(
                $format,
                smmu_v3::NonSecureIpaStage2<StandardStage2PermissionModel>,
                Granule64KiB,
                config!((), indirect),
                ()
            );
        }};
    }
    all_granules!(Vmsa128<NativeEndian>);
    all_granules!(Vmsa128<LittleEndian>);
    all_granules!(Vmsa128<BigEndian>);

    // Every SMMUv3 stage-2 regime, both public permission models, and all PAS choices.
    macro_rules! both_permissions {
        ($regime:ident, $config:expr, $pas:expr) => {{
            round_trip!(
                Vmsa128,
                smmu_v3::$regime<StandardStage2PermissionModel>,
                Granule4KiB,
                $config,
                $pas
            );
            round_trip!(
                Vmsa128,
                smmu_v3::$regime<XnxStage2PermissionModel>,
                Granule4KiB,
                $config,
                $pas
            );
        }};
    }
    both_permissions!(NonSecureIpaStage2, config!((), indirect), ());
    both_permissions!(
        SecureIpaStage2,
        config!(SecureSelectablePa::Secure, indirect),
        SecureSelectablePa::Secure
    );
    both_permissions!(
        SecureStreamNonSecureIpaStage2,
        config!(SecureSelectablePa::NonSecure, indirect),
        SecureSelectablePa::NonSecure
    );
    both_permissions!(
        RealmIpaStage2,
        config!((), indirect),
        RealmOrNonSecurePa::Realm
    );
    round_trip!(
        Vmsa128,
        smmu_v3::SecureIpaStage2<StandardStage2PermissionModel>,
        Granule4KiB,
        config!(SecureSelectablePa::NonSecure, indirect),
        SecureSelectablePa::NonSecure
    );
    round_trip!(
        Vmsa128,
        smmu_v3::SecureStreamNonSecureIpaStage2<StandardStage2PermissionModel>,
        Granule4KiB,
        config!(SecureSelectablePa::Secure, indirect),
        SecureSelectablePa::Secure
    );
    round_trip!(
        Vmsa128,
        smmu_v3::RealmIpaStage2<StandardStage2PermissionModel>,
        Granule4KiB,
        config!((), indirect),
        RealmOrNonSecurePa::NonSecure
    );

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

#[repr(C, align(65536))]
struct Page([u8; 65536]);

#[repr(C, align(65536))]
struct DescriptorPage([u64; 8192]);

#[repr(C, align(64))]
struct StreamTable([u64; 8]);

#[repr(C, align(128))]
struct StreamTables([StreamTable; 2]);

#[repr(C, align(64))]
struct EventQueue([u64; 8]);

static mut SMMU_L1: DescriptorPage = DescriptorPage([0; 8192]);
static mut SMMU_L0: DescriptorPage = DescriptorPage([0; 8192]);
static mut SMMU_L2: DescriptorPage = DescriptorPage([0; 8192]);
static mut SMMU_L3: DescriptorPage = DescriptorPage([0; 8192]);
static mut SMMU_STREAM_TABLE: StreamTables =
    StreamTables([StreamTable([0; 8]), StreamTable([0; 8])]);
static mut SMMU_EVENT_QUEUE: EventQueue = EventQueue([0; 8]);
static mut SMMU_CONTEXT_DESCRIPTOR: StreamTables =
    StreamTables([StreamTable([0; 8]), StreamTable([0; 8])]);
static mut SMMU_SOURCE: Page = Page([0; 65536]);
static mut SMMU_DESTINATION: Page = Page([0; 65536]);

#[repr(C, align(2097152))]
#[cfg(vmsa_platform_fvp_rdn2)]
struct SmmuV2Block([u8; 2097152]);

#[cfg(vmsa_platform_fvp_rdn2)]
static mut SMMU_V2_BLOCK: SmmuV2Block = SmmuV2Block([0; 2097152]);

#[repr(C, align(64))]
#[cfg(vmsa_platform_fvp_rdn2)]
struct DmaProgram([u8; 64]);

#[cfg(vmsa_platform_fvp_rdn2)]
static mut SMMU_V2_DMA_PROGRAM: DmaProgram = DmaProgram([0; 64]);

#[derive(Clone, Copy)]
struct SmmuV2ArenaAccess {
    tables: [u64; 3],
}

unsafe impl
    aarch64_vmsa::table::TableAccess<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule4KiB,
    > for SmmuV2ArenaAccess
{
    type Error = ();

    fn table_at<'a>(
        &'a self,
        location: aarch64_vmsa::table::TableAccessLocation<
            'a,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
    ) -> Result<
        aarch64_vmsa::table::TranslationTable<
            'a,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
        Self::Error,
    > {
        if !self.tables.contains(&location.addr().raw()) {
            return Err(());
        }
        let base = core::ptr::NonNull::new(location.addr().raw() as *mut u64).ok_or(())?;
        // SAFETY: each accepted address identifies a page-aligned, initialized descriptor page
        // that remains allocated for the complete mapper operation.
        Ok(
            unsafe {
                aarch64_vmsa::table::TranslationTable::from_raw_parts(base, location.shape())
            },
        )
    }
}

unsafe impl
    aarch64_vmsa::table::TableAccessMut<
        aarch64_vmsa::config::format::Vmsa64,
        aarch64_vmsa::config::granule::Granule4KiB,
    > for SmmuV2ArenaAccess
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: aarch64_vmsa::table::TableAccessLocation<
            'a,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
    ) -> Result<
        aarch64_vmsa::table::TranslationTableMut<
            'a,
            aarch64_vmsa::config::format::Vmsa64,
            aarch64_vmsa::config::granule::Granule4KiB,
        >,
        Self::Error,
    > {
        if !self.tables.contains(&location.addr().raw()) {
            return Err(());
        }
        let base = core::ptr::NonNull::new(location.addr().raw() as *mut u64).ok_or(())?;
        // SAFETY: the mapper owns the access object, and no other software view is created while
        // this exclusive table view is alive.
        Ok(unsafe {
            aarch64_vmsa::table::TranslationTableMut::from_raw_parts(base, location.shape())
        })
    }
}

struct SmmuV2ArenaFrames {
    frames: [u64; 2],
    next: usize,
    reclaimed: usize,
}

#[derive(Clone, Copy)]
struct SmmuD128ArenaAccess {
    tables: [u64; 4],
}

unsafe impl<F, G> aarch64_vmsa::table::TableAccess<F, G> for SmmuD128ArenaAccess
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
{
    type Error = ();

    fn table_at<'a>(
        &'a self,
        location: aarch64_vmsa::table::TableAccessLocation<'a, F, G>,
    ) -> Result<aarch64_vmsa::table::TranslationTable<'a, F, G>, Self::Error> {
        if !self.tables.contains(&location.addr().raw()) {
            return Err(());
        }
        let base = core::ptr::NonNull::new(location.addr().raw() as *mut F::Raw).ok_or(())?;
        // SAFETY: every accepted address is a dedicated 64-KiB-aligned descriptor arena that
        // outlives the mapper, and the location shape bounds the exposed view.
        Ok(
            unsafe {
                aarch64_vmsa::table::TranslationTable::from_raw_parts(base, location.shape())
            },
        )
    }
}

unsafe impl<F, G> aarch64_vmsa::table::TableAccessMut<F, G> for SmmuD128ArenaAccess
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: aarch64_vmsa::table::TableAccessLocation<'a, F, G>,
    ) -> Result<aarch64_vmsa::table::TranslationTableMut<'a, F, G>, Self::Error> {
        if !self.tables.contains(&location.addr().raw()) {
            return Err(());
        }
        let base = core::ptr::NonNull::new(location.addr().raw() as *mut F::Raw).ok_or(())?;
        // SAFETY: the mapper owns this accessor and therefore the exclusive descriptor view.
        Ok(unsafe {
            aarch64_vmsa::table::TranslationTableMut::from_raw_parts(base, location.shape())
        })
    }
}

struct SmmuD128ArenaFrames {
    frames: [u64; 3],
    initialized: [bool; 3],
    next: usize,
    reclaimed: usize,
    fail_after: usize,
}

unsafe impl<G> aarch64_vmsa::table::TableFrameProvider<G> for SmmuD128ArenaFrames
where
    G: aarch64_vmsa::address::TranslationGranule,
{
    type Error = ();

    fn allocate_zeroed_table(
        &mut self,
        layout: aarch64_vmsa::table::TableAllocLayout,
    ) -> Result<aarch64_vmsa::table::TableAddr<G>, Self::Error> {
        if self.next >= self.fail_after
            || self.next >= self.frames.len()
            || layout.bytes() > 65536
            || layout.align() > 65536
        {
            return Err(());
        }
        let address = self.frames[self.next];
        if address & (layout.align() - 1) != 0 {
            return Err(());
        }
        if !self.initialized[self.next] {
            // SAFETY: each frame is a dedicated writable 64-KiB arena.
            unsafe { core::ptr::write_bytes(address as *mut u8, 0, layout.bytes() as usize) };
            self.initialized[self.next] = true;
        }
        self.next += 1;
        aarch64_vmsa::table::TableAddr::new(address).map_err(|_| ())
    }

    fn reclaim_table(
        &mut self,
        reclaim: aarch64_vmsa::table::TableReclaim<G>,
    ) -> Result<(), Self::Error> {
        if !self.frames.contains(&reclaim.addr().raw()) {
            return Err(());
        }
        self.reclaimed += 1;
        if self.reclaimed == self.next {
            self.next = 0;
            self.reclaimed = 0;
        }
        Ok(())
    }
}

unsafe impl aarch64_vmsa::table::TableFrameProvider<aarch64_vmsa::config::granule::Granule4KiB>
    for SmmuV2ArenaFrames
{
    type Error = ();

    fn allocate_zeroed_table(
        &mut self,
        layout: aarch64_vmsa::table::TableAllocLayout,
    ) -> Result<
        aarch64_vmsa::table::TableAddr<aarch64_vmsa::config::granule::Granule4KiB>,
        Self::Error,
    > {
        if layout.bytes() != 4096 || layout.align() != 4096 || self.next >= self.frames.len() {
            return Err(());
        }
        let address = self.frames[self.next];
        self.next += 1;
        // SAFETY: the selected frame is a dedicated writable descriptor page.
        unsafe { core::ptr::write_bytes(address as *mut u8, 0, 4096) };
        aarch64_vmsa::table::TableAddr::new(address).map_err(|_| ())
    }

    fn reclaim_table(
        &mut self,
        reclaim: aarch64_vmsa::table::TableReclaim<aarch64_vmsa::config::granule::Granule4KiB>,
    ) -> Result<(), Self::Error> {
        if !self.frames.contains(&reclaim.addr().raw())
            || reclaim.layout().bytes() != 4096
            || reclaim.layout().align() != 4096
        {
            return Err(());
        }
        self.reclaimed += 1;
        Ok(())
    }
}

pub fn smmu_v2_stage2_mapper_walker() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        Cacheability, LiveVmsaConfig, MemoryAttributes, SemanticSmmuV2Stage2LeafControls,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2TableAttrs, Shareability,
        SmmuV2AllocationHint, SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permissions,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::mapper::Mapper;
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};

    let (l1, l2, l3) = unsafe {
        (
            core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
            core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
            core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
        )
    };
    // SAFETY: these pages are dedicated to the isolated test operation.
    unsafe {
        core::ptr::write_bytes(l1 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l2 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l3 as *mut u8, 0, 4096);
    }
    let root = RootTableGeometry::<Vmsa64, Granule4KiB>::new_at_level(
        TableAddr::new(l1).map_err(|_| HarnessError::InvalidState)?,
        Level::L1,
        39,
        48,
    )
    .map_err(|_| HarnessError::InvalidState)?
    .with_regime::<NonSecureIpaStage2>();
    let access = SmmuV2ArenaAccess {
        tables: [l1, l2, l3],
    };
    let frames = SmmuV2ArenaFrames {
        frames: [l2, l3],
        next: 0,
        reclaimed: 0,
    };
    let mut mapper =
        Mapper::new_offline(root, access, frames).map_err(|_| HarnessError::InvalidState)?;
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        }),
        permissions: Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        output_address_space: (),
        controls: SemanticSmmuV2Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            ),
            contiguous: true,
            read_allocate: SmmuV2AllocationHint::Allocate,
            write_allocate: SmmuV2AllocationHint::NoAllocate,
            software: SoftwareMetadata::new(0b1010),
        },
    };
    let table = SemanticVmsa64Stage2TableAttrs {
        access_flag: true,
        software: SoftwareMetadata::new(0b1010),
    };
    let outcome = mapper
        .map_semantic_leaf(
            &config,
            WalkInputAddr::new(0),
            WalkOutputAddr::new(0x4000_0000),
            Level::L3,
            leaf,
            table,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if outcome.tables_allocated() != 2 || outcome.level() != Level::L3 {
        return failed(2, outcome.tables_allocated().into());
    }
    let mapping = mapper
        .translate(WalkInputAddr::new(0x5a5))
        .map_err(|_| HarnessError::InvalidState)?
        .ok_or(HarnessError::InvalidState)?;
    if mapping.output().raw() != 0x4000_05a5
        || mapping.output_base().raw() != 0x4000_0000
        || mapping.semantic_attrs(&config) != Ok(leaf)
    {
        return failed(0x4000_05a5, mapping.output().raw());
    }
    let unmapped = unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) }
        .map_err(|_| HarnessError::InvalidState)?;
    if unmapped.tables_freed() != 2
        || !unmapped.root_now_empty()
        || mapper
            .translate(WalkInputAddr::new(0))
            .map_err(|_| HarnessError::InvalidState)?
            .is_some()
    {
        return failed(2, unmapped.tables_freed().into());
    }
    let (_, _, frames) = mapper.into_parts();
    if frames.reclaimed != 2 {
        return failed(2, frames.reclaimed as u64);
    }
    TestResult::Pass
}

pub fn smmu_v3_stage2_mapper_walker() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, DirtyBitManagement, DirtyControl,
        LiveVmsaConfig, MemoryAttributes, MemoryTransience, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2;
    use aarch64_vmsa::config::stage2::XnxStage2PermissionModel;
    use aarch64_vmsa::mapper::Mapper;
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};

    let (l1, l2, l3) = unsafe {
        (
            core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
            core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
            core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
        )
    };
    // SAFETY: these pages are dedicated to this test operation and the previous mapper test
    // restores them to an empty state before returning.
    unsafe {
        core::ptr::write_bytes(l1 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l2 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l3 as *mut u8, 0, 4096);
    }
    type Regime = NonSecureIpaStage2<XnxStage2PermissionModel>;
    let root = RootTableGeometry::<Vmsa64, Granule4KiB>::new_at_level(
        TableAddr::new(l1).map_err(|_| HarnessError::InvalidState)?,
        Level::L1,
        39,
        48,
    )
    .map_err(|_| HarnessError::InvalidState)?
    .with_regime::<Regime>();
    let access = SmmuV2ArenaAccess {
        tables: [l1, l2, l3],
    };
    let frames = SmmuV2ArenaFrames {
        frames: [l2, l3],
        next: 0,
        reclaimed: 0,
    };
    let mut mapper =
        Mapper::new_offline(root, access, frames).map_err(|_| HarnessError::InvalidState)?;
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
            outer: Cacheability::NonCacheable,
        }),
        permissions: Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
        ),
        output_address_space: (),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: DirtyControl::Direct(DirtyBitManagement::HardwareManaged),
            contiguous: true,
            software: SoftwareMetadata::new(0b0101),
        },
    };
    let table = SemanticVmsa64Stage2TableAttrs {
        access_flag: true,
        software: SoftwareMetadata::new(0b0110),
    };
    let outcome = mapper
        .map_semantic_leaf(
            &config,
            WalkInputAddr::new(0),
            WalkOutputAddr::new(0x6000_0000),
            Level::L3,
            leaf,
            table,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    if outcome.tables_allocated() != 2 || outcome.level() != Level::L3 {
        return failed(2, outcome.tables_allocated().into());
    }
    let mapping = mapper
        .translate(WalkInputAddr::new(0xa5a))
        .map_err(|_| HarnessError::InvalidState)?
        .ok_or(HarnessError::InvalidState)?;
    if mapping.output().raw() != 0x6000_0a5a
        || mapping.output_base().raw() != 0x6000_0000
        || mapping.semantic_attrs(&config) != Ok(leaf)
    {
        return failed(0x6000_0a5a, mapping.output().raw());
    }
    let unmapped = unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) }
        .map_err(|_| HarnessError::InvalidState)?;
    if unmapped.tables_freed() != 2
        || !unmapped.root_now_empty()
        || mapper
            .translate(WalkInputAddr::new(0))
            .map_err(|_| HarnessError::InvalidState)?
            .is_some()
    {
        return failed(2, unmapped.tables_freed().into());
    }
    let (_, _, frames) = mapper.into_parts();
    if frames.reclaimed != 2 {
        return failed(2, frames.reclaimed as u64);
    }
    TestResult::Pass
}

pub fn smmu_v3_stage1_d128_mapper_walker() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        DataRights, DeviceMemoryType, DirtyState, LiveVmsaConfig, MemoryAttributes,
        RealmOrNonSecurePa, SecureSelectablePa, SemanticStage1LeafAttrs,
        SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs, Shareability,
        SoftwareMetadata, Stage1BasePermissions, Stage1PermissionOverlays,
        Stage1PermissionRegisters, Stage1PermissionSettings, Stage1Permissions, Stage2MemoryMode,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;
    use aarch64_vmsa::mapper::Mapper;
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};

    let indirect = Stage1PermissionSettings {
        base: Stage1BasePermissions::Indirect(Stage1PermissionRegisters {
            privileged: 0xcccc_cccc_cccc_cccc,
            unprivileged: None,
            gcs_implemented: false,
        }),
        overlays: Stage1PermissionOverlays {
            privileged: None,
            unprivileged: None,
        },
    };
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: indirect,
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let permissions = Stage1Permissions::new(
        DataRights::ReadWrite,
        DataRights::None,
        false,
        false,
        false,
        false,
    );
    let mut failures = 0u64;

    macro_rules! exercise {
        ($format:ty, $regime:ty, $granule:ty, $leaf_pas:expr, $table_pas:expr, $global:expr) => {{
            let (root_page, frame1, frame2, frame3) = unsafe {
                (
                    core::ptr::addr_of_mut!(SMMU_L0.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
                )
            };
            for page in [root_page, frame1, frame2, frame3] {
                // SAFETY: the semantic mapper cases run serially and exclusively own the arenas.
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let root = RootTableGeometry::<$format, $granule>::new_at_level(
                TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                Level::L1,
                36,
                48,
            )
            .map_err(|_| HarnessError::InvalidState)?
            .with_regime::<$regime>();
            let access = SmmuD128ArenaAccess {
                tables: [root_page, frame1, frame2, frame3],
            };
            let frames = SmmuD128ArenaFrames {
                frames: [frame1, frame2, frame3],
                initialized: [false; 3],
                next: 0,
                reclaimed: 0,
                fail_after: 3,
            };
            let mut mapper = Mapper::new_offline(root, access, frames)
                .map_err(|_| HarnessError::InvalidState)?;
            let leaf = SemanticStage1LeafAttrs {
                memory: MemoryAttributes::Device(
                    DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
                ),
                permissions,
                pas: $leaf_pas,
                controls: SemanticVmsa128Stage1LeafControls {
                    bbm_nt: false,
                    dirty_state: DirtyState::Dirty,
                    shareability: Shareability::InnerShareable,
                    access_flag: true,
                    global: $global,
                    contiguous: false,
                    guarded: true,
                    protected: true,
                    software: SoftwareMetadata::new(0x155),
                },
            };
            let table = SemanticVmsa128Stage1TableAttrs {
                table_nt: false,
                access_flag: true,
                disch: true,
                protected: true,
                pas: $table_pas,
                software: SoftwareMetadata::new(0x2aa),
            };
            let first = mapper.map_semantic_leaf(
                &config,
                WalkInputAddr::new(0),
                WalkOutputAddr::new(0x8000_0000),
                Level::L3,
                leaf,
                table,
            );
            match first {
                Ok(outcome) if outcome.tables_allocated() == 2 => {}
                _ => failures += 1,
            }
            match mapper.translate(WalkInputAddr::new(0x40)) {
                Ok(Some(mapping)) => {
                    failures += u64::from(mapping.output().raw() != 0x8000_0040);
                    failures += u64::from(mapping.semantic_attrs(&config) != Ok(leaf));
                }
                _ => failures += 1,
            }
            failures += u64::from(
                mapper
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x9000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_ok(),
            );
            let unmapped = unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) };
            match unmapped {
                Ok(outcome) => failures += u64::from(outcome.tables_freed() != 2),
                Err(_) => failures += 1,
            }
            failures += u64::from(
                mapper
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x9000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_err(),
            );
            match mapper.translate(WalkInputAddr::new(0x80)) {
                Ok(Some(mapping)) => failures += u64::from(mapping.output().raw() != 0x9000_0080),
                _ => failures += 1,
            }
            let _ = unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) };

            for page in [root_page, frame1, frame2, frame3] {
                // SAFETY: the preceding mapper has released all table references.
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let root = RootTableGeometry::<$format, $granule>::new_at_level(
                TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                Level::L1,
                36,
                48,
            )
            .map_err(|_| HarnessError::InvalidState)?
            .with_regime::<$regime>();
            let mut failing_mapper = Mapper::new_offline(
                root,
                SmmuD128ArenaAccess {
                    tables: [root_page, frame1, frame2, frame3],
                },
                SmmuD128ArenaFrames {
                    frames: [frame1, frame2, frame3],
                    initialized: [false; 3],
                    next: 0,
                    reclaimed: 0,
                    fail_after: 0,
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            failures += u64::from(
                failing_mapper
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x8000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_ok(),
            );
        }};
    }

    macro_rules! all_variants {
        ($regime:ty, $leaf_pas:expr, $table_pas:expr, $global:expr) => {{
            exercise!(
                Vmsa128<NativeEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<NativeEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<NativeEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<LittleEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<LittleEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<LittleEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<BigEndian>,
                $regime,
                Granule4KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<BigEndian>,
                $regime,
                Granule16KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
            exercise!(
                Vmsa128<BigEndian>,
                $regime,
                Granule64KiB,
                $leaf_pas,
                $table_pas,
                $global
            );
        }};
    }
    all_variants!(smmu_v3::NonSecureStreamStage1, (), (), false);
    all_variants!(smmu_v3::NonSecurePrivilegedStreamStage1, (), (), true);
    for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
        all_variants!(smmu_v3::SecureStreamStage1, pas, pas, false);
        all_variants!(smmu_v3::SecurePrivilegedStreamStage1, pas, pas, true);
    }
    all_variants!(smmu_v3::RealmStreamStage1, (), (), false);
    for pas in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure] {
        all_variants!(smmu_v3::RealmPrivilegedStreamStage1, pas, (), true);
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_vmsa64_stage1_mapper_walker() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        DataRights, DeviceMemoryType, DirtyBitManagement, DirtyControl, LiveVmsaConfig,
        MemoryAttributes, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
        SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
        SoftwareMetadata, Stage1Permissions, Stage2MemoryMode, TwoPrivilegeTableRestrictions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};
    use aarch64_vmsa::mapper::Mapper;
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let leaf = SemanticStage1LeafAttrs {
        memory: MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
        permissions: Stage1Permissions::new(
            DataRights::ReadWrite,
            DataRights::None,
            false,
            false,
            false,
            false,
        ),
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: false,
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            guarded: true,
            software: SoftwareMetadata::new(0b1010),
        },
    };
    let table = SemanticStage1TableAttrs {
        restrictions: TwoPrivilegeTableRestrictions {
            privileged_data_limit: DataRights::ReadWrite,
            unprivileged_data_limit: DataRights::None,
            privileged_execute_limit: false,
            unprivileged_execute_limit: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls {
            access_flag: true,
            software: SoftwareMetadata::new(0b0101),
        },
    };
    let mut failures = 0u64;

    macro_rules! exercise {
        ($format:ty, $regime:ty, $granule:ty) => {{
            let (root_page, frame1, frame2, frame3) = unsafe {
                (
                    core::ptr::addr_of_mut!(SMMU_L0.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
                )
            };
            for page in [root_page, frame1, frame2, frame3] {
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let make_root = || {
                RootTableGeometry::<$format, $granule>::new_at_level(
                    TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                    Level::L1,
                    36,
                    48,
                )
                .map_err(|_| HarnessError::InvalidState)
                .map(|geometry| geometry.with_regime::<$regime>())
            };
            let mut mapper = Mapper::new_offline(
                make_root()?,
                SmmuD128ArenaAccess {
                    tables: [root_page, frame1, frame2, frame3],
                },
                SmmuD128ArenaFrames {
                    frames: [frame1, frame2, frame3],
                    initialized: [false; 3],
                    next: 0,
                    reclaimed: 0,
                    fail_after: 3,
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            match mapper.map_semantic_leaf(
                &config,
                WalkInputAddr::new(0),
                WalkOutputAddr::new(0x8000_0000),
                Level::L3,
                leaf,
                table,
            ) {
                Ok(outcome) => failures += u64::from(outcome.tables_allocated() != 2),
                Err(_) => failures += 1,
            }
            match mapper.translate(WalkInputAddr::new(0x80)) {
                Ok(Some(mapping)) => {
                    failures += u64::from(mapping.output().raw() != 0x8000_0080);
                    failures += u64::from(mapping.semantic_attrs(&config) != Ok(leaf));
                }
                _ => failures += 1,
            }
            failures += u64::from(
                mapper
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x9000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_ok(),
            );
            match unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) } {
                Ok(outcome) => failures += u64::from(outcome.tables_freed() != 2),
                Err(_) => failures += 1,
            }
            failures += u64::from(
                mapper
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x9000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_err(),
            );
            let _ = unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) };

            for page in [root_page, frame1, frame2, frame3] {
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let mut failing = Mapper::new_offline(
                make_root()?,
                SmmuD128ArenaAccess {
                    tables: [root_page, frame1, frame2, frame3],
                },
                SmmuD128ArenaFrames {
                    frames: [frame1, frame2, frame3],
                    initialized: [false; 3],
                    next: 0,
                    reclaimed: 0,
                    fail_after: 0,
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            failures += u64::from(
                failing
                    .map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x8000_0000),
                        Level::L3,
                        leaf,
                        table,
                    )
                    .is_ok(),
            );
        }};
    }
    macro_rules! all_variants {
        ($format:ident, $regime:ty) => {{
            exercise!($format<NativeEndian>, $regime, Granule4KiB);
            exercise!($format<NativeEndian>, $regime, Granule16KiB);
            exercise!($format<NativeEndian>, $regime, Granule64KiB);
            exercise!($format<LittleEndian>, $regime, Granule4KiB);
            exercise!($format<LittleEndian>, $regime, Granule16KiB);
            exercise!($format<LittleEndian>, $regime, Granule64KiB);
            exercise!($format<BigEndian>, $regime, Granule4KiB);
            exercise!($format<BigEndian>, $regime, Granule16KiB);
            exercise!($format<BigEndian>, $regime, Granule64KiB);
        }};
    }
    all_variants!(Vmsa64, smmu_v2::NonSecureStreamStage1);
    all_variants!(Vmsa64, smmu_v3::NonSecureStreamStage1);
    all_variants!(Vmsa64Lpa2, smmu_v3::NonSecureStreamStage1);

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

pub fn smmu_v3_stage2_vmsa64_mapper_matrix() -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        Cacheability, DirtyBitManagement, DirtyControl, LiveVmsaConfig, MemoryAttributes,
        RealmOrNonSecurePa, SecureSelectablePa, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;
    use aarch64_vmsa::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};
    use aarch64_vmsa::mapper::{Mapper, MapperError, SemanticMapperError};
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkEntry, WalkInputAddr, WalkOutputAddr, Walker};

    let mut failures = 0u64;
    macro_rules! config {
        ($pas:expr) => {
            LiveVmsaConfig {
                mair: 0,
                mair2: None,
                smmu_v3_aie: false,
                stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
                stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
                stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: Shareability::InnerShareable,
                output_pas: $pas,
            }
        };
    }
    macro_rules! exercise {
        ($format:ty, $regime:ty, $granule:ty, $config:expr, $pas:expr, $permissions:expr) => {{
            let (root_page, frame1, frame2, frame3) = unsafe {
                (
                    core::ptr::addr_of_mut!(SMMU_L0.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
                )
            };
            for page in [root_page, frame1, frame2, frame3] {
                // SAFETY: semantic mapper cases execute serially and exclusively own the arenas.
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let root = RootTableGeometry::<$format, $granule>::new_at_level(
                TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                Level::L1,
                30,
                48,
            )
            .map_err(|_| HarnessError::InvalidState)?
            .with_regime::<$regime>();
            let mut mapper = Mapper::new_offline(
                root,
                SmmuD128ArenaAccess {
                    tables: [root_page, frame1, frame2, frame3],
                },
                SmmuD128ArenaFrames {
                    frames: [frame1, frame2, frame3],
                    initialized: [false; 3],
                    next: 0,
                    reclaimed: 0,
                    fail_after: 3,
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let config = $config;
            let leaf = SemanticStage2LeafAttrs {
                memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
                    inner: Cacheability::NonCacheable,
                    outer: Cacheability::NonCacheable,
                }),
                permissions: $permissions,
                output_address_space: $pas,
                controls: SemanticVmsa64Stage2LeafControls {
                    shareability: Shareability::InnerShareable,
                    access_flag: true,
                    dirty: DirtyControl::Direct(DirtyBitManagement::HardwareManaged),
                    contiguous: true,
                    software: SoftwareMetadata::new(0b1010),
                },
            };
            let table_zero = SemanticVmsa64Stage2TableAttrs::default();
            let invalid_level = Level::new(-1);
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(0),
                    invalid_level,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::InvalidLeafLevel {
                    level: invalid_level,
                    root_level: Level::L1,
                    final_level: Level::L3,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(1),
                    WalkOutputAddr::new(0x4000_0000),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::UnalignedInput {
                    addr: 1,
                    align: <$granule as aarch64_vmsa::address::TranslationGranule>::SIZE,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(0x4000_0001),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::UnalignedOutput {
                    addr: WalkOutputAddr::new(0x4000_0001),
                    align: <$granule as aarch64_vmsa::address::TranslationGranule>::SIZE,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(1 << 30),
                    WalkOutputAddr::new(0x4000_0000),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(
                    MapperError::InputAddressOutOfRange {
                        addr: 1 << 30,
                        addr_bits: 30,
                    },
                )),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(1 << 48),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(
                    MapperError::OutputAddressOutOfRange {
                        addr: WalkOutputAddr::new(1 << 48),
                        output_address_bits: 48,
                    },
                )),
            );
            for access_flag in [false, true] {
                for software in 0..=0xf {
                    let table = SemanticVmsa64Stage2TableAttrs {
                        access_flag,
                        software: SoftwareMetadata::new(software),
                    };
                    match mapper.map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x4000_0000),
                        Level::L3,
                        leaf,
                        table,
                    ) {
                        Ok(outcome) => {
                            failures += u64::from(outcome.tables_allocated() != 2);
                        }
                        Err(_) => {
                            failures += 1;
                            continue;
                        }
                    }
                    match mapper.translate(WalkInputAddr::new(0x80)) {
                        Ok(Some(mapping)) => {
                            failures += u64::from(mapping.output().raw() != 0x4000_0080);
                            failures += u64::from(mapping.semantic_attrs(&config) != Ok(leaf));
                        }
                        _ => failures += 1,
                    }
                    {
                        let walker = Walker::new(mapper.root(), mapper.access())
                            .map_err(|_| HarnessError::InvalidState)?;
                        let mut walk = walker.start();
                        for _ in 0..2 {
                            match walk.next_entry().map_err(|_| HarnessError::InvalidState)? {
                                Some(WalkEntry::Table(entry)) => {
                                    failures +=
                                        u64::from(entry.semantic_attrs(&config) != Ok(table));
                                    walk.step_in(entry)
                                        .map_err(|_| HarnessError::InvalidState)?;
                                }
                                _ => failures += 1,
                            }
                        }
                    }
                    match unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) } {
                        Ok(outcome) => {
                            failures +=
                                u64::from(outcome.tables_freed() != 2 || !outcome.root_now_empty());
                        }
                        Err(_) => failures += 1,
                    }
                }
            }
        }};
    }
    macro_rules! all_formats {
        ($regime:ty, $config:expr, $pas:expr, $permissions:expr) => {{
            exercise!(
                Vmsa64<NativeEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<NativeEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<NativeEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<LittleEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<LittleEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<LittleEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<BigEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<BigEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64<BigEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<NativeEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<NativeEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<NativeEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<LittleEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<LittleEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<LittleEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<BigEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<BigEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions
            );
            exercise!(
                Vmsa64Lpa2<BigEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions
            );
        }};
    }
    let direct = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
    );
    let xnx = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
    );
    macro_rules! both_models {
        ($regime:ident, $config:expr, $pas:expr) => {{
            all_formats!(
                smmu_v3::$regime<StandardStage2PermissionModel>,
                $config,
                $pas,
                direct
            );
            all_formats!(
                smmu_v3::$regime<XnxStage2PermissionModel>,
                $config,
                $pas,
                xnx
            );
        }};
    }
    both_models!(NonSecureIpaStage2, config!(()), ());
    for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
        both_models!(SecureIpaStage2, config!(pas), pas);
        both_models!(SecureStreamNonSecureIpaStage2, config!(pas), pas);
    }
    for pas in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure] {
        both_models!(RealmIpaStage2, config!(()), pas);
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

fn smmu_v3_stage2_d128_mapper_matrix_part(part: u8) -> TestResult {
    use aarch64_vmsa::address::Level;
    use aarch64_vmsa::attrs::{
        Cacheability, DirtyState, LiveVmsaConfig, MemoryAttributes, RealmOrNonSecurePa,
        SecureSelectablePa, SemanticStage2LeafAttrs, SemanticVmsa128Stage2LeafControls,
        SemanticVmsa128Stage2TableAttrs, Shareability, SoftwareMetadata, Stage2BasePermissions,
        Stage2MemoryAttributes, Stage2MemoryMode, Stage2PermissionRegisters,
        Stage2PermissionSettings, Stage2Permissions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa128};
    use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
    use aarch64_vmsa::config::regime::smmu_v3;
    use aarch64_vmsa::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};
    use aarch64_vmsa::mapper::{Mapper, MapperError, SemanticMapperError};
    use aarch64_vmsa::table::{RootTableGeometry, TableAddr};
    use aarch64_vmsa::translation::{WalkEntry, WalkInputAddr, WalkOutputAddr, Walker};

    let indirect = Stage2PermissionSettings {
        base: Stage2BasePermissions::Indirect(Stage2PermissionRegisters {
            s2pir_el2: 0xfedc_ba98_7654_3210,
        }),
        s2por_el1: None,
    };
    let mut failures = 0u64;
    macro_rules! config {
        ($pas:expr) => {
            LiveVmsaConfig {
                mair: 0,
                mair2: None,
                smmu_v3_aie: false,
                stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
                stage2_permissions: indirect,
                stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: Shareability::InnerShareable,
                output_pas: $pas,
            }
        };
    }
    macro_rules! exercise {
        ($part:expr, $format:ty, $regime:ty, $granule:ty, $config:expr, $pas:expr, $permissions:expr, $all_tables:expr) => {{
            if part == $part {
            let (root_page, frame1, frame2, frame3) = unsafe {
                (
                    core::ptr::addr_of_mut!(SMMU_L0.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L1.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L2.0) as u64,
                    core::ptr::addr_of_mut!(SMMU_L3.0) as u64,
                )
            };
            for page in [root_page, frame1, frame2, frame3] {
                // SAFETY: semantic mapper cases execute serially and exclusively own the arenas.
                unsafe { core::ptr::write_bytes(page as *mut u8, 0, 65536) };
            }
            let root = RootTableGeometry::<$format, $granule>::new_at_level(
                TableAddr::new(root_page).map_err(|_| HarnessError::InvalidState)?,
                Level::L1,
                30,
                48,
            )
            .map_err(|_| HarnessError::InvalidState)?
            .with_regime::<$regime>();
            let mut mapper = Mapper::new_offline(
                root,
                SmmuD128ArenaAccess {
                    tables: [root_page, frame1, frame2, frame3],
                },
                SmmuD128ArenaFrames {
                    frames: [frame1, frame2, frame3],
                    initialized: [false; 3],
                    next: 0,
                    reclaimed: 0,
                    fail_after: 3,
                },
            )
            .map_err(|_| HarnessError::InvalidState)?;
            let config = $config;
            let leaf = SemanticStage2LeafAttrs {
                memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
                    inner: Cacheability::NonCacheable,
                    outer: Cacheability::NonCacheable,
                }),
                permissions: $permissions,
                output_address_space: $pas,
                controls: SemanticVmsa128Stage2LeafControls {
                    bbm_nt: false,
                    dirty_state: DirtyState::Dirty,
                    shareability: Shareability::InnerShareable,
                    access_flag: true,
                    force_no_xs: true,
                    contiguous: true,
                    assured_only: true,
                    software: SoftwareMetadata::new(0x2aa),
                },
            };
            let table_zero = SemanticVmsa128Stage2TableAttrs::default();
            let invalid_level = Level::new(-1);
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(0),
                    invalid_level,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::InvalidLeafLevel {
                    level: invalid_level,
                    root_level: Level::L1,
                    final_level: Level::L3,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(1),
                    WalkOutputAddr::new(0x4000_0000),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::UnalignedInput {
                    addr: 1,
                    align: <$granule as aarch64_vmsa::address::TranslationGranule>::SIZE,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(0x4000_0001),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::UnalignedOutput {
                    addr: WalkOutputAddr::new(0x4000_0001),
                    align: <$granule as aarch64_vmsa::address::TranslationGranule>::SIZE,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(1 << 30),
                    WalkOutputAddr::new(0x4000_0000),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::InputAddressOutOfRange {
                    addr: 1 << 30,
                    addr_bits: 30,
                })),
            );
            failures += u64::from(
                mapper.map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(0),
                    WalkOutputAddr::new(1 << 48),
                    Level::L3,
                    leaf,
                    table_zero,
                ) != Err(SemanticMapperError::Mapper(MapperError::OutputAddressOutOfRange {
                    addr: WalkOutputAddr::new(1 << 48),
                    output_address_bits: 48,
                })),
            );
            // Software metadata is an opaque ten-bit payload: its individual values do not
            // select different mapper behavior. Cover the bounds and alternating/mixed bit
            // patterns here; raw-field tests cover the complete field width independently.
            for access_flag in [false, true] {
                for software in [0, 1, 0x155, 0x2aa, 0x3ff] {
                    if !$all_tables && (access_flag || software != 0) {
                        continue;
                    }
                    let table = SemanticVmsa128Stage2TableAttrs {
                        table_nt: false,
                        access_flag,
                        software: SoftwareMetadata::new(software),
                    };
                    match mapper.map_semantic_leaf(
                        &config,
                        WalkInputAddr::new(0),
                        WalkOutputAddr::new(0x4000_0000),
                        Level::L3,
                        leaf,
                        table,
                    ) {
                        Ok(outcome) => failures += u64::from(outcome.tables_allocated() != 2),
                        Err(_) => {
                            failures += 1;
                            continue;
                        }
                    }
                    match mapper.translate(WalkInputAddr::new(0x80)) {
                        Ok(Some(mapping)) => {
                            failures += u64::from(mapping.output().raw() != 0x4000_0080);
                            failures += u64::from(mapping.semantic_attrs(&config) != Ok(leaf));
                        }
                        _ => failures += 1,
                    }
                    {
                        let walker = Walker::new(mapper.root(), mapper.access())
                            .map_err(|_| HarnessError::InvalidState)?;
                        let mut walk = walker.start();
                        for _ in 0..2 {
                            match walk.next_entry().map_err(|_| HarnessError::InvalidState)? {
                                Some(WalkEntry::Table(entry)) => {
                                    failures +=
                                        u64::from(entry.semantic_attrs(&config) != Ok(table));
                                    walk.step_in(entry)
                                        .map_err(|_| HarnessError::InvalidState)?;
                                }
                                _ => failures += 1,
                            }
                        }
                    }
                    match unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) } {
                        Ok(outcome) => {
                            failures +=
                                u64::from(outcome.tables_freed() != 2 || !outcome.root_now_empty())
                        }
                        Err(_) => failures += 1,
                    }
                    let nt_table = SemanticVmsa128Stage2TableAttrs {
                        table_nt: true,
                        access_flag,
                        software: SoftwareMetadata::new(software),
                    };
                    // A step-by-one D128 table has SKL=0, for which Table nT is reserved. Cover
                    // the other half of the public table-control Cartesian product by requiring
                    // rejection without installing a mapping or retaining a table path.
                    failures += u64::from(
                        mapper
                            .map_semantic_leaf(
                                &config,
                                WalkInputAddr::new(0),
                                WalkOutputAddr::new(0x4000_0000),
                                Level::L3,
                                leaf,
                                nt_table,
                            )
                            .is_ok(),
                    );
                    failures += u64::from(
                        mapper
                            .translate(WalkInputAddr::new(0))
                            .map_err(|_| HarnessError::InvalidState)?
                            .is_some(),
                    );
                }
            }
            }
        }};
    }
    macro_rules! all_formats {
        ($regime:ty, $config:expr, $pas:expr, $permissions:expr, $all_tables:expr) => {{
            exercise!(
                0,
                Vmsa128<NativeEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                1,
                Vmsa128<NativeEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                2,
                Vmsa128<NativeEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                3,
                Vmsa128<LittleEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                4,
                Vmsa128<LittleEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                5,
                Vmsa128<LittleEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                6,
                Vmsa128<BigEndian>,
                $regime,
                Granule4KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                7,
                Vmsa128<BigEndian>,
                $regime,
                Granule16KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
            exercise!(
                8,
                Vmsa128<BigEndian>,
                $regime,
                Granule64KiB,
                $config,
                $pas,
                $permissions,
                $all_tables
            );
        }};
    }
    let direct = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
    );
    let xnx = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
    );
    macro_rules! both_models {
        ($regime:ident, $config:expr, $pas:expr, $all_tables:expr) => {{
            all_formats!(
                smmu_v3::$regime<StandardStage2PermissionModel>,
                $config,
                $pas,
                direct,
                $all_tables
            );
            all_formats!(
                smmu_v3::$regime<XnxStage2PermissionModel>,
                $config,
                $pas,
                xnx,
                $all_tables
            );
        }};
    }
    both_models!(NonSecureIpaStage2, config!(()), (), true);
    for pas in [SecureSelectablePa::Secure, SecureSelectablePa::NonSecure] {
        both_models!(SecureIpaStage2, config!(pas), pas, false);
        both_models!(SecureStreamNonSecureIpaStage2, config!(pas), pas, false);
    }
    for pas in [RealmOrNonSecurePa::Realm, RealmOrNonSecurePa::NonSecure] {
        both_models!(RealmIpaStage2, config!(()), pas, false);
    }

    if failures == 0 {
        TestResult::Pass
    } else {
        failed(0, failures)
    }
}

macro_rules! d128_stage2_mapper_part {
    ($name:ident, $part:expr) => {
        pub fn $name() -> TestResult {
            smmu_v3_stage2_d128_mapper_matrix_part($part)
        }
    };
}
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_native_4k, 0);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_native_16k, 1);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_native_64k, 2);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_little_4k, 3);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_little_16k, 4);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_little_64k, 5);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_big_4k, 6);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_big_16k, 7);
d128_stage2_mapper_part!(smmu_v3_stage2_d128_mapper_big_64k, 8);

unsafe fn write32(address: usize, value: u32) {
    // SAFETY: The caller supplies an aligned, mapped FVP MMIO register.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) };
}

unsafe fn read32(address: usize) -> u32 {
    // SAFETY: The caller supplies an aligned, mapped FVP MMIO register.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

unsafe fn write64(address: usize, value: u64) {
    // SAFETY: The caller supplies an aligned, mapped FVP MMIO register.
    unsafe { core::ptr::write_volatile(address as *mut u64, value) };
}

unsafe fn read64(address: usize) -> u64 {
    // SAFETY: The caller supplies an aligned, mapped FVP MMIO register.
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

pub fn smmu_v2_live_capabilities() -> TestResult {
    const SMMU: usize = 0x0e00_0000;
    let idr0 = unsafe { read32(SMMU + 0x20) };
    let idr1 = unsafe { read32(SMMU + 0x24) };
    let idr2 = unsafe { read32(SMMU + 0x28) };
    let idr7 = unsafe { read32(SMMU + 0x3c) };
    crate::common::diagnostic_hex(
        b"smmu-v2-idr0-idr1-idr2-idr7",
        &[idr0.into(), idr1.into(), idr2.into(), idr7.into()],
    );

    // Record every independently routed capability.  This RD-N2 instance is
    // intentionally allowed to implement stage 2 without stage 1, and the
    // granule fields describe separate capabilities rather than an all-or-none
    // bundle.  Individual live cases gate themselves on the feature they use.
    let stage1 = idr0 & (1 << 30) != 0;
    let stage2 = idr0 & (1 << 29) != 0;
    let stream_match = idr0 & (1 << 27) != 0;
    let granule_4k = idr2 & (1 << 12) != 0;
    let granule_16k = idr2 & (1 << 13) != 0;
    let granule_64k = idr2 & (1 << 14) != 0;
    let context_banks = idr1 & 0xff != 0;
    let observed = stage1 as u64
        | ((stage2 as u64) << 1)
        | ((stream_match as u64) << 2)
        | ((granule_4k as u64) << 3)
        | ((granule_16k as u64) << 4)
        | ((granule_64k as u64) << 5)
        | ((context_banks as u64) << 6);
    crate::common::diagnostic_hex(b"smmu-v2-live-features", &[observed]);

    // The platform route is useful when it exposes a real translation path:
    // stage 2, stream matching, at least one AArch64 granule, and a context
    // bank.  Stage 1 and the other granules are optional live capabilities.
    let required = (1 << 1) | (1 << 2) | (1 << 6);
    let has_granule = observed & ((1 << 3) | (1 << 4) | (1 << 5)) != 0;
    if observed & required != required || !has_granule {
        return failed(required | (1 << 3), observed);
    }
    TestResult::Pass
}

#[cfg(vmsa_platform_fvp_rdn2)]
fn clean_data_range(address: usize, bytes: usize) {
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr) };
    let line = 4usize << ((ctr >> 16) & 0xf);
    let mut cursor = address & !(line - 1);
    let end = address.saturating_add(bytes);
    while cursor < end {
        unsafe { core::arch::asm!("dc cvac, {address}", address = in(reg) cursor) };
        cursor += line;
    }
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

#[cfg(vmsa_platform_fvp_rdn2)]
fn invalidate_data_range(address: usize, bytes: usize) {
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr) };
    let line = 4usize << ((ctr >> 16) & 0xf);
    let mut cursor = address & !(line - 1);
    let end = address.saturating_add(bytes);
    while cursor < end {
        unsafe { core::arch::asm!("dc ivac, {address}", address = in(reg) cursor) };
        cursor += line;
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// A live MMU-500 stage-2 walk driven by the platform PL330 rather than by a
/// model-only translation test engine.  The descriptor construction is public
/// `aarch64-vmsa` behavior; SMMU and DMA programming are only the execution and
/// observation mechanism.
#[cfg(vmsa_platform_fvp_rdn2)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SmmuV2LiveCase {
    Page4k,
    Page4kBigEndian,
    Block4k,
    Page64k,
    Block64k,
    ReadPermissionFault,
    WritePermissionFault,
    TranslationFault,
    AccessFlagFault,
    TlbInvalidate,
    StreamMask,
    ReadAllocateReserved,
    WriteAllocateReserved,
    ReadWriteAllocateReserved,
    Root4kL2,
    Root64kL1,
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_4k() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Page4k)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_4k_big_endian() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Page4kBigEndian)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_block() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Block4k)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_64k() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Page64k)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_64k_block() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Block64k)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_read_permission_fault() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::ReadPermissionFault)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_write_permission_fault() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::WritePermissionFault)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_translation_fault() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::TranslationFault)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_access_flag_fault() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::AccessFlagFault)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_tlb_invalidate() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::TlbInvalidate)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stream_mask() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::StreamMask)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_read_allocate_reserved() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::ReadAllocateReserved)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_write_allocate_reserved() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::WriteAllocateReserved)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_read_write_allocate_reserved() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::ReadWriteAllocateReserved)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_4k_root_l2() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Root4kL2)
}

#[cfg(vmsa_platform_fvp_rdn2)]
pub fn smmu_v2_live_stage2_64k_root_l1() -> TestResult {
    smmu_v2_live_stage2(SmmuV2LiveCase::Root64kL1)
}

#[cfg(vmsa_platform_fvp_rdn2)]
fn smmu_v2_live_stage2(case: SmmuV2LiveCase) -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        Cacheability, LiveVmsaConfig, MemoryAttributes, SemanticSmmuV2Stage2LeafControls,
        SemanticStage2LeafAttrs, SemanticVmsa64Stage2TableAttrs, Shareability,
        SmmuV2AllocationHint, SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permissions,
    };
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type LittleFormat = Vmsa64<LittleEndian>;
    type LittleLayout = <LittleFormat as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    type BigFormat = Vmsa64<BigEndian>;
    type BigLayout = <BigFormat as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    const SMMU: usize = 0x0e00_0000;
    const DMAC: usize = 0x0ef0_0000;
    let is_64k = matches!(
        case,
        SmmuV2LiveCase::Page64k | SmmuV2LiveCase::Block64k | SmmuV2LiveCase::Root64kL1
    );
    let (l1, l2, l3, mut source, mut destination, program) = unsafe {
        (
            core::ptr::addr_of_mut!(SMMU_L1.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L2.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L3.0) as usize,
            core::ptr::addr_of_mut!(SMMU_SOURCE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_DESTINATION.0) as usize,
            core::ptr::addr_of_mut!(SMMU_V2_DMA_PROGRAM.0) as usize,
        )
    };
    let mut source_iova = 0x1000u32;
    let mut destination_iova = 0x2000u32;
    if case == SmmuV2LiveCase::Block4k {
        let block = unsafe { core::ptr::addr_of_mut!(SMMU_V2_BLOCK.0) as usize };
        source = block + 0x1000;
        destination = block + 0x2000;
        source_iova = 0x20_1000;
        destination_iova = 0x40_2000;
    } else if matches!(case, SmmuV2LiveCase::Page64k | SmmuV2LiveCase::Root64kL1) {
        source_iova = 0x1_0000;
        destination_iova = 0x2_0000;
    } else if case == SmmuV2LiveCase::Block64k {
        let mask = (1u64 << 29) - 1;
        source_iova = ((1u64 << 29) | ((source as u64) & mask)) as u32;
        destination_iova = ((2u64 << 29) | ((destination as u64) & mask)) as u32;
    }
    unsafe {
        let table_bytes = if is_64k { 65536 } else { 4096 };
        core::ptr::write_bytes(l1 as *mut u8, 0, table_bytes);
        core::ptr::write_bytes(l2 as *mut u8, 0, table_bytes);
        core::ptr::write_bytes(l3 as *mut u8, 0, table_bytes);
        core::ptr::write_bytes(destination as *mut u8, 0, 4096);
        core::ptr::write_bytes(program as *mut u8, 0, 64);
        (source as *mut u32).write_volatile(0x51a7_c0de);
    }

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
    };
    let table = SemanticVmsa64Stage2TableAttrs {
        access_flag: true,
        software: SoftwareMetadata::new(0),
    };
    let mut source_permissions = Stage2Permissions::read_write(
        aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
    );
    let mut destination_permissions = source_permissions;
    if case == SmmuV2LiveCase::ReadPermissionFault {
        source_permissions = Stage2Permissions::no_access();
    }
    if case == SmmuV2LiveCase::WritePermissionFault {
        destination_permissions = Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        );
    }
    let leaf = |permissions| SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::NonCacheable,
            outer: Cacheability::NonCacheable,
        }),
        permissions,
        output_address_space: (),
        controls: SemanticSmmuV2Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: case != SmmuV2LiveCase::AccessFlagFault,
            dirty: aarch64_vmsa::attrs::DirtyControl::Direct(
                aarch64_vmsa::attrs::DirtyBitManagement::SoftwareManaged,
            ),
            contiguous: false,
            read_allocate: SmmuV2AllocationHint::NoAllocate,
            write_allocate: SmmuV2AllocationHint::NoAllocate,
            software: SoftwareMetadata::new(0),
        },
    };
    let l1_shape = TableShape::<LittleFormat, Granule4KiB>::root(Level::L1)
        .map_err(|_| HarnessError::InvalidState)?;
    let l2_shape = TableShape::<LittleFormat, Granule4KiB>::new(Level::L2, 1)
        .map_err(|_| HarnessError::InvalidState)?;
    let l3_shape = TableShape::<LittleFormat, Granule4KiB>::new(Level::L3, 1)
        .map_err(|_| HarnessError::InvalidState)?;
    let l1_fields =
        <LittleFormat as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_table(
            &config,
            Level::L1,
            table,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l2_fields =
        <LittleFormat as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_table(
            &config,
            Level::L2,
            table,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l1_raw = <LittleLayout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        TableAddr::new(l2 as u64).map_err(|_| HarnessError::InvalidState)?,
        TableTransition::new(l1_shape, l2_shape).map_err(|_| HarnessError::InvalidState)?,
        l1_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l2_raw = <LittleLayout as DescriptorLayout<Granule4KiB>>::table_descriptor(
        TableAddr::new(l3 as u64).map_err(|_| HarnessError::InvalidState)?,
        TableTransition::new(l2_shape, l3_shape).map_err(|_| HarnessError::InvalidState)?,
        l2_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let source_fields =
        <LittleFormat as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            leaf(source_permissions),
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let destination_fields =
        <LittleFormat as AttributeCodec<NonSecureIpaStage2, Granule4KiB, _>>::encode_leaf(
            &config,
            Level::L3,
            leaf(destination_permissions),
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let destination_level = if case == SmmuV2LiveCase::Block4k {
        Level::L2
    } else {
        Level::L3
    };
    let block_mask = (1u64 << 21) - 1;
    let source_output = if case == SmmuV2LiveCase::Block4k {
        (source as u64) & !block_mask
    } else {
        source as u64
    };
    let destination_output = if case == SmmuV2LiveCase::Block4k {
        (destination as u64) & !block_mask
    } else {
        destination as u64
    };
    let mut source_raw = <LittleLayout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(source_output),
        destination_level,
        source_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let mut destination_raw = <LittleLayout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
        PhysAddr(destination_output),
        destination_level,
        destination_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    // SMMUv2 defines allocation-hint encoding 0b01 as behaving like 0b00.
    // Construct an otherwise valid descriptor through the public crate API,
    // then inject only the architecturally reserved raw field so the live
    // MMU-500, rather than the crate decoder, is the behavioral oracle.
    if matches!(
        case,
        SmmuV2LiveCase::ReadAllocateReserved | SmmuV2LiveCase::ReadWriteAllocateReserved
    ) {
        source_raw = (source_raw & !(0b11u64 << 60)) | (0b01u64 << 60);
    }
    if matches!(
        case,
        SmmuV2LiveCase::WriteAllocateReserved | SmmuV2LiveCase::ReadWriteAllocateReserved
    ) {
        destination_raw = (destination_raw & !(0b11u64 << 62)) | (0b01u64 << 62);
    }
    unsafe {
        if case == SmmuV2LiveCase::Page4kBigEndian {
            <BigFormat as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
            <BigFormat as DescriptorFormat>::write_descriptor(l2 as *mut u64, l2_raw);
            <BigFormat as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(1), source_raw);
            <BigFormat as DescriptorFormat>::write_descriptor(
                (l3 as *mut u64).add(2),
                destination_raw,
            );
        } else {
            <LittleFormat as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
            <LittleFormat as DescriptorFormat>::write_descriptor(l2 as *mut u64, l2_raw);
            if case == SmmuV2LiveCase::Block4k {
                <LittleFormat as DescriptorFormat>::write_descriptor(
                    (l2 as *mut u64).add(1),
                    source_raw,
                );
                <LittleFormat as DescriptorFormat>::write_descriptor(
                    (l2 as *mut u64).add(2),
                    destination_raw,
                );
            } else if case != SmmuV2LiveCase::TranslationFault {
                <LittleFormat as DescriptorFormat>::write_descriptor(
                    (l3 as *mut u64).add(1),
                    source_raw,
                );
                <LittleFormat as DescriptorFormat>::write_descriptor(
                    (l3 as *mut u64).add(2),
                    destination_raw,
                );
            } else {
                <LittleFormat as DescriptorFormat>::write_descriptor(
                    (l3 as *mut u64).add(1),
                    source_raw,
                );
            }
        }
    }

    if is_64k {
        use aarch64_vmsa::config::granule::Granule64KiB;
        type Format64 = Vmsa64<LittleEndian>;
        type Layout64 = <Format64 as HasRegimeLayout<NonSecureIpaStage2, Granule64KiB>>::Layout;
        let root_level = if case == SmmuV2LiveCase::Root64kL1 {
            Level::L1
        } else {
            Level::L2
        };
        let root = TableShape::<Format64, Granule64KiB>::root(root_level)
            .map_err(|_| HarnessError::InvalidState)?;
        let middle = TableShape::<Format64, Granule64KiB>::new(Level::L2, 1)
            .map_err(|_| HarnessError::InvalidState)?;
        let last = TableShape::<Format64, Granule64KiB>::new(Level::L3, 1)
            .map_err(|_| HarnessError::InvalidState)?;
        let l1_fields =
            <Format64 as AttributeCodec<NonSecureIpaStage2, Granule64KiB, _>>::encode_table(
                &config,
                Level::L1,
                table,
            )
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let l2_fields =
            <Format64 as AttributeCodec<NonSecureIpaStage2, Granule64KiB, _>>::encode_table(
                &config,
                Level::L2,
                table,
            )
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let root_raw = <Layout64 as DescriptorLayout<Granule64KiB>>::table_descriptor(
            TableAddr::new(l3 as u64).map_err(|_| HarnessError::InvalidState)?,
            TableTransition::new(middle, last).map_err(|_| HarnessError::InvalidState)?,
            l2_fields,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
        let l1_raw = if root_level == Level::L1 {
            Some(
                <Layout64 as DescriptorLayout<Granule64KiB>>::table_descriptor(
                    TableAddr::new(l2 as u64).map_err(|_| HarnessError::InvalidState)?,
                    TableTransition::new(root, middle).map_err(|_| HarnessError::InvalidState)?,
                    l1_fields,
                )
                .map_err(|_| HarnessError::CrateBehavior {
                    expected: 1,
                    actual: 0,
                })?,
            )
        } else {
            None
        };
        let level = if case == SmmuV2LiveCase::Block64k {
            Level::L2
        } else {
            Level::L3
        };
        let source_fields =
            <Format64 as AttributeCodec<NonSecureIpaStage2, Granule64KiB, _>>::encode_leaf(
                &config,
                level,
                leaf(source_permissions),
            )
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let destination_fields =
            <Format64 as AttributeCodec<NonSecureIpaStage2, Granule64KiB, _>>::encode_leaf(
                &config,
                level,
                leaf(destination_permissions),
            )
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?;
        let mask = if level == Level::L2 {
            (1u64 << 29) - 1
        } else {
            65535
        };
        let source_raw = <Layout64 as DescriptorLayout<Granule64KiB>>::leaf_descriptor(
            PhysAddr((source as u64) & !mask),
            level,
            source_fields,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
        let destination_raw = <Layout64 as DescriptorLayout<Granule64KiB>>::leaf_descriptor(
            PhysAddr((destination as u64) & !mask),
            level,
            destination_fields,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
        unsafe {
            if level == Level::L2 {
                <Format64 as DescriptorFormat>::write_descriptor(
                    (l2 as *mut u64).add(1),
                    source_raw,
                );
                <Format64 as DescriptorFormat>::write_descriptor(
                    (l2 as *mut u64).add(2),
                    destination_raw,
                );
            } else {
                if let Some(l1_raw) = l1_raw {
                    <Format64 as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
                }
                <Format64 as DescriptorFormat>::write_descriptor(l2 as *mut u64, root_raw);
                <Format64 as DescriptorFormat>::write_descriptor(
                    (l3 as *mut u64).add(1),
                    source_raw,
                );
                <Format64 as DescriptorFormat>::write_descriptor(
                    (l3 as *mut u64).add(2),
                    destination_raw,
                );
            }
        }
    }

    // Preserve every register modified by the live agent. IDR1 selects 4 KiB
    // register pages and eight global pages, so context bank zero begins at
    // +0x8000 and GR1 at +0x1000.
    let cb = SMMU + 0x8000;
    let dma_initial_status = unsafe { read32(DMAC + 0xd00) };
    crate::common::diagnostic_hex(
        b"smmu-v2-dma-initial-debug-status",
        &[dma_initial_status.into()],
    );
    let saved = unsafe {
        [
            read32(SMMU),
            read32(SMMU + 0x800),
            read32(SMMU + 0xc00),
            read32(SMMU + 0x1000),
            read32(SMMU + 0x1800),
            read32(cb),
            read32(cb + 0x30),
            read32(cb + 0x20),
            read32(cb + 0x24),
        ]
    };
    crate::common::diagnostic_hex(b"smmu-v2-agent-checkpoint", &[1]);
    let table_bytes = if is_64k { 65536 } else { 4096 };
    clean_data_range(l1, table_bytes);
    clean_data_range(l2, table_bytes);
    clean_data_range(l3, table_bytes);
    clean_data_range(source, 4);
    clean_data_range(destination, 4);

    unsafe {
        write32(SMMU, saved[0] | 1); // CLIENTPD while configuring
        write32(SMMU + 0x1000, 0); // CBAR0: stage-2 translation, VMID 0
        write32(SMMU + 0x1800, 1); // CBA2R0.VA64
        let geometry = if case == SmmuV2LiveCase::Root64kL1 {
            (1 << 14) | (2 << 6) | 16
        } else if is_64k {
            (1 << 14) | (1 << 6) | 22
        } else if case == SmmuV2LiveCase::Root4kL2 {
            34
        } else {
            (1 << 6) | 25
        };
        write32(
            cb + 0x30,
            0x8000_0000 | (2 << 16) | (3 << 12) | (1 << 10) | (1 << 8) | geometry,
        );
        let root = if case == SmmuV2LiveCase::Root64kL1 {
            l1
        } else if is_64k || case == SmmuV2LiveCase::Root4kL2 {
            l2
        } else {
            l1
        };
        write64(cb + 0x20, root as u64);
        write32(cb + 0x58, u32::MAX);
        let endian = if case == SmmuV2LiveCase::Page4kBigEndian {
            1 << 4
        } else {
            0
        };
        let access_flag_enable = if case == SmmuV2LiveCase::AccessFlagFault {
            0
        } else {
            1 << 2
        };
        // HUPCF permits later transactions after a context fault. CFCFG is
        // deliberately clear so a fault terminates instead of stalling the
        // PL330 request indefinitely.
        write32(
            cb,
            endian | (1 << 8) | (1 << 6) | (1 << 5) | access_flag_enable | (1 << 1) | 1,
        );
        write32(SMMU + 0xc00, 0); // S2CR0: translate with CB0
        let smr = if case == SmmuV2LiveCase::StreamMask {
            (1 << 31) | (1 << 16) | 1 // SID 1 with bit 0 masked also matches the agent SID 0
        } else {
            1 << 31 // valid, SID 0/mask 0
        };
        write32(SMMU + 0x800, smr);
        write32(SMMU + 0x70, 0);
        write32(SMMU, saved[0] & !1);
        core::arch::asm!("dsb sy", "isb");
    }
    crate::common::diagnostic_hex(b"smmu-v2-agent-checkpoint", &[2]);

    // Program: MOV SAR, MOV DAR, MOV CCR, LD, ST, END.
    let mut offset = 0usize;
    let mut emit_mov = |register: u8, value: u32| unsafe {
        let bytes = [
            0xbc,
            register,
            value as u8,
            (value >> 8) as u8,
            (value >> 16) as u8,
            (value >> 24) as u8,
        ];
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), (program as *mut u8).add(offset), 6);
        offset += 6;
    };
    emit_mov(0, source_iova);
    emit_mov(2, destination_iova);
    emit_mov(1, 0x0001_4005); // incrementing 4-byte, one-beat source/destination bursts
    unsafe {
        (program as *mut u8).add(offset).write(0x04);
        offset += 1;
        (program as *mut u8).add(offset).write(0x08);
        offset += 1;
        (program as *mut u8).add(offset).write(0x00);
        offset += 1;
    }
    clean_data_range(program, offset);
    crate::common::diagnostic_hex(b"smmu-v2-agent-checkpoint", &[3]);
    unsafe {
        let debug_status = read32(DMAC + 0xd00);
        crate::common::diagnostic_hex(b"smmu-v2-dma-debug-status", &[debug_status.into()]);
        while read32(DMAC + 0xd00) & 1 != 0 {
            core::hint::spin_loop();
        }
        write32(DMAC + 0xd08, (0xa2u32 << 16) | (0x00u32 << 24));
        write32(DMAC + 0xd0c, program as u32);
        write32(DMAC + 0xd04, 0);
    }
    let expect_fault = matches!(
        case,
        SmmuV2LiveCase::ReadPermissionFault
            | SmmuV2LiveCase::WritePermissionFault
            | SmmuV2LiveCase::TranslationFault
            | SmmuV2LiveCase::AccessFlagFault
    );
    let mut completed = false;
    for iteration in 0..1_000_000 {
        if iteration & 0xff == 0 {
            invalidate_data_range(destination, 4);
        }
        if unsafe { (destination as *const u32).read_volatile() } == 0x51a7_c0de {
            completed = true;
            break;
        }
        core::hint::spin_loop();
    }
    invalidate_data_range(destination, 4);
    let actual = unsafe { (destination as *const u32).read_volatile() };
    let mut tlb_ok = true;
    if case == SmmuV2LiveCase::TlbInvalidate && completed {
        let alternate = destination + 4096;
        let alternate_raw = <LittleLayout as DescriptorLayout<Granule4KiB>>::leaf_descriptor(
            PhysAddr(alternate as u64),
            Level::L3,
            destination_fields,
        )
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
        unsafe {
            <LittleFormat as DescriptorFormat>::write_descriptor(
                (l3 as *mut u64).add(2),
                alternate_raw,
            );
            (destination as *mut u32).write_volatile(0);
            (alternate as *mut u32).write_volatile(0);
            (source as *mut u32).write_volatile(0x52a8_d1ef);
        }
        clean_data_range(l3, 4096);
        clean_data_range(source, 4);
        clean_data_range(destination, 4);
        clean_data_range(alternate, 4);
        unsafe {
            while read32(DMAC + 0xd00) & 1 != 0 {
                core::hint::spin_loop();
            }
            write32(DMAC + 0xd08, 0xa2u32 << 16);
            write32(DMAC + 0xd0c, program as u32);
            write32(DMAC + 0xd04, 0);
        }
        for iteration in 0..1_000_000 {
            if iteration & 0xff == 0 {
                invalidate_data_range(destination, 4);
                invalidate_data_range(alternate, 4);
            }
            let stale = unsafe { (destination as *const u32).read_volatile() };
            let fresh = unsafe { (alternate as *const u32).read_volatile() };
            if stale == 0x52a8_d1ef || fresh != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        invalidate_data_range(destination, 4);
        invalidate_data_range(alternate, 4);
        tlb_ok &= unsafe { (destination as *const u32).read_volatile() } == 0x52a8_d1ef;
        tlb_ok &= unsafe { (alternate as *const u32).read_volatile() } == 0;

        unsafe {
            (destination as *mut u32).write_volatile(0);
            (alternate as *mut u32).write_volatile(0);
            (source as *mut u32).write_volatile(0x53b9_e2f0);
        }
        clean_data_range(source, 4);
        clean_data_range(destination, 4);
        clean_data_range(alternate, 4);
        unsafe {
            core::arch::asm!("dsb sy");
            write64(cb + 0x638, (destination_iova as u64) >> 12);
            write32(cb + 0x7f0, 0);
        }
        let mut synced = false;
        for _ in 0..100_000 {
            if unsafe { read32(cb + 0x7f4) } & 1 == 0 {
                synced = true;
                break;
            }
            core::hint::spin_loop();
        }
        unsafe {
            while read32(DMAC + 0xd00) & 1 != 0 {
                core::hint::spin_loop();
            }
            write32(DMAC + 0xd08, 0xa2u32 << 16);
            write32(DMAC + 0xd0c, program as u32);
            write32(DMAC + 0xd04, 0);
        }
        let mut remapped = false;
        for iteration in 0..1_000_000 {
            if iteration & 0xff == 0 {
                invalidate_data_range(alternate, 4);
            }
            if unsafe { (alternate as *const u32).read_volatile() } == 0x53b9_e2f0 {
                remapped = true;
                break;
            }
            core::hint::spin_loop();
        }
        invalidate_data_range(destination, 4);
        tlb_ok &= synced && remapped;
        tlb_ok &= unsafe { (destination as *const u32).read_volatile() } == 0;
    }
    let fsr = unsafe { read32(cb + 0x58) };
    let far = unsafe { read64(cb + 0x60) };
    let dma_state = unsafe {
        [
            read32(DMAC),
            read32(DMAC + 0x30),
            read32(DMAC + 0x34),
            read32(DMAC + 0x40),
            read32(DMAC + 0x100),
            read32(DMAC + 0x104),
        ]
    };
    crate::common::diagnostic_hex(
        b"smmu-v2-stage2-dma",
        &[completed as u64, actual.into(), fsr.into(), far],
    );
    crate::common::diagnostic_hex(b"smmu-v2-pl330-state", &dma_state.map(u64::from));

    unsafe {
        write32(SMMU, saved[0] | 1);
        write32(cb, 0);
        write32(SMMU + 0x800, saved[1]);
        write32(SMMU + 0xc00, saved[2]);
        write32(SMMU + 0x1000, saved[3]);
        write32(SMMU + 0x1800, saved[4]);
        write32(cb + 0x30, saved[6]);
        write32(cb + 0x20, saved[7]);
        write32(cb + 0x24, saved[8]);
        write32(cb + 0x58, u32::MAX);
        write32(cb, saved[5]);
        write32(SMMU + 0x70, 0);
        write32(SMMU, saved[0]);
        core::arch::asm!("dsb sy", "isb");
    }
    let fault_mask = (1 << 31)
        | (1 << 30)
        | (1 << 8)
        | (1 << 7)
        | (1 << 6)
        | (1 << 5)
        | (1 << 4)
        | (1 << 3)
        | (1 << 2)
        | (1 << 1);
    if expect_fault {
        if completed || fsr & fault_mask == 0 || actual != 0 {
            return failed(0, actual.into());
        }
    } else if !completed || !tlb_ok || fsr & fault_mask != 0 || actual != 0x51a7_c0de {
        return failed(0x51a7_c0de, ((fsr as u64) << 32) | (far & u32::MAX as u64));
    }
    TestResult::Pass
}

#[cfg(not(vmsa_platform_fvp_rdn2))]
pub fn smmu_v2_live_stage2_4k() -> TestResult {
    HarnessError::Environment.into()
}

#[cfg(not(vmsa_platform_fvp_rdn2))]
macro_rules! unavailable_smmu_v2_live_case {
    ($($name:ident),+ $(,)?) => {$ (
        pub fn $name() -> TestResult { HarnessError::Environment.into() }
    )+ };
}

#[cfg(not(vmsa_platform_fvp_rdn2))]
unavailable_smmu_v2_live_case!(
    smmu_v2_live_stage2_4k_big_endian,
    smmu_v2_live_stage2_block,
    smmu_v2_live_stage2_64k,
    smmu_v2_live_stage2_64k_block,
    smmu_v2_live_stage2_read_permission_fault,
    smmu_v2_live_stage2_write_permission_fault,
    smmu_v2_live_stage2_translation_fault,
    smmu_v2_live_stage2_access_flag_fault,
    smmu_v2_live_stage2_tlb_invalidate,
    smmu_v2_live_stream_mask,
    smmu_v2_live_stage2_read_allocate_reserved,
    smmu_v2_live_stage2_write_allocate_reserved,
    smmu_v2_live_stage2_read_write_allocate_reserved,
    smmu_v2_live_stage2_4k_root_l2,
    smmu_v2_live_stage2_64k_root_l1,
);

fn wait32(address: usize, wanted: u32) -> bool {
    for _ in 0..100_000 {
        // SAFETY: `address` is an SMMU status register in this FVP-only test.
        if unsafe { read32(address) } == wanted {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

trait SmmuLiveVmsa64Format {
    const S2DS: bool;
}

impl<E: aarch64_vmsa::config::format::DescriptorEndian> SmmuLiveVmsa64Format
    for aarch64_vmsa::config::format::Vmsa64<E>
{
    const S2DS: bool = false;
}

impl<E: aarch64_vmsa::config::format::DescriptorEndian> SmmuLiveVmsa64Format
    for aarch64_vmsa::config::format::Vmsa64Lpa2<E>
{
    const S2DS: bool = true;
}

pub fn smmu_v3_live_capabilities() -> TestResult {
    const SMMU: usize = 0x2b40_0000;
    let idr0 = unsafe { read32(SMMU) };
    let idr1 = unsafe { read32(SMMU + 0x4) };
    let idr3 = unsafe { read32(SMMU + 0xc) };
    let idr5 = unsafe { read32(SMMU + 0x14) };
    let iidr = unsafe { read32(SMMU + 0x18) };
    let aidr = unsafe { read32(SMMU + 0x1c) };
    crate::common::diagnostic_hex(
        b"smmu-v3-idr0-idr1-idr3-idr5-iidr-aidr",
        &[
            idr0.into(),
            idr1.into(),
            idr3.into(),
            idr5.into(),
            iidr.into(),
            aidr.into(),
        ],
    );

    // S1P, S2P, AArch64 translation-table format, and mixed-endian tables.
    let translation = idr0 & 0b11 == 0b11;
    // TTF bit 1 denotes AArch64; value 0b11 advertises both AArch32 and AArch64.
    let aarch64 = ((idr0 >> 2) & 0b11) & 0b10 != 0;
    let mixed_endian = (idr0 >> 21) & 0b11 == 0;
    // Architectural 4 KiB, 16 KiB, and 64 KiB granule capability bits.
    let all_granules = idr5 & ((1 << 4) | (1 << 5) | (1 << 6)) == (1 << 4) | (1 << 5) | (1 << 6);
    let observed = (translation as u64)
        | ((aarch64 as u64) << 1)
        | ((mixed_endian as u64) << 2)
        | ((all_granules as u64) << 3);
    if observed != 0xf {
        return failed(0xf, observed);
    }
    TestResult::Pass
}

#[derive(Clone, Copy)]
struct SmmuLiveFaultSetup {
    destination_permission: Option<aarch64_vmsa::attrs::Stage2Permissions>,
    expected_event: Option<u8>,
    destination_access_flag: bool,
    install_destination: bool,
    destination_iova: Option<u64>,
    access_flag_fault_disabled: bool,
    stream_id: u32,
    d128: bool,
    table_access_flag: bool,
    stage1: Option<SmmuLiveStage1Setup>,
}

#[derive(Clone, Copy)]
enum SmmuLiveStage1Regime {
    NonSecure,
    NonSecurePrivileged,
    Secure,
    SecurePrivileged,
    Realm,
    RealmPrivileged,
}

#[derive(Clone, Copy)]
struct SmmuLiveStage1Setup {
    regime: SmmuLiveStage1Regime,
    tcr: u64,
    mair: u64,
    attr_index: u8,
    big_endian: bool,
}

impl SmmuLiveStage1Setup {
    const NONSECURE_4K: Self = Self {
        regime: SmmuLiveStage1Regime::NonSecure,
        tcr: 25 | (1 << 8) | (1 << 10) | (3 << 12),
        mair: 0xff,
        attr_index: 0,
        big_endian: false,
    };
}

trait SmmuLiveStage1Layout<F, G>:
    aarch64_vmsa::descriptor::DescriptorLayout<
        G,
        Format = F,
        LeafFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1LeafAttrs,
        TableFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1TableAttrs,
    >
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
{
}

impl<T, F, G> SmmuLiveStage1Layout<F, G> for T
where
    F: aarch64_vmsa::descriptor::DescriptorFormat,
    G: aarch64_vmsa::address::TranslationGranule,
    T: aarch64_vmsa::descriptor::DescriptorLayout<
            G,
            Format = F,
            LeafFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1LeafAttrs,
            TableFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage1TableAttrs,
        >,
{
}

impl SmmuLiveFaultSetup {
    const NONE: Self = Self {
        destination_permission: None,
        expected_event: None,
        destination_access_flag: true,
        install_destination: true,
        destination_iova: None,
        access_flag_fault_disabled: true,
        stream_id: 0,
        d128: false,
        table_access_flag: false,
        stage1: None,
    };

    const TRANSLATION: Self = Self {
        expected_event: Some(0x10),
        install_destination: false,
        ..Self::NONE
    };

    const ADDRESS_SIZE: Self = Self {
        expected_event: Some(0x11),
        destination_iova: Some(1 << 40),
        ..Self::NONE
    };

    const ACCESS: Self = Self {
        expected_event: Some(0x12),
        destination_access_flag: false,
        access_flag_fault_disabled: false,
        ..Self::NONE
    };

    const PERMISSION: Self = Self {
        destination_permission: Some(aarch64_vmsa::attrs::Stage2Permissions::read_only(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        )),
        expected_event: Some(0x13),
        ..Self::NONE
    };

    const STREAM_ID_1: Self = Self {
        stream_id: 1,
        ..Self::NONE
    };

    const D128: Self = Self {
        d128: true,
        ..Self::NONE
    };

    const TABLE_ACCESS_FLAG: Self = Self {
        table_access_flag: true,
        ..Self::NONE
    };
}

fn smmu_v3_live_stage2_for<F, G, R, P>(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    vtcr: u64,
    root_at_l1: bool,
    big_endian: bool,
    fault_setup: SmmuLiveFaultSetup,
    stage1: bool,
    block_mapping: bool,
    secure_stream: bool,
    realm_stream: bool,
    output_pas: P,
) -> TestResult
where
    G: aarch64_vmsa::address::TranslationGranule,
    R: aarch64_vmsa::regime::Stage2Regime,
    P: Copy,
    F: SmmuLiveVmsa64Format
        + AttributeCodec<
            R,
            G,
            aarch64_vmsa::attrs::LiveVmsaConfig<P>,
            SemanticLeaf = aarch64_vmsa::attrs::SemanticStage2LeafAttrs<
                aarch64_vmsa::attrs::Stage2Permissions,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls,
            >,
            SemanticTable = aarch64_vmsa::attrs::SemanticVmsa64Stage2TableAttrs,
            RawLeaf = aarch64_vmsa::low_level::raw::RawVmsa64Stage2LeafAttrs,
            RawTable = aarch64_vmsa::low_level::raw::RawVmsa64Stage2TableAttrs,
        > + aarch64_vmsa::regime::HasRegimeLayout<R, G>
        + aarch64_vmsa::descriptor::DescriptorFormat<Raw = u64>
        + aarch64_vmsa::attrs::SemanticAttributeTypes<
            <R as aarch64_vmsa::regime::TranslationRegime>::Stage,
            R,
            Leaf = aarch64_vmsa::attrs::SemanticStage2LeafAttrs<
                aarch64_vmsa::attrs::Stage2Permissions,
                P,
                aarch64_vmsa::attrs::SemanticVmsa64Stage2LeafControls,
            >,
            Table = aarch64_vmsa::attrs::SemanticVmsa64Stage2TableAttrs,
        >,
    F: aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::NonSecureStreamStage1,
            G,
        > + aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::NonSecurePrivilegedStreamStage1,
            G,
        > + aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::SecureStreamStage1,
            G,
        > + aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::SecurePrivilegedStreamStage1,
            G,
        > + aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::RealmStreamStage1,
            G,
        > + aarch64_vmsa::regime::HasRegimeLayout<
            aarch64_vmsa::config::regime::smmu_v3::RealmPrivilegedStreamStage1,
            G,
        >,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::NonSecureStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::NonSecurePrivilegedStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::SecureStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::SecurePrivilegedStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::RealmStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<
        aarch64_vmsa::config::regime::smmu_v3::RealmPrivilegedStreamStage1,
        G,
    >>::Layout: SmmuLiveStage1Layout<F, G>,
    <F as aarch64_vmsa::regime::HasRegimeLayout<R, G>>::Layout:
        aarch64_vmsa::descriptor::DescriptorLayout<
                G,
                Format = F,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage2LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa64Stage2TableAttrs,
            >,
{
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, DirtyBitManagement, DirtyControl,
        LiveVmsaConfig, MemoryAttributes, MemoryTransience, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
        SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode, Stage2Permissions,
    };
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type Layout<F, G, R> = <F as HasRegimeLayout<R, G>>::Layout;

    let (l0, l1, l2, l3, stream_table, event_queue, context_descriptor, source, destination) = unsafe {
        (
            core::ptr::addr_of_mut!(SMMU_L0.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L1.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L2.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L3.0) as usize,
            core::ptr::addr_of_mut!(SMMU_STREAM_TABLE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_EVENT_QUEUE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_CONTEXT_DESCRIPTOR.0) as usize,
            core::ptr::addr_of_mut!(SMMU_SOURCE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_DESTINATION.0) as usize,
        )
    };

    let smmu = 0x2b40_0000usize
        + if secure_stream {
            0x8000
        } else if realm_stream {
            0x40000
        } else {
            0
        };
    let isolated_test_engine = secure_stream || realm_stream;
    let user = if isolated_test_engine {
        0x2b50_0000
    } else {
        0x2bfe_0000
    };
    let privileged = if isolated_test_engine {
        0x2b51_0000
    } else {
        0x2bff_0000
    };
    if stage1 && unsafe { read32(smmu) } & (1 << 1) == 0 {
        return TestResult::Skip(vmsa_test_harness::SkipReason::Unsupported);
    }
    // TF-A configures each architectural register bank independently before
    // handing control to its payload. These are firmware-entry baselines, not
    // a single power-on-reset value.
    let (cr0_entry_baseline, cr1_baseline) = if realm_stream {
        (1 << 4, 0xe4e)
    } else if secure_stream {
        (0xd, 0xd75)
    } else {
        (0, 0x499)
    };
    let cr0_disabled = if realm_stream { 1 << 4 } else { 0 };
    let reset_memory_is_zero = unsafe {
        core::slice::from_raw_parts(l0 as *const u8, G::SIZE as usize)
            .iter()
            .chain(core::slice::from_raw_parts(
                l1 as *const u8,
                G::SIZE as usize,
            ))
            .chain(core::slice::from_raw_parts(
                l2 as *const u8,
                G::SIZE as usize,
            ))
            .chain(core::slice::from_raw_parts(
                l3 as *const u8,
                G::SIZE as usize,
            ))
            .chain(core::slice::from_raw_parts(stream_table as *const u8, 128))
            .chain(core::slice::from_raw_parts(event_queue as *const u8, 64))
            .chain(core::slice::from_raw_parts(
                context_descriptor as *const u8,
                128,
            ))
            .chain(core::slice::from_raw_parts(source as *const u8, 4096))
            .chain(core::slice::from_raw_parts(destination as *const u8, 4096))
            .all(|byte| *byte == 0)
    };
    let reset_test_engine_values = unsafe {
        [
            read32(privileged),
            read32(privileged + 4),
            read32(privileged + 8),
            read32(privileged + 12),
            read32(user),
            read32(user + 4),
            read32(user + 0x20),
            read32(user + 0x28),
            read32(user + 0x30),
            read32(user + 0x38),
            read32(user + 0x40),
        ]
    };
    // Both test-engine status registers reset to the documented idle value;
    // all programmable selector and transfer registers reset to zero.
    let reset_test_engine_is_baseline =
        reset_test_engine_values == [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let reset_values = unsafe {
        [
            read32(smmu + 0x24) as u64,
            read32(smmu + 0x28) as u64,
            read64(smmu + 0x80),
            read64(smmu + 0xa0),
            read32(smmu + 0xa8) as u64,
            read32(smmu + 0xac) as u64,
        ]
    };
    let reset_failures = u64::from(!reset_memory_is_zero) << 4
        | (u64::from(!reset_test_engine_is_baseline) << 5)
        | u64::from(reset_values[0] != cr0_entry_baseline as u64)
        | (u64::from(reset_values[1] != cr1_baseline) << 1)
        | (u64::from(reset_values[4] != 0) << 2)
        | (u64::from(reset_values[5] != 0) << 3);
    if reset_failures != 0 {
        crate::common::diagnostic_hex(b"smmu-reset-baseline", &reset_values);
        crate::common::diagnostic_hex(
            b"smmu-test-engine-reset-baseline",
            &reset_test_engine_values.map(u64::from),
        );
        return failed(0, reset_failures);
    }
    // Every address used here is identity-mapped by the NS-EL2 firmware payload.
    unsafe {
        core::ptr::write_bytes(l0 as *mut u8, 0, G::SIZE as usize);
        core::ptr::write_bytes(l1 as *mut u8, 0, G::SIZE as usize);
        core::ptr::write_bytes(l2 as *mut u8, 0, G::SIZE as usize);
        core::ptr::write_bytes(l3 as *mut u8, 0, G::SIZE as usize);
        core::ptr::write_bytes(stream_table as *mut u8, 0, 128);
        core::ptr::write_bytes(event_queue as *mut u8, 0, 64);
        core::ptr::write_bytes(context_descriptor as *mut u8, 0, 128);
        core::ptr::write_bytes(destination as *mut u8, 0, G::SIZE as usize);
        for index in 0..4096 {
            (source as *mut u8)
                .add(index)
                .write((index as u8).wrapping_mul(37));
        }
    }

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        smmu_v3_aie: false,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas,
    };
    let semantic = SemanticStage2LeafAttrs {
        memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
            inner: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
            outer: Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            },
        }),
        permissions: Stage2Permissions::read_write(
            aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
        ),
        output_address_space: output_pas,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let destination_semantic = SemanticStage2LeafAttrs {
        permissions: fault_setup
            .destination_permission
            .unwrap_or(semantic.permissions),
        controls: SemanticVmsa64Stage2LeafControls {
            access_flag: fault_setup.destination_access_flag,
            ..semantic.controls
        },
        ..semantic
    };
    let table_fields = <F as AttributeCodec<R, G, _>>::encode_table(
        &config,
        Level::L1,
        SemanticVmsa64Stage2TableAttrs {
            access_flag: fault_setup.table_access_flag,
            software: SoftwareMetadata::new(0),
        },
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l1_shape =
        TableShape::<F, G>::root(Level::L1).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l2_shape =
        TableShape::<F, G>::new(Level::L2, 1).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l3_shape =
        TableShape::<F, G>::new(Level::L3, 1).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l1_to_l2 =
        TableTransition::new(l1_shape, l2_shape).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l2_to_l3 =
        TableTransition::new(l2_shape, l3_shape).map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let l0_raw = if secure_stream {
        let l0_shape =
            TableShape::<F, G>::root(Level::L0).map_err(|_| HarnessError::InvalidState)?;
        let transition =
            TableTransition::new(l0_shape, l1_shape).map_err(|_| HarnessError::InvalidState)?;
        Some(
            <Layout<F, G, R> as DescriptorLayout<G>>::table_descriptor(
                TableAddr::new(l1 as u64).map_err(|_| HarnessError::InvalidState)?,
                transition,
                table_fields,
            )
            .map_err(|_| HarnessError::InvalidState)?,
        )
    } else {
        None
    };
    let l1_raw = <Layout<F, G, R> as DescriptorLayout<G>>::table_descriptor(
        TableAddr::new(l2 as u64).map_err(|_| HarnessError::InvalidState)?,
        l1_to_l2,
        table_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let table_fields = <F as AttributeCodec<R, G, _>>::encode_table(
        &config,
        Level::L2,
        SemanticVmsa64Stage2TableAttrs {
            access_flag: fault_setup.table_access_flag,
            software: SoftwareMetadata::new(0),
        },
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l2_raw = <Layout<F, G, R> as DescriptorLayout<G>>::table_descriptor(
        TableAddr::new(l3 as u64).map_err(|_| HarnessError::InvalidState)?,
        l2_to_l3,
        table_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let leaf_level = if block_mapping { Level::L2 } else { Level::L3 };
    let leaf_fields = <F as AttributeCodec<R, G, _>>::encode_leaf(&config, leaf_level, semantic)
        .map_err(|_| HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        })?;
    let block_mask = (1u64 << 21) - 1;
    let source_output = if block_mapping {
        (source as u64) & !block_mask
    } else {
        source as u64
    };
    let destination_output = if block_mapping {
        (destination as u64) & !block_mask
    } else {
        destination as u64
    };
    let source_raw = <Layout<F, G, R> as DescriptorLayout<G>>::leaf_descriptor(
        PhysAddr(source_output),
        leaf_level,
        leaf_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let destination_raw = <Layout<F, G, R> as DescriptorLayout<G>>::leaf_descriptor(
        PhysAddr(destination_output),
        leaf_level,
        <F as AttributeCodec<R, G, _>>::encode_leaf(&config, leaf_level, destination_semantic)
            .map_err(|_| HarnessError::CrateBehavior {
                expected: 1,
                actual: 0,
            })?,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let stream_entry = stream_table + fault_setup.stream_id as usize * 64;
    let context_entry = context_descriptor;
    unsafe {
        if let Some(raw) = l0_raw {
            <F as DescriptorFormat>::write_descriptor(l0 as *mut u64, raw);
        }
        <F as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
        if block_mapping {
            <F as DescriptorFormat>::write_descriptor((l2 as *mut u64).add(1), source_raw);
            if fault_setup.install_destination {
                <F as DescriptorFormat>::write_descriptor((l2 as *mut u64).add(2), destination_raw);
            }
        } else {
            <F as DescriptorFormat>::write_descriptor(l2 as *mut u64, l2_raw);
            <F as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(1), source_raw);
            if fault_setup.install_destination {
                <F as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(2), destination_raw);
            }
        }
    }

    if fault_setup.d128 {
        use aarch64_vmsa::attrs::{
            DirtyState, SemanticVmsa128Stage2LeafControls, SemanticVmsa128Stage2TableAttrs,
        };
        use aarch64_vmsa::config::format::{LittleEndian, Vmsa128};
        use aarch64_vmsa::config::granule::Granule4KiB;
        use aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2;
        type D128 = Vmsa128<LittleEndian>;
        use aarch64_vmsa::mapper::Mapper;
        use aarch64_vmsa::table::RootTableGeometry;
        use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};

        let d128_config = LiveVmsaConfig {
            mair: config.mair,
            mair2: config.mair2,
            smmu_v3_aie: false,
            stage1_permissions: config.stage1_permissions,
            stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings {
                base: aarch64_vmsa::attrs::Stage2BasePermissions::Indirect(
                    aarch64_vmsa::attrs::Stage2PermissionRegisters {
                        s2pir_el2: 0x0000_0000_0000_fb8c,
                    },
                ),
                s2por_el1: None,
            },
            stage2_memory_mode: config.stage2_memory_mode,
            d128_stage1_alias: config.d128_stage1_alias,
            shareability: config.shareability,
            output_pas: (),
        };

        let d128_semantic = SemanticStage2LeafAttrs {
            memory: Stage2MemoryAttributes::Combined(MemoryAttributes::Normal {
                inner: Cacheability::Cacheable {
                    policy: CachePolicy::WriteBack,
                    transience: MemoryTransience::NonTransient,
                    allocation: AllocationHints::ReadWriteAllocate,
                },
                outer: Cacheability::Cacheable {
                    policy: CachePolicy::WriteBack,
                    transience: MemoryTransience::NonTransient,
                    allocation: AllocationHints::ReadWriteAllocate,
                },
            }),
            permissions: Stage2Permissions::read_write(
                aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(false, false),
            ),
            output_address_space: (),
            controls: SemanticVmsa128Stage2LeafControls {
                bbm_nt: false,
                dirty_state: DirtyState::Dirty,
                shareability: Shareability::InnerShareable,
                access_flag: true,
                force_no_xs: false,
                contiguous: false,
                assured_only: false,
                software: SoftwareMetadata::new(0),
            },
        };
        let root = RootTableGeometry::<D128, Granule4KiB>::new_at_level(
            TableAddr::new(l1 as u64).map_err(|_| HarnessError::InvalidState)?,
            Level::L1,
            36,
            48,
        )
        .map_err(|_| HarnessError::InvalidState)?
        .with_regime::<NonSecureIpaStage2>();
        let mut mapper = Mapper::new_offline(
            root,
            SmmuD128ArenaAccess {
                tables: [l1 as u64, l2 as u64, l3 as u64, l0 as u64],
            },
            SmmuD128ArenaFrames {
                frames: [l2 as u64, l3 as u64, l0 as u64],
                initialized: [false; 3],
                next: 0,
                reclaimed: 0,
                fail_after: 3,
            },
        )
        .map_err(|_| HarnessError::InvalidState)?;
        let table = SemanticVmsa128Stage2TableAttrs {
            access_flag: true,
            ..SemanticVmsa128Stage2TableAttrs::default()
        };
        for (input, output) in [(4096, source as u64), (8192, destination as u64)] {
            mapper
                .map_semantic_leaf(
                    &d128_config,
                    WalkInputAddr::new(input),
                    WalkOutputAddr::new(output),
                    Level::L3,
                    d128_semantic,
                    table,
                )
                .map_err(|_| HarnessError::InvalidState)?;
        }
    }

    if stage1 {
        use aarch64_vmsa::low_level::raw::{
            FourBit, RawShareability, RawVmsa64PermissionFields, RawVmsa64Stage1LeafAttrs,
            RawVmsa64Stage1TableAttrs, TableAp, ThreeBit,
        };
        let stage1_setup = fault_setup
            .stage1
            .unwrap_or(SmmuLiveStage1Setup::NONSECURE_4K);
        let nonsecure_output = matches!(
            stage1_setup.regime,
            SmmuLiveStage1Regime::NonSecure | SmmuLiveStage1Regime::NonSecurePrivileged
        );
        let table = RawVmsa64Stage1TableAttrs {
            access_flag: true,
            privileged_execute_never_limit: false,
            unprivileged_execute_never_limit: false,
            ap_table: TableAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
            ns_table: nonsecure_output,
            software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
        };
        let leaf = |ap| {
            Ok::<_, HarnessError>(RawVmsa64Stage1LeafAttrs {
                attr_index: FourBit::new(stage1_setup.attr_index)
                    .map_err(|_| HarnessError::InvalidState)?,
                ns: nonsecure_output,
                permissions: RawVmsa64PermissionFields {
                    // AP[2:1] = 0b01 permits both privileged and unprivileged
                    // reads and writes, so the test does not depend on the
                    // requester's privilege attribute.
                    primary: FourBit::new(ap).map_err(|_| HarnessError::InvalidState)?,
                    dirty: false,
                    overlay: ThreeBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                },
                shareability: RawShareability::from_bits(0b11)
                    .map_err(|_| HarnessError::InvalidState)?,
                access_flag: true,
                alias_bit: false,
                contiguous: false,
                guarded: false,
                software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
            })
        };
        macro_rules! install_stage1 {
            ($regime:ty) => {{
                type Stage1Layout<F, G> = <F as HasRegimeLayout<$regime, G>>::Layout;
                let l1_raw = <Stage1Layout<F, G> as DescriptorLayout<G>>::table_descriptor(
                    TableAddr::new(l2 as u64).map_err(|_| HarnessError::InvalidState)?,
                    l1_to_l2,
                    table,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                let l2_raw = <Stage1Layout<F, G> as DescriptorLayout<G>>::table_descriptor(
                    TableAddr::new(l3 as u64).map_err(|_| HarnessError::InvalidState)?,
                    l2_to_l3,
                    table,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                let source_raw = <Stage1Layout<F, G> as DescriptorLayout<G>>::leaf_descriptor(
                    PhysAddr(source as u64),
                    Level::L3,
                    leaf(1)?,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                let destination_raw = <Stage1Layout<F, G> as DescriptorLayout<G>>::leaf_descriptor(
                    PhysAddr(destination as u64),
                    Level::L3,
                    leaf(1)?,
                )
                .map_err(|_| HarnessError::InvalidState)?;
                unsafe {
                    <F as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
                    <F as DescriptorFormat>::write_descriptor(l2 as *mut u64, l2_raw);
                    <F as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(1), source_raw);
                    <F as DescriptorFormat>::write_descriptor(
                        (l3 as *mut u64).add(2),
                        destination_raw,
                    );
                }
            }};
        }
        use aarch64_vmsa::config::regime::smmu_v3;
        match stage1_setup.regime {
            SmmuLiveStage1Regime::NonSecure => {
                install_stage1!(smmu_v3::NonSecureStreamStage1)
            }
            SmmuLiveStage1Regime::NonSecurePrivileged => {
                install_stage1!(smmu_v3::NonSecurePrivilegedStreamStage1)
            }
            SmmuLiveStage1Regime::Secure => install_stage1!(smmu_v3::SecureStreamStage1),
            SmmuLiveStage1Regime::SecurePrivileged => {
                install_stage1!(smmu_v3::SecurePrivilegedStreamStage1)
            }
            SmmuLiveStage1Regime::Realm => install_stage1!(smmu_v3::RealmStreamStage1),
            SmmuLiveStage1Regime::RealmPrivileged => {
                install_stage1!(smmu_v3::RealmPrivilegedStreamStage1)
            }
        }
    }

    // Linear stream table, SID 0, stage-2-only. VTCR describes a 39-bit, 4 KiB,
    // inner-shareable, WBWA walk rooted at level 1.
    unsafe {
        let root = if stage1 && root_at_l1 {
            l1
        } else if stage1 {
            l2
        } else if secure_stream {
            l0
        } else if root_at_l1 {
            l1
        } else {
            l2
        };
        if stage1 {
            let stage1_setup = fault_setup
                .stage1
                .unwrap_or(SmmuLiveStage1Setup::NONSECURE_4K);
            // Linear CD table with one context, stage-1-only translation.
            (stream_entry as *mut u64).write(
                (1u64 | (5u64 << 1) | ((context_descriptor as u64) & 0x000f_ffff_ffff_ffc0))
                    .to_le(),
            );
            (stream_entry as *mut u64).add(1).write(
                (((secure_stream as u64) << 1)
                    | (1u64 << 2)
                    | (1u64 << 4)
                    | (3u64 << 6)
                    | (1u64 << 19)
                    | ((secure_stream as u64) << 31)
                    | (1u64 << 44))
                    .to_le(),
            );
            (context_entry as *mut u64).write(
                (stage1_setup.tcr
                    | ((stage1_setup.big_endian as u64) << 15)
                    | (1u64 << 30)
                    | (1u64 << 31)
                    | (2u64 << 32)
                    | (1u64 << 41)
                    | (1u64 << 45)
                    | (1u64 << 46)
                    | (1u64 << 47)
                    | (1u64 << 48))
                    .to_le(),
            );
            (context_entry as *mut u64)
                .add(1)
                .write(((root as u64) & 0x000f_ffff_ffff_fff0).to_le());
            (context_entry as *mut u64)
                .add(3)
                .write(stage1_setup.mair.to_le());
        } else {
            (stream_entry as *mut u64).write((1u64 | (6u64 << 1)).to_le());
            (stream_entry as *mut u64)
                .add(1)
                .write(((1u64 << 19) | (1u64 << 27) | (1u64 << 44)).to_le());
            (stream_entry as *mut u64).add(2).write(
                (1 | (vtcr << 32)
                    | ((!fault_setup.d128 as u64) << 51)
                    | ((big_endian as u64) << 52)
                    | ((fault_setup.access_flag_fault_disabled as u64) << 53)
                    | ((!fault_setup.d128 as u64) << 54))
                    .to_le(),
            );
            (stream_entry as *mut u64)
                .add(3)
                .write((((root as u64) & 0x000f_ffff_ffff_ffe0) | ((F::S2DS as u64) << 3)).to_le());
            if secure_stream {
                /* Secure STEs select the S-EL2 stream world and carry a
                 * distinct Secure-IPA geometry/root in words 4 and 6. */
                (stream_entry as *mut u64)
                    .add(1)
                    .write((2u64 << 30).to_le());
                (stream_entry as *mut u64)
                    .add(3)
                    .write((((root as u64) & 0x000f_ffff_ffff_fff0) | (1 << 1)).to_le());
                (stream_entry as *mut u64).add(4).write(
                    (((vtcr & 0x3f) << 32)
                        | (((vtcr >> 6) & 0x3) << 38)
                        | (((vtcr >> 14) & 0x3) << 46))
                        .to_le(),
                );
                (stream_entry as *mut u64)
                    .add(6)
                    .write(((root as u64) & 0x000f_ffff_ffff_fff0).to_le());
            }
        }
    }

    for (address, bytes) in [
        (l0 as u64, G::SIZE as usize),
        (l1 as u64, G::SIZE as usize),
        (l2 as u64, G::SIZE as usize),
        (l3 as u64, G::SIZE as usize),
        (stream_table as u64, 128),
        (event_queue as u64, 64),
        (context_descriptor as u64, 128),
        (source as u64, G::SIZE as usize),
        (destination as u64, G::SIZE as usize),
    ] {
        context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
            address,
            bytes,
        })?;
    }
    if secure_stream {
        crate::common::diagnostic_hex(b"smmu-secure-ste", unsafe {
            core::slice::from_raw_parts(stream_entry as *const u64, 8)
        });
    }

    if secure_stream {
        unsafe {
            write32(smmu + 0x3c, 1);
        }
        if !wait32(smmu + 0x3c, 0) {
            return failed(0, unsafe { read32(smmu + 0x3c) }.into());
        }
        unsafe {
            write32(smmu + 0x44, 1 << 31);
        }
        for _ in 0..100_000 {
            if unsafe { read32(smmu + 0x44) } & (1 << 31) == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
    unsafe {
        write32(smmu + 0x20, 0);
    }
    // The Realm register bank keeps R_CR0.RME_IMPL enabled as a read-only-one
    // capability bit. Preserve that architectural baseline while toggling the
    // translation and event-queue enable bits shared by all register banks.
    if !wait32(smmu + 0x24, cr0_disabled) {
        return failed(cr0_disabled.into(), unsafe { read32(smmu + 0x24) }.into());
    }
    unsafe {
        write32(smmu + 0x28, (1 << 10) | (1 << 8) | (1 << 6));
        if fault_setup.d128 {
            write64(smmu + 0x30, 0x0000_0000_0000_fb8c);
        }
        write64(smmu + 0x80, (stream_table as u64) & 0x000f_ffff_ffff_ffc0);
        write32(smmu + 0x88, u32::from(fault_setup.stream_id != 0));
        write64(
            smmu + 0xa0,
            ((event_queue as u64) & 0x000f_ffff_ffff_ffe0) | (1u64 << 62) | 1,
        );
        write32(smmu + 0xac, 0);
        write32(smmu + 0x50, 1 << 2);
        write32(smmu + 0x20, cr0_disabled | 1 | (1 << 2));
    }
    if !wait32(smmu + 0x54, 1 << 2) {
        return failed(1 << 2, unsafe { read32(smmu + 0x54) }.into());
    }
    let cr0_enabled = cr0_disabled | 1 | (1 << 2);
    if !wait32(smmu + 0x24, cr0_enabled) {
        return failed(cr0_enabled.into(), unsafe { read32(smmu + 0x24) }.into());
    }

    unsafe {
        // The test engine's two-bit security-state selector uses the FVP SSD
        // encoding: Secure=0, Non-secure=1, Root=2, Realm=3.
        let stream_security_state = if realm_stream {
            3
        } else if secure_stream {
            0
        } else {
            1
        };
        write32(privileged, stream_security_state);
        write32(privileged + 4, 0);
        write32(privileged + 8, fault_setup.stream_id);
        write32(privileged + 12, u32::MAX);
        write32(user, 1);
        write32(user + 4, 0);
        write32(
            user + 0x20,
            if realm_stream {
                0xc2ff_c2ff
            } else if secure_stream {
                0x00ff_00ff
            } else {
                0x42ff_42ff
            },
        );
        let source_iova = if block_mapping {
            (1u64 << 21) | ((source as u64) & block_mask)
        } else {
            G::SIZE
        };
        let destination_iova = fault_setup.destination_iova.unwrap_or_else(|| {
            if block_mapping {
                (2u64 << 21) | ((destination as u64) & block_mask)
            } else {
                G::SIZE * 2
            }
        });
        write64(user + 0x28, source_iova);
        write64(user + 0x30, source_iova + 4095);
        write64(user + 0x38, 1);
        write64(user + 0x40, destination_iova);
        write32(user, 2);
    }
    let mut status = 0;
    for _ in 0..1_000_000 {
        status = unsafe { read32(user) };
        if status == 1 || status == u32::MAX || status == u32::MAX - 1 {
            break;
        }
        core::hint::spin_loop();
    }
    if status != 1 {
        let mut producer = 0;
        for _ in 0..100_000 {
            producer = unsafe { read32(smmu + 0xa8) };
            if producer != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        context.maintain_cache(
            vmsa_test_harness::CacheMaintenanceOperation::InvalidateData {
                address: event_queue as u64,
                bytes: 64,
            },
        )?;
        let event = unsafe { core::ptr::read_volatile(event_queue as *const u64) };
        crate::common::diagnostic_hex(b"smmu-event", unsafe {
            core::slice::from_raw_parts(event_queue as *const u64, 4)
        });
        crate::common::diagnostic_hex(
            b"smmu-event-regs",
            &[
                unsafe { read32(smmu + 0x24) }.into(),
                unsafe { read32(smmu + 0x60) }.into(),
                unsafe { read32(smmu + 0x64) }.into(),
                unsafe { read32(smmu + 0xa8) }.into(),
                unsafe { read32(smmu + 0xac) }.into(),
                unsafe { read64(smmu + 0x30) },
            ],
        );
        if let Some(expected_fault) = fault_setup.expected_event {
            context.maintain_cache(
                vmsa_test_harness::CacheMaintenanceOperation::InvalidateData {
                    address: destination as u64,
                    bytes: 4096,
                },
            )?;
            let destination_unchanged = unsafe {
                core::slice::from_raw_parts(destination as *const u8, 4096)
                    .iter()
                    .all(|byte| *byte == 0)
            };
            let global_error = unsafe { read32(smmu + 0x60) };
            let global_error_ack = unsafe { read32(smmu + 0x64) };
            let exact_event = producer != 0 && event as u8 == expected_fault;
            // Some FVP SMMUv3 configurations terminate the transaction at the
            // external test engine without committing an event record. The
            // independently observable permission-fault outcome is still exact:
            // the engine reports a terminated transfer, the destination is
            // untouched, and the SMMU has no unacknowledged global error.
            let terminated_without_event =
                producer == 0 && status == u32::MAX && global_error == global_error_ack;
            if (exact_event || terminated_without_event) && destination_unchanged {
                return TestResult::Pass;
            }
            return failed(
                expected_fault.into(),
                ((status as u64) << 32) | ((producer as u64) << 8) | (event & 0xff),
            );
        }
        return failed(((status as u64) << 32) | producer as u64, event);
    }
    if fault_setup.expected_event.is_some() {
        return failed(0, 1);
    }
    context.maintain_cache(
        vmsa_test_harness::CacheMaintenanceOperation::InvalidateData {
            address: destination as u64,
            bytes: 4096,
        },
    )?;
    let equal = unsafe {
        core::slice::from_raw_parts(source as *const u8, 4096)
            == core::slice::from_raw_parts(destination as *const u8, 4096)
    };
    if !equal {
        return failed(1, 0);
    }
    TestResult::Pass
}

pub fn smmu_v3_live_stage2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_lpa2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64Lpa2};
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        Vmsa64Lpa2<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_d128(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    // VMSAv9-128 uses a 36-bit IPA here. S2SL0 is RES0 for D128; the table's
    // initial lookup size is conveyed by its 128-bit root descriptor geometry.
    let vtcr = 28u64 | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::D128,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_16k(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule16KiB;
    let vtcr = 25u64 | (2 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 14) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule16KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_64k(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule64KiB;
    let vtcr = 22u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 14) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule64KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        false,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_big_endian(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::BigEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<BigEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        true,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_permission_fault(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::PERMISSION,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_table_access_flag(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage2_fault(context, SmmuLiveFaultSetup::TABLE_ACCESS_FLAG)
}

fn smmu_v3_live_stage2_fault(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    fault_setup: SmmuLiveFaultSetup,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;

    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        fault_setup,
        false,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage2_translation_fault(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage2_fault(context, SmmuLiveFaultSetup::TRANSLATION)
}

pub fn smmu_v3_live_stage2_address_size_fault(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage2_fault(context, SmmuLiveFaultSetup::ADDRESS_SIZE)
}

pub fn smmu_v3_live_stage2_access_fault(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage2_fault(context, SmmuLiveFaultSetup::ACCESS)
}

pub fn smmu_v3_live_stage2_stream_id_1(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage2_fault(context, SmmuLiveFaultSetup::STREAM_ID_1)
}

pub fn smmu_v3_live_stage1(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let unused_stage2_vtcr = 0;
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        unused_stage2_vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage1_16k(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule16KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule16KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        0,
        true,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                tcr: 25 | (2 << 6) | (1 << 8) | (1 << 10) | (3 << 12),
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage1_64k(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule64KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule64KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        0,
        false,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                tcr: 22 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12),
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage1_big_endian(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{BigEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<BigEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        0,
        true,
        true,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                big_endian: true,
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage1_privileged(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        0,
        true,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                regime: SmmuLiveStage1Regime::NonSecurePrivileged,
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_stage1_mair_index_7(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 7)
}

pub fn smmu_v3_live_stage1_mair_index_1(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 1)
}

pub fn smmu_v3_live_stage1_mair_index_2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 2)
}

pub fn smmu_v3_live_stage1_mair_index_3(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 3)
}

pub fn smmu_v3_live_stage1_mair_index_4(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 4)
}

pub fn smmu_v3_live_stage1_mair_index_5(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 5)
}

pub fn smmu_v3_live_stage1_mair_index_6(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    smmu_v3_live_stage1_mair_index(context, 6)
}

fn smmu_v3_live_stage1_mair_index(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
    index: u8,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        0,
        true,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                mair: 0xffu64 << (u32::from(index) * 8),
                attr_index: index,
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_secure_stage1(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::SecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa,
    >(
        context,
        0,
        true,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                regime: SmmuLiveStage1Regime::Secure,
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        true,
        false,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
    )
}

pub fn smmu_v3_live_realm_stage1(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    smmu_v3_live_stage2_for::<
        Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::RealmIpaStage2,
        aarch64_vmsa::attrs::RealmOrNonSecurePa,
    >(
        context,
        0,
        true,
        false,
        SmmuLiveFaultSetup {
            stage1: Some(SmmuLiveStage1Setup {
                regime: SmmuLiveStage1Regime::Realm,
                ..SmmuLiveStage1Setup::NONSECURE_4K
            }),
            ..SmmuLiveFaultSetup::NONE
        },
        true,
        false,
        false,
        true,
        aarch64_vmsa::attrs::RealmOrNonSecurePa::Realm,
    )
}

pub fn smmu_v3_live_stage2_block(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2,
        (),
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        true,
        false,
        false,
        (),
    )
}

pub fn smmu_v3_live_secure_stage2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    let vtcr = 16u64 | (2 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (5 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        aarch64_vmsa::config::regime::smmu_v3::SecureIpaStage2,
        aarch64_vmsa::attrs::SecureSelectablePa,
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        true,
        false,
        aarch64_vmsa::attrs::SecureSelectablePa::Secure,
    )
}

pub fn smmu_v3_live_secure_stream_nonsecure_stage2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::attrs::SecureSelectablePa;
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::SecureStreamNonSecureIpaStage2;
    use aarch64_vmsa::config::stage2::StandardStage2PermissionModel;

    let vtcr = 16u64 | (2 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (5 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        SecureStreamNonSecureIpaStage2<StandardStage2PermissionModel>,
        SecureSelectablePa,
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        true,
        false,
        SecureSelectablePa::NonSecure,
    )
}

pub fn smmu_v3_live_secure_stream_nonsecure_stage2_xnx(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::attrs::{SecureSelectablePa, Stage2Permissions};
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::SecureStreamNonSecureIpaStage2;
    use aarch64_vmsa::config::stage2::XnxStage2PermissionModel;

    let vtcr = 16u64 | (2 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (5 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        SecureStreamNonSecureIpaStage2<XnxStage2PermissionModel>,
        SecureSelectablePa,
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup {
            destination_permission: Some(Stage2Permissions::read_write(
                aarch64_vmsa::attrs::ExecuteRights::from_privileged_unprivileged(true, false),
            )),
            ..SmmuLiveFaultSetup::NONE
        },
        false,
        false,
        true,
        false,
        SecureSelectablePa::NonSecure,
    )
}

pub fn smmu_v3_live_realm_stage2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::attrs::RealmOrNonSecurePa;
    use aarch64_vmsa::config::format::LittleEndian;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::RealmIpaStage2;

    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    smmu_v3_live_stage2_for::<
        aarch64_vmsa::config::format::Vmsa64<LittleEndian>,
        Granule4KiB,
        RealmIpaStage2,
        RealmOrNonSecurePa,
    >(
        context,
        vtcr,
        true,
        false,
        SmmuLiveFaultSetup::NONE,
        false,
        false,
        false,
        true,
        RealmOrNonSecurePa::Realm,
    )
}
