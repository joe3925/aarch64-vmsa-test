use vmsa_test_harness::{HarnessError, TestResult};

fn failed(expected: u64, actual: u64) -> TestResult {
    HarnessError::CrateBehavior { expected, actual }.into()
}

pub fn descriptor_endian_storage() -> TestResult {
    use aarch64_vmsa::config::format::{BigEndian, LittleEndian, Vmsa64, Vmsa128};
    use aarch64_vmsa::descriptor::DescriptorFormat;

    let raw64 = 0x0123_4567_89ab_cdefu64;
    let mut le64 = 0u64;
    let mut be64 = 0u64;
    unsafe {
        <Vmsa64<LittleEndian> as DescriptorFormat>::write_descriptor(&mut le64, raw64);
        <Vmsa64<BigEndian> as DescriptorFormat>::write_descriptor(&mut be64, raw64);
    }
    if le64 != raw64.to_le() || be64 != raw64.to_be() {
        return failed(raw64.to_le(), le64);
    }
    let read_le =
        unsafe { <Vmsa64<LittleEndian> as DescriptorFormat>::read_descriptor(&raw64.to_le()) };
    let read_be =
        unsafe { <Vmsa64<BigEndian> as DescriptorFormat>::read_descriptor(&raw64.to_be()) };
    if read_le != raw64 || read_be != raw64 {
        return failed(raw64, read_le);
    }

    let raw128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
    let mut be128 = 0u128;
    unsafe {
        <Vmsa128<BigEndian> as DescriptorFormat>::write_descriptor(&mut be128, raw128);
    }
    if be128 != raw128.to_be()
        || unsafe { <Vmsa128<BigEndian> as DescriptorFormat>::read_descriptor(&be128) } != raw128
    {
        return failed(raw128 as u64, be128 as u64);
    }
    TestResult::Pass
}

pub fn smmu_v2_stage2_exact_vector() -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        AttributeCodec, Cacheability, LiveVmsaConfig, MemoryAttributes,
        SemanticSmmuV2Stage2LeafControls, SemanticStage2LeafAttrs, Shareability,
        SmmuV2AllocationHint, SoftwareMetadata, Stage2MemoryAttributes, Stage2MemoryMode,
        Stage2Permission,
    };
    use aarch64_vmsa::config::format::Vmsa64;
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v2::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;

    type Layout = <Vmsa64 as HasRegimeLayout<NonSecureIpaStage2, Granule4KiB>>::Layout;
    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
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
        permissions: Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: (),
        controls: SemanticSmmuV2Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
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
    let raw = <Layout as DescriptorLayout<_, Granule4KiB>>::leaf_descriptor(
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
        <Layout as DescriptorLayout<_, Granule4KiB>>::decode_leaf_fields(expected, Level::L3);
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

#[repr(C, align(4096))]
struct Page([u8; 4096]);

#[repr(C, align(4096))]
struct DescriptorPage([u64; 512]);

#[repr(C, align(64))]
struct StreamTable([u64; 8]);

static mut SMMU_L1: DescriptorPage = DescriptorPage([0; 512]);
static mut SMMU_L2: DescriptorPage = DescriptorPage([0; 512]);
static mut SMMU_L3: DescriptorPage = DescriptorPage([0; 512]);
static mut SMMU_STREAM_TABLE: StreamTable = StreamTable([0; 8]);
static mut SMMU_SOURCE: Page = Page([0; 4096]);
static mut SMMU_DESTINATION: Page = Page([0; 4096]);

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

pub fn smmu_v3_live_stage2(
    context: &mut vmsa_test_harness::TestContext<'_, crate::CurrentEnvironment>,
) -> TestResult {
    use aarch64_vmsa::address::{Level, PhysAddr};
    use aarch64_vmsa::attrs::{
        AllocationHints, AttributeCodec, CachePolicy, Cacheability, DirtyBitManagement,
        DirtyControl, LiveVmsaConfig, MemoryAttributes, MemoryTransience, SemanticStage2LeafAttrs,
        SemanticVmsa64Stage2LeafControls, Shareability, SoftwareMetadata, Stage2MemoryAttributes,
        Stage2MemoryMode, Stage2Permission,
    };
    use aarch64_vmsa::config::format::{LittleEndian, Vmsa64};
    use aarch64_vmsa::config::granule::Granule4KiB;
    use aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2;
    use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout};
    use aarch64_vmsa::regime::HasRegimeLayout;
    use aarch64_vmsa::table::{TableAddr, TableShape, TableTransition};

    type Format = Vmsa64<LittleEndian>;
    type Regime = NonSecureIpaStage2;
    type Layout = <Format as HasRegimeLayout<Regime, Granule4KiB>>::Layout;

    let (l1, l2, l3, stream_table, source, destination) = unsafe {
        (
            core::ptr::addr_of_mut!(SMMU_L1.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L2.0) as usize,
            core::ptr::addr_of_mut!(SMMU_L3.0) as usize,
            core::ptr::addr_of_mut!(SMMU_STREAM_TABLE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_SOURCE.0) as usize,
            core::ptr::addr_of_mut!(SMMU_DESTINATION.0) as usize,
        )
    };

    // Every address used here is identity-mapped by the NS-EL2 firmware payload.
    unsafe {
        core::ptr::write_bytes(l1 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l2 as *mut u8, 0, 4096);
        core::ptr::write_bytes(l3 as *mut u8, 0, 4096);
        core::ptr::write_bytes(stream_table as *mut u8, 0, 64);
        core::ptr::write_bytes(destination as *mut u8, 0, 4096);
        for index in 0..4096 {
            (source as *mut u8)
                .add(index)
                .write((index as u8).wrapping_mul(37));
        }
    }

    let config = LiveVmsaConfig {
        mair: 0,
        mair2: None,
        stage1_permissions: aarch64_vmsa::attrs::Stage1PermissionSettings::direct(),
        stage2_permissions: aarch64_vmsa::attrs::Stage2PermissionSettings::direct(),
        stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
        d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
        shareability: Shareability::InnerShareable,
        output_pas: (),
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
        permissions: Stage2Permission::ReadWrite {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        output_address_space: (),
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            software: SoftwareMetadata::new(0),
        },
    };
    let table_fields = <Format as AttributeCodec<Regime, Granule4KiB, _>>::encode_table(
        &config,
        Level::L1,
        Default::default(),
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l1_shape = TableShape::<Format, Granule4KiB>::root(Level::L1).map_err(|_| {
        HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
    })?;
    let l2_shape = TableShape::<Format, Granule4KiB>::new(Level::L2, 1).map_err(|_| {
        HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
    })?;
    let l3_shape = TableShape::<Format, Granule4KiB>::new(Level::L3, 1).map_err(|_| {
        HarnessError::CrateBehavior {
            expected: 1,
            actual: 0,
        }
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
    let l1_raw = <Layout as DescriptorLayout<_, Granule4KiB>>::table_descriptor(
        TableAddr::new(l2 as u64).map_err(|_| HarnessError::InvalidState)?,
        l1_to_l2,
        table_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let table_fields = <Format as AttributeCodec<Regime, Granule4KiB, _>>::encode_table(
        &config,
        Level::L2,
        Default::default(),
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let l2_raw = <Layout as DescriptorLayout<_, Granule4KiB>>::table_descriptor(
        TableAddr::new(l3 as u64).map_err(|_| HarnessError::InvalidState)?,
        l2_to_l3,
        table_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let leaf_fields = <Format as AttributeCodec<Regime, Granule4KiB, _>>::encode_leaf(
        &config,
        Level::L3,
        semantic,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let source_raw = <Layout as DescriptorLayout<_, Granule4KiB>>::leaf_descriptor(
        PhysAddr(source as u64),
        Level::L3,
        leaf_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    let destination_raw = <Layout as DescriptorLayout<_, Granule4KiB>>::leaf_descriptor(
        PhysAddr(destination as u64),
        Level::L3,
        leaf_fields,
    )
    .map_err(|_| HarnessError::CrateBehavior {
        expected: 1,
        actual: 0,
    })?;
    unsafe {
        <Format as DescriptorFormat>::write_descriptor(l1 as *mut u64, l1_raw);
        <Format as DescriptorFormat>::write_descriptor(l2 as *mut u64, l2_raw);
        <Format as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(1), source_raw);
        <Format as DescriptorFormat>::write_descriptor((l3 as *mut u64).add(2), destination_raw);
    }

    // Linear stream table, SID 0, stage-2-only. VTCR describes a 39-bit, 4 KiB,
    // inner-shareable, WBWA walk rooted at level 1.
    let vtcr = 25u64 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
    unsafe {
        (stream_table as *mut u64).write((1u64 | (6u64 << 1)).to_le());
        (stream_table as *mut u64)
            .add(1)
            .write((1u64 << 44).to_le());
        (stream_table as *mut u64)
            .add(2)
            .write((1 | (vtcr << 32) | (1u64 << 51) | (1u64 << 54)).to_le());
        (stream_table as *mut u64)
            .add(3)
            .write(((l1 as u64) & 0x000f_ffff_ffff_fff0).to_le());
    }

    for (address, bytes) in [
        (l1 as u64, 4096),
        (l2 as u64, 4096),
        (l3 as u64, 4096),
        (stream_table as u64, 64),
        (source as u64, 4096),
        (destination as u64, 4096),
    ] {
        context.maintain_cache(vmsa_test_harness::CacheMaintenanceOperation::CleanData {
            address,
            bytes,
        })?;
    }

    const SMMU: usize = 0x2b40_0000;
    unsafe {
        write32(SMMU + 0x20, 0);
    }
    if !wait32(SMMU + 0x24, 0) {
        return failed(0, unsafe { read32(SMMU + 0x24) }.into());
    }
    unsafe {
        write32(SMMU + 0x28, (1 << 10) | (1 << 8) | (1 << 6));
        write64(SMMU + 0x80, (stream_table as u64) & 0x000f_ffff_ffff_ffc0);
        write32(SMMU + 0x88, 0);
        write32(SMMU + 0x20, 1);
    }
    if !wait32(SMMU + 0x24, 1) {
        return failed(1, unsafe { read32(SMMU + 0x24) }.into());
    }

    const USER: usize = 0x2bfe_0000;
    const PRIVILEGED: usize = 0x2bff_0000;
    unsafe {
        write32(PRIVILEGED, 1); // Non-secure transaction
        write32(PRIVILEGED + 4, 0);
        write32(PRIVILEGED + 8, 0); // SID 0
        write32(PRIVILEGED + 12, u32::MAX);
        write32(USER, 1);
        write32(USER + 4, 0);
        write32(USER + 0x20, 0x42ff_42ff);
        write64(USER + 0x28, 0x1000);
        write64(USER + 0x30, 0x1fff);
        write64(USER + 0x38, 1);
        write64(USER + 0x40, 0x2000);
        write32(USER, 2);
    }
    let mut status = 0;
    for _ in 0..1_000_000 {
        status = unsafe { read32(USER) };
        if status == 1 || status == u32::MAX || status == u32::MAX - 1 {
            break;
        }
        core::hint::spin_loop();
    }
    if status != 1 {
        return failed(1, status.into());
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
