use vmsa_test_harness::{HarnessError, TestResult};

pub fn raw_field_bounds() -> TestResult {
    use aarch64_vmsa::attrs::AttrError;
    use aarch64_vmsa::low_level::raw::{
        FourBit, LeafAp, RawShareability, Stage1NotDirty, Stage2Ap, Stage2Dirty,
        Stage2ExecuteNever, TableAp, TenBit, ThreeBit,
    };

    macro_rules! bounded {
        ($constructor:path, $maximum:expr, $invalid:expr) => {{
            let zero = $constructor(0).map_err(|_| HarnessError::InvalidState)?;
            let maximum = $constructor($maximum).map_err(|_| HarnessError::InvalidState)?;
            if zero.bits() != 0
                || maximum.bits() != $maximum
                || $constructor($invalid) != Err(AttrError::RawFieldOutOfRange)
            {
                return HarnessError::InvalidState.into();
            }
        }};
    }

    bounded!(FourBit::new, 0xf, 0x10);
    bounded!(ThreeBit::new, 0x7, 0x8);
    bounded!(TenBit::new, 0x3ff, 0x400);
    bounded!(LeafAp::from_bits, 0b11, 0b100);
    bounded!(TableAp::from_bits, 0b11, 0b100);
    bounded!(Stage2Ap::from_bits, 0b11, 0b100);
    bounded!(Stage2ExecuteNever::from_bits, 0b11, 0b100);

    for bits in [0b00, 0b10, 0b11] {
        if RawShareability::from_bits(bits)
            .map(|value| value.bits())
            .ok()
            != Some(bits)
        {
            return HarnessError::InvalidState.into();
        }
    }
    if RawShareability::from_bits(0b01) != Err(AttrError::InvalidShareability) {
        return HarnessError::InvalidState.into();
    }
    for value in [false, true] {
        if Stage1NotDirty::new(value).bit() != value || Stage2Dirty::new(value).bit() != value {
            return HarnessError::InvalidState.into();
        }
    }
    TestResult::Pass
}

pub fn descriptor_errors() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::attrs::AttrError;
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa64};
    use aarch64_vmsa::low_level::raw::{
        FourBit, LeafAp, RawShareability, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
        TableAp, ThreeBit,
    };
    use aarch64_vmsa::table::{TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage1;

    type Layout = <Vmsa64 as HasLayout<Stage1, Granule4KiB>>::Layout;
    let leaf = RawVmsa64Stage1LeafAttrs {
        attr_index: ThreeBit::new(0).map_err(|_| HarnessError::InvalidState)?,
        ns: false,
        ap: LeafAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        shareability: RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: false,
        dirty_bit_modifier: false,
        contiguous: false,
        privileged_execute_never: false,
        unprivileged_execute_never: false,
        guarded: false,
        software: FourBit::ZERO,
    };
    if <Layout as DescriptorLayout<Vmsa64, Stage1, Granule4KiB>>::leaf_descriptor(
        PhysAddr(0),
        Level::L0,
        leaf,
    ) != Err(DescriptorError::InvalidLeafLevel { level: Level::L0 })
    {
        return HarnessError::InvalidState.into();
    }
    let parent = TableShape::<Vmsa64, Granule4KiB>::root(Level::L0);
    let child = TableShape::<Vmsa64, Granule4KiB>::new(Level::L2, 2)
        .map_err(|_| HarnessError::InvalidState)?;
    let transition = TableTransition::new(parent, child).map_err(|_| HarnessError::InvalidState)?;
    let table = RawVmsa64Stage1TableAttrs {
        privileged_execute_never_limit: false,
        unprivileged_execute_never_limit: false,
        ap_table: TableAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        ns_table: false,
        software: FourBit::ZERO,
    };
    if <Layout as DescriptorLayout<Vmsa64, Stage1, Granule4KiB>>::table_descriptor(
        PhysAddr(0x4000),
        transition,
        table,
    ) != Err(DescriptorError::InvalidTableTransition {
        parent_level: Level::L0,
        child_level: Level::L2,
        stride_count: 2,
    }) || FourBit::new(0x10) != Err(AttrError::RawFieldOutOfRange)
    {
        return HarnessError::InvalidState.into();
    }
    TestResult::Pass
}

fn d128_stage1_leaf(
    bbm_nt: bool,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs, HarnessError> {
    use aarch64_vmsa::low_level::raw::{
        FourBit, PermissionIndices, RawShareability, RawVmsa128Stage1LeafAttrs, Stage1NotDirty,
        TenBit,
    };
    Ok(RawVmsa128Stage1LeafAttrs {
        attr_index: FourBit::ZERO,
        bbm_nt,
        not_dirty: Stage1NotDirty::new(false),
        shareability: RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: false,
        contiguous: false,
        guarded: false,
        protected: false,
        permissions: PermissionIndices {
            pi: FourBit::ZERO,
            po: FourBit::ZERO,
        },
        ns: false,
        software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
    })
}

fn d128_stage2_leaf(
    bbm_nt: bool,
) -> Result<aarch64_vmsa::low_level::raw::RawVmsa128Stage2LeafAttrs, HarnessError> {
    use aarch64_vmsa::low_level::raw::{
        FourBit, PermissionIndices, RawShareability, RawVmsa128Stage2LeafAttrs, Stage2Dirty, TenBit,
    };
    Ok(RawVmsa128Stage2LeafAttrs {
        mem_attr: FourBit::ZERO,
        bbm_nt,
        dirty: Stage2Dirty::new(false),
        shareability: RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        force_no_execute: false,
        contiguous: false,
        assured_only: false,
        permissions: PermissionIndices {
            pi: FourBit::ZERO,
            po: FourBit::ZERO,
        },
        ns: false,
        software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
    })
}

pub fn d128_stage1_final_bbm_nt_error() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::translation::Stage1;
    type Layout = <Vmsa128 as HasLayout<Stage1, Granule4KiB>>::Layout;
    if <Layout as DescriptorLayout<Vmsa128, Stage1, Granule4KiB>>::leaf_descriptor(
        PhysAddr(0),
        Level::L3,
        d128_stage1_leaf(true)?,
    ) == Err(DescriptorError::InvalidNtBbmCombination { level: Level::L3 })
    {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}

pub fn d128_stage2_final_bbm_nt_error() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::translation::Stage2;
    type Layout = <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout;
    if <Layout as DescriptorLayout<Vmsa128, Stage2, Granule4KiB>>::leaf_descriptor(
        PhysAddr(0),
        Level::L3,
        d128_stage2_leaf(true)?,
    ) == Err(DescriptorError::InvalidNtBbmCombination { level: Level::L3 })
    {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}

pub fn d128_stage1_table_nt_skl0_error() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs;
    use aarch64_vmsa::table::{TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage1;
    type Layout = <Vmsa128 as HasLayout<Stage1, Granule4KiB>>::Layout;
    let transition = TableTransition::new(
        TableShape::<Vmsa128, Granule4KiB>::root(Level::L0),
        TableShape::<Vmsa128, Granule4KiB>::root(Level::L1),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let fields = RawVmsa128Stage1TableAttrs {
        table_nt: true,
        ..RawVmsa128Stage1TableAttrs::default()
    };
    if <Layout as DescriptorLayout<Vmsa128, Stage1, Granule4KiB>>::table_descriptor(
        PhysAddr(0),
        transition,
        fields,
    ) == Err(DescriptorError::ReservedFieldSet { bit: 6 })
    {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}

pub fn d128_stage2_table_nt_skl0_error() -> TestResult {
    use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
    use aarch64_vmsa::descriptor::{DescriptorError, DescriptorLayout, HasLayout, Vmsa128};
    use aarch64_vmsa::low_level::raw::RawVmsa128Stage2TableAttrs;
    use aarch64_vmsa::table::{TableShape, TableTransition};
    use aarch64_vmsa::translation::Stage2;
    type Layout = <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout;
    let transition = TableTransition::new(
        TableShape::<Vmsa128, Granule4KiB>::root(Level::L0),
        TableShape::<Vmsa128, Granule4KiB>::root(Level::L1),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let fields = RawVmsa128Stage2TableAttrs {
        table_nt: true,
        ..RawVmsa128Stage2TableAttrs::default()
    };
    if <Layout as DescriptorLayout<Vmsa128, Stage2, Granule4KiB>>::table_descriptor(
        PhysAddr(0),
        transition,
        fields,
    ) == Err(DescriptorError::ReservedFieldSet { bit: 6 })
    {
        TestResult::Pass
    } else {
        HarnessError::InvalidState.into()
    }
}
