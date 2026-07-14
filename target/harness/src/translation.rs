#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeError {
    RawFieldOutOfRange,
    UnencodablePermissions,
    InvalidLeafAp(u8),
    InvalidTableAp(u8),
    InvalidStage2Permission(u8),
    InvalidStage2ExecuteNever,
    InvalidOutputAddressSpace,
    InvalidShareability,
    ShareabilityMismatch,
    MemoryAttributeNotConfigured,
    Mair2Unavailable,
    UnencodableMemoryAttribute,
    WrongStage2MemoryMode,
    MtePermissionUnavailable,
    PermissionIndirectionUnavailable,
    PermissionCombinationNotConfigured,
    InvalidD128Alias,
    InvalidD128Configuration,
    ConflictingSemanticAttributes,
}

impl AttributeError {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::RawFieldOutOfRange => 0,
            Self::UnencodablePermissions => 1,
            Self::InvalidLeafAp(value) => 0x20 + value as u64,
            Self::InvalidTableAp(value) => 0x40 + value as u64,
            Self::InvalidStage2Permission(value) => 0x60 + value as u64,
            Self::InvalidStage2ExecuteNever => 3,
            Self::InvalidOutputAddressSpace => 4,
            Self::InvalidShareability => 5,
            Self::ShareabilityMismatch => 6,
            Self::MemoryAttributeNotConfigured => 7,
            Self::Mair2Unavailable => 8,
            Self::UnencodableMemoryAttribute => 9,
            Self::WrongStage2MemoryMode => 10,
            Self::MtePermissionUnavailable => 11,
            Self::PermissionIndirectionUnavailable => 12,
            Self::PermissionCombinationNotConfigured => 13,
            Self::InvalidD128Alias => 14,
            Self::InvalidD128Configuration => 15,
            Self::ConflictingSemanticAttributes => 16,
        }
    }
}

pub(crate) fn normalize_attribute_error(error: aarch64_vmsa::attrs::AttrError) -> AttributeError {
    use aarch64_vmsa::attrs::AttrError;
    match error {
        AttrError::RawFieldOutOfRange => AttributeError::RawFieldOutOfRange,
        AttrError::UnencodablePermissions => AttributeError::UnencodablePermissions,
        AttrError::InvalidLeafAp(value) => AttributeError::InvalidLeafAp(value),
        AttrError::InvalidTableAp(value) => AttributeError::InvalidTableAp(value),
        AttrError::InvalidStage2Permission(value) => AttributeError::InvalidStage2Permission(value),
        AttrError::InvalidStage2ExecuteNever => AttributeError::InvalidStage2ExecuteNever,
        AttrError::InvalidOutputAddressSpace => AttributeError::InvalidOutputAddressSpace,
        AttrError::InvalidShareability => AttributeError::InvalidShareability,
        AttrError::ShareabilityMismatch { .. } => AttributeError::ShareabilityMismatch,
        AttrError::MemoryAttributeNotConfigured => AttributeError::MemoryAttributeNotConfigured,
        AttrError::Mair2Unavailable => AttributeError::Mair2Unavailable,
        AttrError::UnencodableMemoryAttribute => AttributeError::UnencodableMemoryAttribute,
        AttrError::WrongStage2MemoryMode => AttributeError::WrongStage2MemoryMode,
        AttrError::MtePermissionUnavailable => AttributeError::MtePermissionUnavailable,
        AttrError::PermissionIndirectionUnavailable => {
            AttributeError::PermissionIndirectionUnavailable
        }
        AttrError::PermissionCombinationNotConfigured => {
            AttributeError::PermissionCombinationNotConfigured
        }
        AttrError::InvalidD128Alias => AttributeError::InvalidD128Alias,
        AttrError::InvalidD128Configuration => AttributeError::InvalidD128Configuration,
        AttrError::ConflictingSemanticAttributes => AttributeError::ConflictingSemanticAttributes,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalAddress(u64);
impl PhysicalAddress {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationStage {
    Stage1,
    Stage2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Granule {
    Size4KiB,
    Size16KiB,
    Size64KiB,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionStack {
    pub(crate) physical_top: u64,
    pub(crate) virtual_top: u64,
    pub(crate) granule: Granule,
    pub(crate) recovery_root: u64,
    pub(crate) recovery_tcr: u64,
    pub(crate) recovery_mair: u64,
    pub(crate) recovery_vector: u64,
}

impl TransitionStack {
    pub const fn physical_top(self) -> u64 {
        self.physical_top
    }

    pub const fn virtual_top(self) -> u64 {
        self.virtual_top
    }

    pub const fn granule(self) -> Granule {
        self.granule
    }

    pub const fn recovery_root(self) -> u64 {
        self.recovery_root
    }

    pub const fn recovery_tcr(self) -> u64 {
        self.recovery_tcr
    }

    pub const fn recovery_mair(self) -> u64 {
        self.recovery_mair
    }

    pub const fn recovery_vector(self) -> u64 {
        self.recovery_vector
    }
}

impl Granule {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size4KiB => 4096,
            Self::Size16KiB => 16 * 1024,
            Self::Size64KiB => 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlbiOperation {
    All,
    Address(u64),
    Range { start: u64, pages: u64 },
    VirtualAddress(u64),
    IntermediatePhysicalAddress(u64),
    VirtualRange { start: u64, pages: u64 },
    IntermediatePhysicalRange { start: u64, pages: u64 },
    Asid(Asid),
    Vmid(Vmid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlbiScope {
    Local,
    InnerShareable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationFormat {
    Vmsa64,
    Vmsa64Lpa2,
    Vmsa128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressBits(u8);
impl AddressBits {
    pub const fn new(bits: u8) -> Option<Self> {
        if bits >= 32 && bits <= 56 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupLevel(i8);
impl LookupLevel {
    pub const fn new(level: i8) -> Option<Self> {
        if level >= -2 && level <= 3 {
            Some(Self(level))
        } else {
            None
        }
    }
    pub const fn get(self) -> i8 {
        self.0
    }
}

pub const fn stage1_start_level(
    format: TranslationFormat,
    granule: Granule,
    input_bits: AddressBits,
) -> Option<LookupLevel> {
    let bits = input_bits.get();
    let maximum = match format {
        TranslationFormat::Vmsa64 => 48,
        TranslationFormat::Vmsa64Lpa2 => 52,
        TranslationFormat::Vmsa128 => 56,
    };
    if bits < 32
        || bits > maximum
        || (matches!(format, TranslationFormat::Vmsa128) && !matches!(granule, Granule::Size4KiB))
    {
        return None;
    }
    let level = match granule {
        Granule::Size4KiB => {
            if bits <= 39 {
                1
            } else if bits <= 48 {
                0
            } else {
                -1
            }
        }
        Granule::Size16KiB => {
            if bits <= 36 {
                2
            } else if bits <= 47 {
                1
            } else {
                0
            }
        }
        Granule::Size64KiB => {
            if bits <= 42 {
                2
            } else {
                1
            }
        }
    };
    LookupLevel::new(level)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asid(pub u16);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmid(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryAttributeSlot(u8);

impl MemoryAttributeSlot {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 16 { Some(Self(index)) } else { None }
    }

    pub const fn index(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1MemoryControls {
    mair: u64,
    mair2: u64,
}

impl Stage1MemoryControls {
    pub const DEFAULT: Self = Self {
        mair: 0x0000_ff44,
        mair2: 0,
    };

    pub const fn empty() -> Self {
        Self { mair: 0, mair2: 0 }
    }

    pub fn with_attribute(
        mut self,
        slot: MemoryAttributeSlot,
        attributes: aarch64_vmsa::attrs::MemoryAttributes,
    ) -> Result<Self, AttributeError> {
        let encoded = encode_memory_attributes(attributes)?;
        let index = slot.index();
        let (register, shift) = if index < 8 {
            (&mut self.mair, u32::from(index) * 8)
        } else {
            (&mut self.mair2, u32::from(index - 8) * 8)
        };
        *register = (*register & !(0xff_u64 << shift)) | (u64::from(encoded) << shift);
        Ok(self)
    }

    pub(crate) const fn registers(self) -> (u64, u64) {
        (self.mair, self.mair2)
    }
}

fn encode_memory_attributes(
    attributes: aarch64_vmsa::attrs::MemoryAttributes,
) -> Result<u8, AttributeError> {
    use aarch64_vmsa::attrs::{
        AllocationHints, CachePolicy, Cacheability, DeviceMemoryType, MemoryAttributes,
        MemoryTransience,
    };

    const fn device(value: DeviceMemoryType) -> u8 {
        match value {
            DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck => 0,
            DeviceMemoryType::NonGatheringNonReorderingEarlyAck => 1,
            DeviceMemoryType::NonGatheringReorderingEarlyAck => 2,
            DeviceMemoryType::GatheringReorderingEarlyAck => 3,
        }
    }

    fn cacheability(value: Cacheability) -> Result<u8, AttributeError> {
        match value {
            Cacheability::NonCacheable => Ok(0b0100),
            Cacheability::Cacheable {
                policy,
                transience,
                allocation,
            } => {
                let high = match (policy, transience) {
                    (CachePolicy::WriteThrough, MemoryTransience::Transient) => 0b0000,
                    (CachePolicy::WriteBack, MemoryTransience::Transient) => 0b0100,
                    (CachePolicy::WriteThrough, MemoryTransience::NonTransient) => 0b1000,
                    (CachePolicy::WriteBack, MemoryTransience::NonTransient) => 0b1100,
                };
                let low = match allocation {
                    AllocationHints::None => 0,
                    AllocationHints::WriteAllocate => 1,
                    AllocationHints::ReadAllocate => 2,
                    AllocationHints::ReadWriteAllocate => 3,
                };
                if transience == MemoryTransience::Transient && low == 0 {
                    Err(AttributeError::UnencodableMemoryAttribute)
                } else {
                    Ok(high | low)
                }
            }
        }
    }

    match attributes {
        MemoryAttributes::Device(value) => Ok(device(value) << 2),
        MemoryAttributes::Normal { inner, outer } => {
            Ok(cacheability(inner)? | cacheability(outer)? << 4)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D128MappingPermissions {
    ReadExecute,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D128HardwareManagedAttributes {
    pub permissions: D128MappingPermissions,
    pub access_flag: bool,
    pub dirty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D128HardwareUpdateInspection {
    pub access_flag: bool,
    pub dirty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslationControls(u64);
impl TranslationControls {
    pub const EMPTY: Self = Self(0);
    pub const PRESERVE_CURRENT: Self = Self(1 << 63);
    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn preserves_current(self) -> bool {
        self.0 & Self::PRESERVE_CURRENT.0 != 0
    }
}

pub const fn lpa2_el2_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() != 52 || output_bits.get() != 52 {
        return None;
    }
    Some(TranslationControls::from_bits(
        12 | (1 << 8) | (1 << 10) | (3 << 12) | (6 << 16) | (1 << 23) | (1 << 31) | (1 << 32),
    ))
}

pub const fn lpa2_el1_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    lpa2_el1_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

pub const fn lpa2_el1_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() != 52 || output_bits.get() != 52 {
        return None;
    }
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    Some(TranslationControls::from_bits(
        12 | (1 << 8) | (1 << 10) | (3 << 12) | (tg0 << 14) | (1 << 23) | (6 << 32) | (1 << 59),
    ))
}

pub const fn d128_el1_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() != 52 || output_bits.get() != 52 {
        return None;
    }
    Some(TranslationControls::from_bits(
        12 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (6 << 32),
    ))
}

pub const fn d128_el2_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() < 44 || input_bits.get() > 52 {
        return None;
    }
    let (ps, ds) = match output_bits.get() {
        48 => (5u64, 0u64),
        52 => (6u64, 1u64 << 32),
        _ => return None,
    };
    Some(TranslationControls::from_bits(
        (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (ps << 16)
            | (1 << 23)
            | (1 << 31)
            | ds,
    ))
}

pub const fn vmsa64_stage2_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
    start_level: LookupLevel,
) -> Option<TranslationControls> {
    let (minimum_input, maximum_input, sl0) = match start_level.get() {
        0 => (40, 48, 2u64),
        1 => (31, 39, 1u64),
        2 => (22, 30, 0u64),
        3 => (12, 21, 3u64),
        _ => return None,
    };
    if input_bits.get() < minimum_input || input_bits.get() > maximum_input {
        return None;
    }
    let ps = match output_bits.get() {
        32 => 0u64,
        36 => 1u64,
        40 => 2u64,
        42 => 3u64,
        44 => 4u64,
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    Some(TranslationControls::from_bits(
        (1 << 31)
            | (64 - input_bits.get() as u64)
            | (sl0 << 6)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (ps << 16),
    ))
}

pub const fn d128_stage2_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() < 44 || input_bits.get() > 52 {
        return None;
    }
    let ps = match output_bits.get() {
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    Some(TranslationControls::from_bits(
        (1 << 31)
            | (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (ps << 16)
            | (1 << 36)
            | (1 << 38),
    ))
}

pub const fn vmsa64_el1_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    vmsa64_el1_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

pub const fn vmsa64_el1_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() < 32 || input_bits.get() > 48 {
        return None;
    }
    let ips = match output_bits.get() {
        32 => 0u64,
        36 => 1u64,
        40 => 2u64,
        42 => 3u64,
        44 => 4u64,
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    Some(TranslationControls::from_bits(
        (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (1 << 23)
            | (ips << 32),
    ))
}

pub const fn vmsa64_el2_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() < 32 || input_bits.get() > 48 {
        return None;
    }
    let ps = match output_bits.get() {
        32 => 0u64,
        36 => 1u64,
        40 => 2u64,
        42 => 3u64,
        44 => 4u64,
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    Some(TranslationControls::from_bits(
        (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (ps << 16)
            | (1 << 23)
            | (1 << 31),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegimeAttributes {
    Normal,
    Secure,
    Realm,
    Root,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslationSetup {
    pub root: PhysicalAddress,
    pub stage: TranslationStage,
    pub granule: Granule,
    pub format: TranslationFormat,
    pub input_bits: AddressBits,
    pub output_bits: AddressBits,
    pub start_level: Option<LookupLevel>,
    pub asid: Option<Asid>,
    pub vmid: Option<Vmid>,
    pub controls: TranslationControls,
    pub stage1_memory: Stage1MemoryControls,
    pub regime: RegimeAttributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledTranslation {
    setup: TranslationSetup,
    generation: u64,
    adapter_cookie: [u64; 6],
}

impl InstalledTranslation {
    pub const fn new(setup: TranslationSetup, generation: u64, adapter_cookie: [u64; 6]) -> Self {
        Self {
            setup,
            generation,
            adapter_cookie,
        }
    }

    pub const fn stage(self) -> TranslationStage {
        self.setup.stage
    }

    pub const fn setup(self) -> TranslationSetup {
        self.setup
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

use aarch64_vmsa::address::{
    Granule4KiB, Granule16KiB, Granule64KiB, Level, PhysAddr, TranslationGranule, VirtAddr,
};
use aarch64_vmsa::descriptor::{
    DescriptorFormat, DescriptorLayout, HasLayout, Vmsa64, Vmsa64Lpa2, Vmsa128,
};
use aarch64_vmsa::low_level::raw::{
    FourBit, LeafAp, PermissionIndices, RawShareability, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs,
    RawVmsa128Stage2TableAttrs, Stage1NotDirty, Stage2Ap, Stage2Dirty, Stage2ExecuteNever, TableAp,
    TenBit, ThreeBit,
};
use aarch64_vmsa::mapper::{Mapper, Offline};
use aarch64_vmsa::regime::{LeafFieldsOf, StageOf, TableFieldsOf, TranslationRegime};
use aarch64_vmsa::table::{
    OffsetTableAccess, RecursiveTableAccess, RootTable, TableAccess, TableAccessMut,
    TableAllocLayout, TableFrameProvider, TablePhysAddr, TableShape, TableTransition,
};
use aarch64_vmsa::translation::walk::{WalkInputAddr, WalkStep, Walker};
use aarch64_vmsa::translation::{Stage1, Stage2, TranslationWalkProfile};
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::HarnessError;
use crate::memory::TestMemory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingAttributes {
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
}

impl MappingAttributes {
    pub const READ_WRITE: Self = Self {
        writable: true,
        executable: false,
        user_accessible: false,
    };
    pub const READ_ONLY: Self = Self {
        writable: false,
        executable: false,
        user_accessible: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareManagedAttributes {
    pub mapping: MappingAttributes,
    pub access_flag: bool,
    pub dirty_modifier: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareUpdateInspection {
    pub access_flag: bool,
    pub writable: bool,
    pub dirty_modifier: bool,
}

pub trait TestRegime: TranslationRegime {
    fn default_input_bits(capabilities: crate::Capabilities) -> u8;
}

pub trait TestRegimeFor<G: TranslationGranule>: TestRegime
where
    Vmsa64: HasLayout<StageOf<Self>, G>,
{
    fn raw_leaf(
        attributes: MappingAttributes,
    ) -> Result<LeafFieldsOf<Vmsa64, Self, G>, HarnessError>;
    fn raw_table() -> Result<TableFieldsOf<Vmsa64, Self, G>, HarnessError>;
}

pub trait HardwareManagedStage1Regime<G: TranslationGranule>: TestRegimeFor<G>
where
    Vmsa64: HasLayout<StageOf<Self>, G>,
{
    fn raw_hardware_leaf(
        attributes: HardwareManagedAttributes,
    ) -> Result<LeafFieldsOf<Vmsa64, Self, G>, HarnessError>;

    fn inspect_hardware_fields(fields: &LeafFieldsOf<Vmsa64, Self, G>) -> HardwareUpdateInspection;
}

macro_rules! stage1_test_regime_for_granule {
    ($regime:ty, $granule:ty) => {
        impl TestRegimeFor<$granule> for $regime {
            fn raw_leaf(
                attributes: MappingAttributes,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                if attributes.user_accessible {
                    return Err(HarnessError::InvalidState);
                }
                let ap_bits = if attributes.writable { 0b01 } else { 0b11 };
                Ok(RawVmsa64Stage1LeafAttrs {
                    attr_index: ThreeBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                    ns: false,
                    ap: LeafAp::from_bits(ap_bits).map_err(|_| HarnessError::InvalidState)?,
                    shareability: RawShareability::from_bits(0b11)
                        .map_err(|_| HarnessError::InvalidState)?,
                    access_flag: true,
                    alias_bit: false,
                    dirty_bit_modifier: false,
                    contiguous: false,
                    privileged_execute_never: false,
                    unprivileged_execute_never: !attributes.executable,
                    guarded: false,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }

            fn raw_table() -> Result<TableFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                Ok(RawVmsa64Stage1TableAttrs {
                    privileged_execute_never_limit: false,
                    unprivileged_execute_never_limit: false,
                    ap_table: TableAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
                    ns_table: false,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }
        }

        impl HardwareManagedStage1Regime<$granule> for $regime {
            fn raw_hardware_leaf(
                attributes: HardwareManagedAttributes,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let mut fields = <Self as TestRegimeFor<$granule>>::raw_leaf(attributes.mapping)?;
                fields.access_flag = attributes.access_flag;
                fields.dirty_bit_modifier = attributes.dirty_modifier;
                Ok(fields)
            }

            fn inspect_hardware_fields(
                fields: &LeafFieldsOf<Vmsa64, Self, $granule>,
            ) -> HardwareUpdateInspection {
                HardwareUpdateInspection {
                    access_flag: fields.access_flag,
                    writable: fields.ap.bits() == 0b01,
                    dirty_modifier: fields.dirty_bit_modifier,
                }
            }
        }
    };
}

macro_rules! stage1_test_regime {
    ($regime:ty) => {
        impl TestRegime for $regime {
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.va_bits.min(48)
            }
        }
        stage1_test_regime_for_granule!($regime, Granule4KiB);
        stage1_test_regime_for_granule!($regime, Granule16KiB);
        stage1_test_regime_for_granule!($regime, Granule64KiB);
    };
}

stage1_test_regime!(aarch64_vmsa::regime::NonSecureEl2Stage1);
stage1_test_regime!(aarch64_vmsa::regime::SecureEl2Stage1);
stage1_test_regime!(aarch64_vmsa::regime::RealmEl2Stage1);
stage1_test_regime!(aarch64_vmsa::regime::RootEl3Stage1);

macro_rules! two_privilege_test_regime_for_granule {
    ($regime:ty, $granule:ty) => {
        impl TestRegimeFor<$granule> for $regime {
            fn raw_leaf(
                attributes: MappingAttributes,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let ap_bits = match (attributes.user_accessible, attributes.writable) {
                    (false, true) => 0b00,
                    (true, true) => 0b01,
                    (false, false) => 0b10,
                    (true, false) => 0b11,
                };
                Ok(RawVmsa64Stage1LeafAttrs {
                    attr_index: ThreeBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                    ns: false,
                    ap: LeafAp::from_bits(ap_bits).map_err(|_| HarnessError::InvalidState)?,
                    shareability: RawShareability::from_bits(0b11)
                        .map_err(|_| HarnessError::InvalidState)?,
                    access_flag: true,
                    alias_bit: false,
                    dirty_bit_modifier: false,
                    contiguous: false,
                    privileged_execute_never: !attributes.executable,
                    unprivileged_execute_never: !attributes.executable,
                    guarded: false,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }

            fn raw_table() -> Result<TableFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                Ok(RawVmsa64Stage1TableAttrs {
                    privileged_execute_never_limit: false,
                    unprivileged_execute_never_limit: false,
                    ap_table: TableAp::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
                    ns_table: false,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }
        }

        impl HardwareManagedStage1Regime<$granule> for $regime {
            fn raw_hardware_leaf(
                attributes: HardwareManagedAttributes,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let mut fields = <Self as TestRegimeFor<$granule>>::raw_leaf(attributes.mapping)?;
                fields.access_flag = attributes.access_flag;
                fields.dirty_bit_modifier = attributes.dirty_modifier;
                Ok(fields)
            }

            fn inspect_hardware_fields(
                fields: &LeafFieldsOf<Vmsa64, Self, $granule>,
            ) -> HardwareUpdateInspection {
                HardwareUpdateInspection {
                    access_flag: fields.access_flag,
                    writable: matches!(fields.ap.bits(), 0b00 | 0b01),
                    dirty_modifier: fields.dirty_bit_modifier,
                }
            }
        }
    };
}

macro_rules! two_privilege_test_regime {
    ($regime:ty) => {
        impl TestRegime for $regime {
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.va_bits.min(48)
            }
        }
        two_privilege_test_regime_for_granule!($regime, Granule4KiB);
        two_privilege_test_regime_for_granule!($regime, Granule16KiB);
        two_privilege_test_regime_for_granule!($regime, Granule64KiB);
    };
}

two_privilege_test_regime!(aarch64_vmsa::regime::NonSecureEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::regime::SecureEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::regime::RealmEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::regime::NonSecureEl2HostStage1);
two_privilege_test_regime!(aarch64_vmsa::regime::SecureEl2HostStage1);
two_privilege_test_regime!(aarch64_vmsa::regime::RealmEl2HostStage1);

macro_rules! stage2_test_regime_for_granule {
    ($regime:ty, $granule:ty) => {
        impl TestRegimeFor<$granule> for $regime {
            fn raw_leaf(
                attributes: MappingAttributes,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let access = if attributes.writable { 0b11 } else { 0b01 };
                Ok(RawVmsa64Stage2LeafAttrs {
                    mem_attr: FourBit::new(0xf).map_err(|_| HarnessError::InvalidState)?,
                    access: Stage2Ap::from_bits(access).map_err(|_| HarnessError::InvalidState)?,
                    shareability: RawShareability::from_bits(0b11)
                        .map_err(|_| HarnessError::InvalidState)?,
                    access_flag: true,
                    dirty_bit_modifier: false,
                    contiguous: false,
                    execute_never: Stage2ExecuteNever::from_bits(if attributes.executable {
                        0
                    } else {
                        0b10
                    })
                    .map_err(|_| HarnessError::InvalidState)?,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }

            fn raw_table() -> Result<TableFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                Ok(RawVmsa64Stage2TableAttrs {
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }
        }
    };
}

macro_rules! stage2_test_regime {
    ($regime:ty) => {
        impl TestRegime for $regime {
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.pa_bits.min(48)
            }
        }
        stage2_test_regime_for_granule!($regime, Granule4KiB);
        stage2_test_regime_for_granule!($regime, Granule16KiB);
        stage2_test_regime_for_granule!($regime, Granule64KiB);
    };
}

stage2_test_regime!(aarch64_vmsa::regime::NonSecureEl2Stage2);
stage2_test_regime!(
    aarch64_vmsa::regime::NonSecureEl2Stage2<aarch64_vmsa::attrs::Stage2XnxPermissions>
);
stage2_test_regime!(aarch64_vmsa::regime::SecureEl2SecureIpaStage2);
stage2_test_regime!(aarch64_vmsa::regime::SecureEl2NonSecureIpaStage2);
stage2_test_regime!(aarch64_vmsa::regime::RealmEl2Stage2);

pub(crate) struct ArenaFrameProvider {
    memory: NonNull<TestMemory>,
}

impl ArenaFrameProvider {
    pub(crate) const fn new(memory: NonNull<TestMemory>) -> Self {
        Self { memory }
    }

    const fn memory(&self) -> NonNull<TestMemory> {
        self.memory
    }
}

impl<G: aarch64_vmsa::address::TranslationGranule> TableFrameProvider<G> for ArenaFrameProvider {
    type Error = crate::MemoryError;
    type Frame = TablePhysAddr<G>;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<Self::Frame, Self::Error> {
        // SAFETY: TestContext serializes access to the arena for the mapper lifetime.
        <TestMemory as TableFrameProvider<G>>::allocate_zeroed_table(
            unsafe { self.memory.as_mut() },
            layout,
        )
    }

    unsafe fn free_table(
        &mut self,
        frame: TablePhysAddr<G>,
        layout: TableAllocLayout,
    ) -> Result<(), Self::Error> {
        // SAFETY: The mapper supplies a frame previously returned by this provider.
        unsafe {
            <TestMemory as TableFrameProvider<G>>::free_table(self.memory.as_mut(), frame, layout)
        }
    }
}

pub trait TestGranule: TranslationGranule {
    const DEFAULT_START_LEVEL: Level;
    const GRANULE: Granule;
}

impl TestGranule for Granule4KiB {
    const DEFAULT_START_LEVEL: Level = Level::L0;
    const GRANULE: Granule = Granule::Size4KiB;
}

impl TestGranule for Granule16KiB {
    const DEFAULT_START_LEVEL: Level = Level::L0;
    const GRANULE: Granule = Granule::Size16KiB;
}

impl TestGranule for Granule64KiB {
    const DEFAULT_START_LEVEL: Level = Level::L1;
    const GRANULE: Granule = Granule::Size64KiB;
}

pub trait TestFormat: DescriptorFormat {
    const FORMAT: TranslationFormat;
    fn descriptor_bits(raw: Self::Raw) -> DescriptorBits;
    fn raw_descriptor(bits: DescriptorBits) -> Option<Self::Raw>;
}

impl TestFormat for Vmsa64 {
    const FORMAT: TranslationFormat = TranslationFormat::Vmsa64;
    fn descriptor_bits(raw: Self::Raw) -> DescriptorBits {
        DescriptorBits { low: raw, high: 0 }
    }
    fn raw_descriptor(bits: DescriptorBits) -> Option<Self::Raw> {
        (bits.high == 0).then_some(bits.low)
    }
}

impl TestFormat for Vmsa64Lpa2 {
    const FORMAT: TranslationFormat = TranslationFormat::Vmsa64Lpa2;
    fn descriptor_bits(raw: Self::Raw) -> DescriptorBits {
        DescriptorBits { low: raw, high: 0 }
    }
    fn raw_descriptor(bits: DescriptorBits) -> Option<Self::Raw> {
        (bits.high == 0).then_some(bits.low)
    }
}

impl TestFormat for Vmsa128 {
    const FORMAT: TranslationFormat = TranslationFormat::Vmsa128;
    fn descriptor_bits(raw: Self::Raw) -> DescriptorBits {
        DescriptorBits {
            low: raw as u64,
            high: (raw >> 64) as u64,
        }
    }
    fn raw_descriptor(bits: DescriptorBits) -> Option<Self::Raw> {
        Some(u128::from(bits.low) | (u128::from(bits.high) << 64))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchitecturalInvalidation {
    stage: TranslationStage,
    identifier: u16,
    lower_stage1: bool,
    failed: bool,
}

impl ArchitecturalInvalidation {
    pub const fn new(stage: TranslationStage, identifier: u16, lower_stage1: bool) -> Self {
        Self {
            stage,
            identifier,
            lower_stage1,
            failed: false,
        }
    }

    pub const fn failed(&self) -> bool {
        self.failed
    }

    fn invalidate_all(&mut self) {
        vmsa_test_architecture::barriers::dsb_ishst();
        match self.stage {
            TranslationStage::Stage1 => {
                if self.lower_stage1 {
                    vmsa_test_architecture::barriers::invalidate_el1_stage1_all();
                } else {
                    if !vmsa_test_architecture::barriers::invalidate_current_stage1_all() {
                        self.failed = true;
                    }
                }
            }
            TranslationStage::Stage2 => {
                vmsa_test_architecture::barriers::invalidate_stage2_all();
            }
        }
    }

    fn invalidate_address(&mut self, address: u64) {
        match self.stage {
            TranslationStage::Stage1 => {
                if self.lower_stage1 {
                    vmsa_test_architecture::barriers::invalidate_el1_stage1_address(
                        address,
                        self.identifier,
                    );
                } else {
                    if !vmsa_test_architecture::barriers::invalidate_current_stage1_address(
                        address,
                        self.identifier,
                    ) {
                        self.failed = true;
                    }
                }
            }
            TranslationStage::Stage2 => {
                if !vmsa_test_architecture::barriers::invalidate_stage2_address(address) {
                    self.invalidate_all();
                }
            }
        }
    }
}

pub(crate) fn explicit_tlbi(
    setup: TranslationSetup,
    lower_stage1: bool,
    scope: TlbiScope,
    mut operation: TlbiOperation,
) -> Result<(), HarnessError> {
    operation = match operation {
        TlbiOperation::VirtualAddress(address) if setup.stage == TranslationStage::Stage1 => {
            TlbiOperation::Address(address)
        }
        TlbiOperation::IntermediatePhysicalAddress(address)
            if setup.stage == TranslationStage::Stage2 =>
        {
            TlbiOperation::Address(address)
        }
        TlbiOperation::VirtualRange { start, pages } if setup.stage == TranslationStage::Stage1 => {
            TlbiOperation::Range { start, pages }
        }
        TlbiOperation::IntermediatePhysicalRange { start, pages }
            if setup.stage == TranslationStage::Stage2 =>
        {
            TlbiOperation::Range { start, pages }
        }
        TlbiOperation::Asid(asid) => {
            return explicit_asid_tlbi(setup, lower_stage1, scope, asid);
        }
        TlbiOperation::Vmid(vmid)
            if setup.stage == TranslationStage::Stage2 && setup.vmid == Some(vmid) =>
        {
            TlbiOperation::All
        }
        TlbiOperation::VirtualAddress(_)
        | TlbiOperation::IntermediatePhysicalAddress(_)
        | TlbiOperation::VirtualRange { .. }
        | TlbiOperation::IntermediatePhysicalRange { .. }
        | TlbiOperation::Vmid(_) => return Err(HarnessError::InvalidState),
        operation => operation,
    };
    if scope == TlbiScope::Local {
        return explicit_local_tlbi(setup, lower_stage1, operation);
    }
    let mut invalidation = ArchitecturalInvalidation::new(
        setup.stage,
        match setup.stage {
            TranslationStage::Stage1 => setup.asid.map_or(0, |asid| asid.0),
            TranslationStage::Stage2 => setup.vmid.map_or(0, |vmid| vmid.0),
        },
        lower_stage1,
    );
    match operation {
        TlbiOperation::All => invalidation.invalidate_all(),
        TlbiOperation::Address(address) => {
            if !address.is_multiple_of(setup.granule.bytes()) {
                return Err(HarnessError::InvalidState);
            }
            invalidation.invalidate_address(address);
        }
        TlbiOperation::Range { start, pages } => {
            if pages == 0 || !start.is_multiple_of(setup.granule.bytes()) {
                return Err(HarnessError::InvalidState);
            }
            let stride = setup.granule.bytes();
            let mut address = start;
            for index in 0..pages {
                invalidation.invalidate_address(address);
                if index + 1 != pages {
                    address = address
                        .checked_add(stride)
                        .ok_or(HarnessError::InvalidState)?;
                }
            }
        }
        TlbiOperation::VirtualAddress(_)
        | TlbiOperation::IntermediatePhysicalAddress(_)
        | TlbiOperation::VirtualRange { .. }
        | TlbiOperation::IntermediatePhysicalRange { .. }
        | TlbiOperation::Asid(_)
        | TlbiOperation::Vmid(_) => return Err(HarnessError::InvalidState),
    }
    if invalidation.failed() {
        Err(HarnessError::InvalidState)
    } else {
        Ok(())
    }
}

fn explicit_asid_tlbi(
    setup: TranslationSetup,
    lower_stage1: bool,
    scope: TlbiScope,
    asid: Asid,
) -> Result<(), HarnessError> {
    if setup.stage != TranslationStage::Stage1 || setup.asid != Some(asid) {
        return Err(HarnessError::InvalidState);
    }
    let completed = match (scope, lower_stage1) {
        (TlbiScope::InnerShareable, true) => {
            vmsa_test_architecture::barriers::invalidate_el1_stage1_asid(asid.0);
            true
        }
        (TlbiScope::InnerShareable, false) => {
            vmsa_test_architecture::barriers::invalidate_current_stage1_asid(asid.0)
        }
        (TlbiScope::Local, true) => {
            vmsa_test_architecture::barriers::invalidate_el1_stage1_asid_local(asid.0);
            true
        }
        (TlbiScope::Local, false) => {
            vmsa_test_architecture::barriers::invalidate_current_stage1_asid_local(asid.0)
        }
    };
    if completed {
        Ok(())
    } else {
        Err(HarnessError::InvalidState)
    }
}

fn explicit_local_tlbi(
    setup: TranslationSetup,
    lower_stage1: bool,
    operation: TlbiOperation,
) -> Result<(), HarnessError> {
    let identifier = match setup.stage {
        TranslationStage::Stage1 => setup.asid.map_or(0, |asid| asid.0),
        TranslationStage::Stage2 => setup.vmid.map_or(0, |vmid| vmid.0),
    };
    let invalidate_all = || match setup.stage {
        TranslationStage::Stage1 if lower_stage1 => {
            vmsa_test_architecture::barriers::invalidate_el1_stage1_all_local();
            true
        }
        TranslationStage::Stage1 => {
            vmsa_test_architecture::barriers::invalidate_current_stage1_all_local()
        }
        TranslationStage::Stage2 => {
            vmsa_test_architecture::barriers::invalidate_stage2_all_local();
            true
        }
    };
    let invalidate_address = |address| match setup.stage {
        TranslationStage::Stage1 if lower_stage1 => {
            vmsa_test_architecture::barriers::invalidate_el1_stage1_address_local(
                address, identifier,
            );
            true
        }
        TranslationStage::Stage1 => {
            vmsa_test_architecture::barriers::invalidate_current_stage1_address_local(
                address, identifier,
            )
        }
        TranslationStage::Stage2 => {
            vmsa_test_architecture::barriers::invalidate_stage2_address_local(address)
        }
    };
    let stride = setup.granule.bytes();
    match operation {
        TlbiOperation::All if invalidate_all() => Ok(()),
        TlbiOperation::All => Err(HarnessError::InvalidState),
        TlbiOperation::Address(address) => {
            if !address.is_multiple_of(stride) || !invalidate_address(address) {
                Err(HarnessError::InvalidState)
            } else {
                Ok(())
            }
        }
        TlbiOperation::Range { start, pages } => {
            if pages == 0 || !start.is_multiple_of(stride) {
                return Err(HarnessError::InvalidState);
            }
            let mut address = start;
            for index in 0..pages {
                if !invalidate_address(address) {
                    return Err(HarnessError::InvalidState);
                }
                if index + 1 != pages {
                    address = address
                        .checked_add(stride)
                        .ok_or(HarnessError::InvalidState)?;
                }
            }
            Ok(())
        }
        TlbiOperation::VirtualAddress(_)
        | TlbiOperation::IntermediatePhysicalAddress(_)
        | TlbiOperation::VirtualRange { .. }
        | TlbiOperation::IntermediatePhysicalRange { .. }
        | TlbiOperation::Asid(_)
        | TlbiOperation::Vmid(_) => Err(HarnessError::InvalidState),
    }
}

fn invalidation_address<F, G>(
    location: aarch64_vmsa::table::TableAccessLocation<F, G>,
    index: usize,
) -> Option<u64>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let cursor = location.cursor();
    let root_level = cursor.root_level();
    let path = cursor.path();
    let mut address = 0u64;
    for depth in 0..path.len() {
        let entry = path.entry(root_level, depth)?;
        address |= (entry.index() as u64)
            << aarch64_vmsa::table::TableGeometry::<F, G>::checked_level_shift(
                entry.parent_level(),
            )?;
    }
    address |= (index as u64)
        << aarch64_vmsa::table::TableGeometry::<F, G>::checked_level_shift(cursor.level())?;
    Some(address)
}

impl<F, G> aarch64_vmsa::mapper::MapperInvalidation<F, G> for ArchitecturalInvalidation
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn leaf_inserted(
        &mut self,
        location: aarch64_vmsa::table::TableAccessLocation<F, G>,
        index: usize,
        _: F::Raw,
        _: F::Raw,
    ) {
        if let Some(address) = invalidation_address(location, index) {
            self.invalidate_address(address);
        } else {
            self.invalidate_all();
        }
    }

    fn leaf_removed(
        &mut self,
        location: aarch64_vmsa::table::TableAccessLocation<F, G>,
        index: usize,
        _: F::Raw,
    ) {
        if let Some(address) = invalidation_address(location, index) {
            self.invalidate_address(address);
        } else {
            self.invalidate_all();
        }
    }

    fn table_descriptor_inserted(
        &mut self,
        location: aarch64_vmsa::table::TableAccessLocation<F, G>,
        index: usize,
        _: F::Raw,
        _: F::Raw,
    ) {
        if let Some(address) = invalidation_address(location, index) {
            self.invalidate_address(address);
        } else {
            self.invalidate_all();
        }
    }

    fn table_descriptor_removed(
        &mut self,
        location: aarch64_vmsa::table::TableAccessLocation<F, G>,
        index: usize,
        _: F::Raw,
    ) {
        if let Some(address) = invalidation_address(location, index) {
            self.invalidate_address(address);
        } else {
            self.invalidate_all();
        }
    }

    fn before_table_frame_reclaim(&mut self, _: TablePhysAddr<G>, _: TableAllocLayout) {
        self.invalidate_all();
    }

    fn synchronize(&mut self) {
        vmsa_test_architecture::barriers::dsb_ish();
        vmsa_test_architecture::barriers::isb();
    }
}

type InnerMapper<F, R, G> = Mapper<F, R, G, OffsetTableAccess, ArenaFrameProvider, Offline>;
pub(crate) type LiveTestMapper<F, R, G> = Mapper<
    F,
    R,
    G,
    OffsetTableAccess,
    ArenaFrameProvider,
    aarch64_vmsa::mapper::Live<ArchitecturalInvalidation>,
>;

pub(crate) type RecursiveLiveTestMapper<R> = Mapper<
    Vmsa64,
    R,
    Granule4KiB,
    RecursiveTableAccess<Vmsa64, Granule4KiB>,
    ArenaFrameProvider,
    aarch64_vmsa::mapper::Live<ArchitecturalInvalidation>,
>;

pub(crate) fn recursive_live_mapper<R>(
    memory: NonNull<TestMemory>,
    setup: TranslationSetup,
    recursive_index: usize,
    recursive_base: u64,
) -> Result<RecursiveLiveTestMapper<R>, HarnessError>
where
    R: TestRegimeFor<Granule4KiB>,
    Vmsa64: HasLayout<StageOf<R>, Granule4KiB>,
    LeafFieldsOf<Vmsa64, R, Granule4KiB>: Copy,
{
    if setup.format != TranslationFormat::Vmsa64
        || setup.granule != Granule::Size4KiB
        || setup.stage != TranslationStage::Stage1
    {
        return Err(HarnessError::InvalidState);
    }
    let root_level = Level::new(setup.start_level.ok_or(HarnessError::InvalidState)?.get());
    let child_level = root_level.next();
    if child_level == root_level {
        return Err(HarnessError::InvalidState);
    }
    let root_address =
        TablePhysAddr::new(PhysAddr(setup.root.get())).map_err(|_| HarnessError::Memory)?;
    let transition = TableTransition::new(
        TableShape::<Vmsa64, Granule4KiB>::root(root_level),
        TableShape::<Vmsa64, Granule4KiB>::root(child_level),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    type Layout<R> = <Vmsa64 as HasLayout<StageOf<R>, Granule4KiB>>::Layout;
    let descriptor =
        <Layout<R> as DescriptorLayout<Vmsa64, StageOf<R>, Granule4KiB>>::table_descriptor(
            PhysAddr(setup.root.get()),
            transition,
            <R as TestRegimeFor<Granule4KiB>>::raw_table()?,
        )
        .map_err(|_| HarnessError::InvalidState)?
            | (1 << 10);
    let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
    let root_virtual = setup.root.get().wrapping_add(offset) as *mut u64;
    if root_virtual.is_null() || recursive_index >= 512 {
        return Err(HarnessError::InvalidState);
    }
    // SAFETY: The installed root is an arena-owned 4 KiB VMSA64 table, and the
    // checked index selects one of its 512 u64 descriptors.
    unsafe { Vmsa64::write_descriptor(root_virtual.add(recursive_index), descriptor) };
    vmsa_test_architecture::barriers::dsb_ishst();
    if !vmsa_test_architecture::barriers::invalidate_current_stage1_all() {
        return Err(HarnessError::InvalidState);
    }
    // SAFETY: The descriptor above recursively maps this live root at the
    // supplied base; the constructor validates the repeated index geometry.
    let access = unsafe {
        RecursiveTableAccess::new(
            recursive_index,
            VirtAddr(recursive_base),
            root_address,
            root_level,
        )
    }
    .map_err(|_| HarnessError::InvalidState)?;
    let root = RootTable::new(
        root_address,
        root_level,
        setup.input_bits.get(),
        setup.output_bits.get(),
    );
    Mapper::new_live(
        root,
        access,
        ArenaFrameProvider::new(memory),
        ArchitecturalInvalidation::new(
            TranslationStage::Stage1,
            setup.asid.map_or(0, |asid| asid.0),
            false,
        ),
    )
    .map_err(|_| HarnessError::InvalidState)
}

pub(crate) fn live_mapper<F, R, G>(
    memory: NonNull<TestMemory>,
    setup: TranslationSetup,
    lower_stage1: bool,
) -> Result<LiveTestMapper<F, R, G>, HarnessError>
where
    F: TestFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TestGranule,
{
    if setup.format != F::FORMAT || setup.granule != G::GRANULE {
        return Err(HarnessError::InvalidState);
    }
    let start_level = setup.start_level.ok_or(HarnessError::InvalidState)?;
    let root_address =
        TablePhysAddr::new(PhysAddr(setup.root.get())).map_err(|_| HarnessError::Memory)?;
    // SAFETY: The installed translation root and all descendant tables are
    // allocated from the live per-test arena with a constant physical offset.
    let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
    // SAFETY: The arena offset maps every table frame owned by this session.
    let access = unsafe { OffsetTableAccess::new(VirtAddr(offset)) };
    let root = RootTable::new(
        root_address,
        Level::new(start_level.get()),
        setup.input_bits.get(),
        setup.output_bits.get(),
    );
    Mapper::new_live(
        root,
        access,
        ArenaFrameProvider::new(memory),
        ArchitecturalInvalidation::new(
            setup.stage,
            match setup.stage {
                TranslationStage::Stage1 => setup.asid.map_or(0, |asid| asid.0),
                TranslationStage::Stage2 => setup.vmid.map_or(0, |vmid| vmid.0),
            },
            lower_stage1,
        ),
    )
    .map_err(|_| HarnessError::InvalidState)
}

pub(crate) fn replace_live_mapping<F, R, G>(
    mapper: &mut LiveTestMapper<F, R, G>,
    input: u64,
    output: Option<u64>,
    replacement_fields: LeafFieldsOf<F, R, G>,
    table_fields: TableFieldsOf<F, R, G>,
) -> Result<MappingInspection, HarnessError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TestGranule,
    LeafFieldsOf<F, R, G>: Copy,
    TableFieldsOf<F, R, G>: Copy,
{
    let removed = mapper
        .unmap(WalkInputAddr::new(input))
        .map_err(|_| HarnessError::InvalidState)?;
    let old_output = removed.old().output_base();
    let old_level = removed.old().level();
    let old_fields = *removed.old().fields();
    let replacement_output = PhysAddr(output.unwrap_or(old_output.0));

    if mapper
        .map_leaf(
            WalkInputAddr::new(input),
            replacement_output,
            old_level,
            replacement_fields,
            table_fields,
        )
        .is_err()
    {
        if mapper
            .map_leaf(
                WalkInputAddr::new(input),
                old_output,
                old_level,
                old_fields,
                table_fields,
            )
            .is_err()
        {
            return Err(HarnessError::Cleanup);
        }
        return Err(HarnessError::InvalidState);
    }

    Ok(MappingInspection {
        output: replacement_output.0,
        level: LookupLevel::new(old_level.as_i8())
            .expect("mapper returned an architectural lookup level"),
    })
}

pub(crate) fn replace_live_d128_stage1_mapping<R>(
    mapper: &mut LiveTestMapper<Vmsa128, R, Granule4KiB>,
    input: u64,
    output: Option<u64>,
    permissions: D128MappingPermissions,
) -> Result<MappingInspection, HarnessError>
where
    R: TranslationRegime,
    R::WalkProfile: TranslationWalkProfile<Stage = Stage1>,
    Vmsa128: HasLayout<Stage1, Granule4KiB>,
    <Vmsa128 as HasLayout<Stage1, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa128,
            Stage1,
            Granule4KiB,
            LeafFields = RawVmsa128Stage1LeafAttrs,
            TableFields = RawVmsa128Stage1TableAttrs,
        >,
{
    let zero = FourBit::new(0).map_err(|_| HarnessError::InvalidState)?;
    let permission = FourBit::new(match permissions {
        D128MappingPermissions::ReadExecute => 0,
        D128MappingPermissions::ReadWrite => 1,
    })
    .map_err(|_| HarnessError::InvalidState)?;
    replace_live_mapping(
        mapper,
        input,
        output,
        RawVmsa128Stage1LeafAttrs {
            attr_index: zero,
            bbm_nt: false,
            not_dirty: Stage1NotDirty::new(false),
            shareability: RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
            access_flag: true,
            alias_bit: false,
            contiguous: false,
            guarded: false,
            protected: false,
            permissions: PermissionIndices {
                pi: permission,
                po: permission,
            },
            ns: false,
            software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
        },
        RawVmsa128Stage1TableAttrs {
            access_flag: true,
            ..RawVmsa128Stage1TableAttrs::default()
        },
    )
}

fn d128_stage2_fields(
    attributes: MappingAttributes,
) -> Result<(RawVmsa128Stage2LeafAttrs, RawVmsa128Stage2TableAttrs), HarnessError> {
    if attributes.user_accessible {
        return Err(HarnessError::InvalidState);
    }
    // The adapter installs matching S2PIR_EL2 entries: 0=RW, 1=RO,
    // 2=RO+privileged/unprivileged execute, 3=RW+both execute.
    let index = match (attributes.writable, attributes.executable) {
        (true, false) => 0,
        (false, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    };
    let permission = FourBit::new(index).map_err(|_| HarnessError::InvalidState)?;
    Ok((
        RawVmsa128Stage2LeafAttrs {
            mem_attr: FourBit::new(0xf).map_err(|_| HarnessError::InvalidState)?,
            bbm_nt: false,
            dirty: Stage2Dirty::new(attributes.writable),
            shareability: RawShareability::from_bits(0b11)
                .map_err(|_| HarnessError::InvalidState)?,
            access_flag: true,
            force_no_execute: false,
            contiguous: false,
            assured_only: false,
            permissions: PermissionIndices {
                pi: permission,
                po: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
            },
            ns: false,
            software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
        },
        RawVmsa128Stage2TableAttrs {
            access_flag: true,
            ..RawVmsa128Stage2TableAttrs::default()
        },
    ))
}

pub(crate) fn replace_live_d128_stage2_mapping<R>(
    mapper: &mut LiveTestMapper<Vmsa128, R, Granule4KiB>,
    input: u64,
    output: Option<u64>,
    attributes: MappingAttributes,
) -> Result<MappingInspection, HarnessError>
where
    R: TranslationRegime,
    R::WalkProfile: TranslationWalkProfile<Stage = Stage2>,
    Vmsa128: HasLayout<Stage2, Granule4KiB>,
    <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa128,
            Stage2,
            Granule4KiB,
            LeafFields = RawVmsa128Stage2LeafAttrs,
            TableFields = RawVmsa128Stage2TableAttrs,
        >,
{
    let (leaf, table) = d128_stage2_fields(attributes)?;
    replace_live_mapping(mapper, input, output, leaf, table)
}

#[doc(hidden)]
pub fn prepare_lower_runtime<R>(
    memory: &mut TestMemory,
    setup: TranslationSetup,
    entry: u64,
    stack_top: u64,
) -> Result<(), HarnessError>
where
    R: TestRegimeFor<Granule4KiB> + TestRegimeFor<Granule16KiB> + TestRegimeFor<Granule64KiB>,
    Vmsa64: HasLayout<StageOf<R>, Granule4KiB>,
    Vmsa64: HasLayout<StageOf<R>, Granule16KiB>,
    Vmsa64: HasLayout<StageOf<R>, Granule64KiB>,
    Vmsa64Lpa2: HasLayout<StageOf<R>, Granule4KiB>,
    Vmsa64Lpa2: HasLayout<StageOf<R>, Granule16KiB>,
    Vmsa64Lpa2: HasLayout<StageOf<R>, Granule64KiB>,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa64Lpa2,
            StageOf<R>,
            Granule4KiB,
            LeafFields = LeafFieldsOf<Vmsa64, R, Granule4KiB>,
            TableFields = TableFieldsOf<Vmsa64, R, Granule4KiB>,
        >,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, Granule16KiB>>::Layout: DescriptorLayout<
            Vmsa64Lpa2,
            StageOf<R>,
            Granule16KiB,
            LeafFields = LeafFieldsOf<Vmsa64, R, Granule16KiB>,
            TableFields = TableFieldsOf<Vmsa64, R, Granule16KiB>,
        >,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, Granule64KiB>>::Layout: DescriptorLayout<
            Vmsa64Lpa2,
            StageOf<R>,
            Granule64KiB,
            LeafFields = LeafFieldsOf<Vmsa64, R, Granule64KiB>,
            TableFields = TableFieldsOf<Vmsa64, R, Granule64KiB>,
        >,
    LeafFieldsOf<Vmsa64, R, Granule4KiB>: Copy + PartialEq,
    LeafFieldsOf<Vmsa64, R, Granule16KiB>: Copy + PartialEq,
    LeafFieldsOf<Vmsa64, R, Granule64KiB>: Copy + PartialEq,
{
    match (setup.format, setup.granule) {
        (TranslationFormat::Vmsa64, Granule::Size4KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64, Granule4KiB>(memory, setup, entry, stack_top)
        }
        (TranslationFormat::Vmsa64, Granule::Size16KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64, Granule16KiB>(memory, setup, entry, stack_top)
        }
        (TranslationFormat::Vmsa64, Granule::Size64KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64, Granule64KiB>(memory, setup, entry, stack_top)
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size4KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule4KiB>(memory, setup, entry, stack_top)
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size16KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule16KiB>(
                memory, setup, entry, stack_top,
            )
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size64KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule64KiB>(
                memory, setup, entry, stack_top,
            )
        }
        _ => Err(HarnessError::InvalidState),
    }
}

fn prepare_lower_runtime_for<R, F, G>(
    memory: &mut TestMemory,
    setup: TranslationSetup,
    entry: u64,
    stack_top: u64,
) -> Result<(), HarnessError>
where
    R: TestRegimeFor<G>,
    G: TestGranule,
    Vmsa64: HasLayout<StageOf<R>, G>,
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    <F as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            F,
            StageOf<R>,
            G,
            LeafFields = LeafFieldsOf<Vmsa64, R, G>,
            TableFields = TableFieldsOf<Vmsa64, R, G>,
        >,
    LeafFieldsOf<Vmsa64, R, G>: Copy + PartialEq,
{
    if setup.granule != G::GRANULE || entry == 0 || stack_top < G::SIZE {
        return Err(HarnessError::InvalidState);
    }
    let start_level = setup.start_level.ok_or(HarnessError::InvalidState)?;
    let root_address =
        TablePhysAddr::new(PhysAddr(setup.root.get())).map_err(|_| HarnessError::Memory)?;
    let memory = NonNull::from(memory);
    // SAFETY: The adapter supplies the same reserved contiguous arena used by
    // the frame provider and keeps it live through lower translation restore.
    let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
    // SAFETY: The offset maps every adapter-owned table frame in the arena.
    let access = unsafe { OffsetTableAccess::new(VirtAddr(offset)) };
    let root = RootTable::new(
        root_address,
        Level::new(start_level.get()),
        setup.input_bits.get(),
        setup.output_bits.get(),
    );
    let mut mapper = Mapper::<F, R, G, _, _, Offline>::new_offline(
        root,
        access,
        ArenaFrameProvider::new(memory),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    const CODE_WINDOW: u64 = 512 * 1024;
    let code_fields = R::raw_leaf(MappingAttributes {
        writable: false,
        executable: true,
        user_accessible: true,
    })?;
    let data_fields = R::raw_leaf(MappingAttributes {
        writable: true,
        executable: false,
        user_accessible: true,
    })?;
    let table_fields = R::raw_table()?;
    let code_windows = [
        entry & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::vector_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::runtime_code_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::transition::runtime_code_address() & !(CODE_WINDOW - 1),
    ];
    let stack_page = G::align_down(stack_top - 1);
    let state_pages = [
        G::align_down(vmsa_test_architecture::exception::runtime_state_address()),
        G::align_down(vmsa_test_architecture::transition::runtime_state_address()),
    ];
    let is_state_page = |address: u64| state_pages.contains(&address);
    let is_code_page = |address: u64| {
        code_windows
            .iter()
            .any(|start| (*start..*start + CODE_WINDOW).contains(&address))
    };
    let arena_start = G::align_down(unsafe { memory.as_ref() }.physical_base());
    let arena_end = unsafe { memory.as_ref() }
        .physical_base()
        .checked_add(unsafe { memory.as_ref() }.byte_len() as u64)
        .ok_or(HarnessError::Memory)?;
    let arena_last = G::align_down(arena_end.saturating_sub(1));
    macro_rules! ensure_data_page {
        ($address:expr) => {{
            let address = $address;
            if let Some(mapping) = mapper
                .translate(WalkInputAddr::new(address))
                .map_err(|_| HarnessError::InvalidState)?
            {
                if mapping.output().0 != address
                    || mapping.level() != Level::L3
                    || *mapping.fields() != data_fields
                {
                    return Err(HarnessError::InvalidState);
                }
            } else {
                mapper
                    .map_leaf(
                        WalkInputAddr::new(address),
                        PhysAddr(address),
                        Level::L3,
                        data_fields,
                        table_fields,
                    )
                    .map_err(|_| HarnessError::InvalidState)?;
            }
        }};
    }
    for index in 0..code_windows.len() {
        if code_windows[..index].contains(&code_windows[index]) {
            continue;
        }
        let mut address = code_windows[index];
        let end = address
            .checked_add(CODE_WINDOW)
            .ok_or(HarnessError::Memory)?;
        while address < end {
            if address != stack_page && !is_state_page(address) {
                if let Some(mapping) = mapper
                    .translate(WalkInputAddr::new(address))
                    .map_err(|_| HarnessError::InvalidState)?
                {
                    if mapping.output().0 != address
                        || mapping.level() != Level::L3
                        || *mapping.fields() != code_fields
                    {
                        return Err(HarnessError::InvalidState);
                    }
                } else {
                    mapper
                        .map_leaf(
                            WalkInputAddr::new(address),
                            PhysAddr(address),
                            Level::L3,
                            code_fields,
                            table_fields,
                        )
                        .map_err(|_| HarnessError::InvalidState)?;
                }
            }
            address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
    }
    if is_code_page(stack_page) || is_state_page(stack_page) {
        return Err(HarnessError::InvalidState);
    }
    ensure_data_page!(stack_page);
    for index in 0..state_pages.len() {
        let page = state_pages[index];
        if state_pages[..index].contains(&page) {
            continue;
        }
        ensure_data_page!(page);
    }
    let mut address = arena_start;
    while address <= arena_last {
        if !is_code_page(address) && address != stack_page && !is_state_page(address) {
            ensure_data_page!(address);
        }
        address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
    }
    let uart_page = G::align_down(0x1c0a_0000);
    if !is_code_page(uart_page)
        && !(arena_start..=arena_last).contains(&uart_page)
        && uart_page != stack_page
        && !is_state_page(uart_page)
    {
        ensure_data_page!(uart_page);
    }
    Ok(())
}

#[doc(hidden)]
pub fn prepare_lower_runtime_d128<R>(
    memory: &mut TestMemory,
    setup: TranslationSetup,
    entry: u64,
    stack_top: u64,
    lower_runtime_state: u64,
) -> Result<(), HarnessError>
where
    R: TranslationRegime,
    Vmsa128: HasLayout<StageOf<R>, Granule4KiB>,
    <Vmsa128 as HasLayout<StageOf<R>, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa128,
            StageOf<R>,
            Granule4KiB,
            LeafFields = RawVmsa128Stage1LeafAttrs,
            TableFields = RawVmsa128Stage1TableAttrs,
        >,
{
    if setup.format != TranslationFormat::Vmsa128
        || setup.granule != Granule::Size4KiB
        || entry == 0
        || stack_top < 4096
        || lower_runtime_state == 0
    {
        return Err(HarnessError::InvalidState);
    }
    let start_level = setup.start_level.ok_or(HarnessError::InvalidState)?;
    let root_address =
        TablePhysAddr::new(PhysAddr(setup.root.get())).map_err(|_| HarnessError::Memory)?;
    let memory = NonNull::from(memory);
    let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
    let access = unsafe { OffsetTableAccess::new(VirtAddr(offset)) };
    let root = RootTable::new(
        root_address,
        Level::new(start_level.get()),
        setup.input_bits.get(),
        setup.output_bits.get(),
    );
    let mut mapper = Mapper::<Vmsa128, R, Granule4KiB, _, _, Offline>::new_offline(
        root,
        access,
        ArenaFrameProvider::new(memory),
    )
    .map_err(|_| HarnessError::InvalidState)?;
    let zero = FourBit::new(0).map_err(|_| HarnessError::InvalidState)?;
    let code_fields = RawVmsa128Stage1LeafAttrs {
        attr_index: zero,
        bbm_nt: false,
        not_dirty: Stage1NotDirty::new(false),
        shareability: RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?,
        access_flag: true,
        alias_bit: false,
        contiguous: false,
        guarded: false,
        protected: false,
        permissions: PermissionIndices { pi: zero, po: zero },
        ns: false,
        software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
    };
    let one = FourBit::new(1).map_err(|_| HarnessError::InvalidState)?;
    let data_fields = RawVmsa128Stage1LeafAttrs {
        permissions: PermissionIndices { pi: one, po: one },
        ..code_fields
    };
    let table_fields = RawVmsa128Stage1TableAttrs {
        access_flag: true,
        ..RawVmsa128Stage1TableAttrs::default()
    };
    const PAGE_SIZE: u64 = 4096;
    const CODE_WINDOW: u64 = 512 * 1024;
    const STATE_WINDOW: u64 = PAGE_SIZE;
    let code_windows = [
        entry & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::vector_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::runtime_code_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::transition::runtime_code_address() & !(CODE_WINDOW - 1),
    ];
    let stack_page = (stack_top - 1) & !(PAGE_SIZE - 1);
    let state_windows = [
        vmsa_test_architecture::exception::runtime_state_address() & !(STATE_WINDOW - 1),
        vmsa_test_architecture::transition::runtime_state_address() & !(STATE_WINDOW - 1),
        lower_runtime_state & !(STATE_WINDOW - 1),
    ];
    let is_state_page = |address: u64| {
        state_windows
            .iter()
            .any(|start| (*start..*start + STATE_WINDOW).contains(&address))
    };
    let is_code_page = |address: u64| {
        code_windows
            .iter()
            .any(|start| (*start..*start + CODE_WINDOW).contains(&address))
    };
    let arena_start = unsafe { memory.as_ref() }.physical_base() & !(PAGE_SIZE - 1);
    let arena_end = unsafe { memory.as_ref() }
        .physical_base()
        .checked_add(unsafe { memory.as_ref() }.byte_len() as u64)
        .ok_or(HarnessError::Memory)?;
    let arena_last = arena_end.saturating_sub(1) & !(PAGE_SIZE - 1);
    for index in 0..code_windows.len() {
        if code_windows[..index].contains(&code_windows[index]) {
            continue;
        }
        let mut address = code_windows[index];
        let end = address
            .checked_add(CODE_WINDOW)
            .ok_or(HarnessError::Memory)?;
        while address < end {
            if address != stack_page && !is_state_page(address) {
                mapper
                    .map_leaf(
                        WalkInputAddr::new(address),
                        PhysAddr(address),
                        Level::L3,
                        code_fields,
                        table_fields,
                    )
                    .map_err(|_| HarnessError::InvalidState)?;
            }
            address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
        }
    }
    if !is_state_page(stack_page) {
        mapper
            .map_leaf(
                WalkInputAddr::new(stack_page),
                PhysAddr(stack_page),
                Level::L3,
                data_fields,
                table_fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
    }
    for index in 0..state_windows.len() {
        if state_windows[..index].contains(&state_windows[index]) {
            continue;
        }
        let mut page = state_windows[index];
        let end = page.checked_add(STATE_WINDOW).ok_or(HarnessError::Memory)?;
        while page < end {
            mapper
                .map_leaf(
                    WalkInputAddr::new(page),
                    PhysAddr(page),
                    Level::L3,
                    data_fields,
                    table_fields,
                )
                .map_err(|_| HarnessError::InvalidState)?;
            page = page.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
        }
    }
    let mut address = arena_start;
    while address <= arena_last {
        if !is_code_page(address) && address != stack_page && !is_state_page(address) {
            mapper
                .map_leaf(
                    WalkInputAddr::new(address),
                    PhysAddr(address),
                    Level::L3,
                    data_fields,
                    table_fields,
                )
                .map_err(|_| HarnessError::InvalidState)?;
        }
        address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
    }
    const UART_PAGE: u64 = 0x1c0a_0000;
    if !is_code_page(UART_PAGE)
        && !(arena_start..=arena_last).contains(&UART_PAGE)
        && UART_PAGE != stack_page
        && !is_state_page(UART_PAGE)
    {
        mapper
            .map_leaf(
                WalkInputAddr::new(UART_PAGE),
                PhysAddr(UART_PAGE),
                Level::L3,
                data_fields,
                table_fields,
            )
            .map_err(|_| HarnessError::InvalidState)?;
    }
    Ok(())
}

pub struct TestMapper<
    R: TranslationRegime,
    G: TestGranule = Granule4KiB,
    F: DescriptorFormat = Vmsa64,
> where
    F: HasLayout<StageOf<R>, G>,
{
    inner: InnerMapper<F, R, G>,
    _regime: PhantomData<(F, R, G)>,
}

/// Explicit negative-test surface for replacing a descriptor in an offline,
/// caller-owned table. It exposes raw descriptor bits but never table pointers,
/// frame allocation, installed register state, or cleanup operations.
pub struct IsolatedMalformedTable<'a, R, G, F>
where
    R: TranslationRegime,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
{
    mapper: &'a mut TestMapper<R, G, F>,
}

impl<R, G, F> TestMapper<R, G, F>
where
    R: TranslationRegime,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
{
    pub fn map_semantic_leaf<Codec, Cfg>(
        &mut self,
        config: &Cfg,
        input: u64,
        output: u64,
        level: LookupLevel,
        leaf: Codec::SemanticLeaf,
        table: Codec::SemanticTable,
    ) -> Result<(), HarnessError>
    where
        Codec: aarch64_vmsa::attrs::AttributeCodec<
                F,
                R,
                G,
                Cfg,
                RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
                RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        aarch64_vmsa::mapper::map_semantic_leaf::<F, R, G, _, _, _, Codec, Cfg>(
            &mut self.inner,
            config,
            WalkInputAddr::new(input),
            PhysAddr(output),
            Level::new(level.get()),
            leaf,
            table,
        )
        .map(|_| ())
        .map_err(|error| match error {
            aarch64_vmsa::mapper::SemanticMapperError::Attribute(error) => {
                HarnessError::Attribute(normalize_attribute_error(error))
            }
            aarch64_vmsa::mapper::SemanticMapperError::Mapper(_) => HarnessError::InvalidState,
        })
    }

    pub fn isolated_malformed_table(&mut self) -> IsolatedMalformedTable<'_, R, G, F> {
        IsolatedMalformedTable { mapper: self }
    }

    pub fn inspect_semantic_leaf<Codec, Cfg>(
        &mut self,
        input: u64,
        config: &Cfg,
    ) -> Result<Option<Codec::SemanticLeaf>, HarnessError>
    where
        Codec: aarch64_vmsa::attrs::AttributeCodec<
                F,
                R,
                G,
                Cfg,
                RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
                RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        let mapping = self
            .inner
            .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
            .map_err(|_| HarnessError::InvalidState)?;
        mapping
            .map(|mapping| {
                aarch64_vmsa::mapper::decode_semantic_leaf::<F, R, G, Codec, Cfg>(
                    config,
                    mapping.level(),
                    *mapping.fields(),
                )
                .map_err(|error| HarnessError::Attribute(normalize_attribute_error(error)))
            })
            .transpose()
    }
}

impl<R, G, F> IsolatedMalformedTable<'_, R, G, F>
where
    R: TranslationRegime,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
{
    pub fn replace_terminal_descriptor(
        &mut self,
        input: u64,
        replacement: DescriptorBits,
    ) -> Result<DescriptorBits, HarnessError> {
        let root = self.mapper.inner.root();
        let (location, entry_index, original) = {
            let walker = Walker::<F, R::WalkProfile, G, _>::new(
                root.addr(),
                root.level(),
                self.mapper.inner.access(),
            )
            .map_err(|_| HarnessError::InvalidState)?;
            match walker
                .walk(WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
            {
                aarch64_vmsa::translation::walk::WalkOutcome::Leaf(leaf) => {
                    (leaf.location(), leaf.entry_index(), leaf.raw())
                }
                aarch64_vmsa::translation::walk::WalkOutcome::Invalid(_) => {
                    return Err(HarnessError::InvalidState);
                }
            }
        };
        let replacement = F::raw_descriptor(replacement).ok_or(HarnessError::InvalidState)?;
        let mut table = self
            .mapper
            .inner
            .access_mut()
            .table_at_mut(location)
            .map_err(|_| HarnessError::InvalidState)?;
        table
            .write(entry_index, replacement)
            .map_err(|_| HarnessError::InvalidState)?;
        Ok(F::descriptor_bits(original))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingInspection {
    pub output: u64,
    pub level: LookupLevel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorBits {
    pub low: u64,
    pub high: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkDescriptorKind {
    Invalid,
    Table,
    Block,
    Page,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkDescriptorInspection {
    pub level: LookupLevel,
    pub entry_index: usize,
    pub kind: WalkDescriptorKind,
    pub raw: Option<DescriptorBits>,
    pub next_table: Option<u64>,
    pub output: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkInspection {
    steps: [Option<WalkDescriptorInspection>; 6],
    length: u8,
}

impl WalkInspection {
    pub fn steps(&self) -> &[Option<WalkDescriptorInspection>] {
        &self.steps[..usize::from(self.length)]
    }

    pub const fn leaf(&self) -> Option<WalkDescriptorInspection> {
        if self.length == 0 {
            None
        } else {
            self.steps[self.length as usize - 1]
        }
    }

    fn push(&mut self, step: WalkDescriptorInspection) -> Result<(), HarnessError> {
        let index = usize::from(self.length);
        let slot = self
            .steps
            .get_mut(index)
            .ok_or(HarnessError::InvalidState)?;
        *slot = Some(step);
        self.length = self
            .length
            .checked_add(1)
            .ok_or(HarnessError::InvalidState)?;
        Ok(())
    }
}

pub(crate) fn inspect_walk_with_access<R, G, F, A>(
    root: RootTable<F, G>,
    access: &A,
    input: u64,
) -> Result<WalkInspection, HarnessError>
where
    R: TranslationRegime,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
    A: TableAccess<F, G>,
{
    let walker = Walker::<F, R::WalkProfile, G, _>::new(root.addr(), root.level(), access)
        .map_err(|_| HarnessError::InvalidState)?;
    let mut cursor = walker
        .cursor(WalkInputAddr::new(input))
        .map_err(|_| HarnessError::InvalidState)?;
    let mut inspection = WalkInspection {
        steps: [None; 6],
        length: 0,
    };
    loop {
        match walker
            .step(cursor)
            .map_err(|_| HarnessError::InvalidState)?
        {
            WalkStep::Invalid(invalid) => {
                inspection.push(WalkDescriptorInspection {
                    level: LookupLevel::new(invalid.level().as_i8())
                        .ok_or(HarnessError::InvalidState)?,
                    entry_index: invalid.entry_index(),
                    kind: WalkDescriptorKind::Invalid,
                    raw: None,
                    next_table: None,
                    output: None,
                })?;
                return Ok(inspection);
            }
            WalkStep::Leaf(leaf) => {
                let kind = match leaf.kind() {
                    aarch64_vmsa::translation::walk::WalkLeafKind::Block => {
                        WalkDescriptorKind::Block
                    }
                    aarch64_vmsa::translation::walk::WalkLeafKind::Page => WalkDescriptorKind::Page,
                };
                inspection.push(WalkDescriptorInspection {
                    level: LookupLevel::new(leaf.level().as_i8())
                        .ok_or(HarnessError::InvalidState)?,
                    entry_index: leaf.entry_index(),
                    kind,
                    raw: Some(F::descriptor_bits(leaf.raw())),
                    next_table: None,
                    output: Some(leaf.output().0),
                })?;
                return Ok(inspection);
            }
            WalkStep::Table(table) => {
                inspection.push(WalkDescriptorInspection {
                    level: LookupLevel::new(table.level().as_i8())
                        .ok_or(HarnessError::InvalidState)?,
                    entry_index: table.entry_index(),
                    kind: WalkDescriptorKind::Table,
                    raw: Some(F::descriptor_bits(table.raw())),
                    next_table: Some(table.next().raw()),
                    output: None,
                })?;
                cursor = table.next_cursor();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapRangeResult {
    pub mappings_created: u64,
    pub bytes_mapped: u64,
    pub tables_allocated: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnmapResult {
    pub mapping: MappingInspection,
    pub tables_freed: u8,
    pub root_now_empty: bool,
}

impl<R: TranslationRegime, G: TestGranule, F: DescriptorFormat> TestMapper<R, G, F>
where
    F: HasLayout<StageOf<R>, G>,
{
    pub(crate) fn new(
        memory: NonNull<TestMemory>,
        root: &crate::RootTableMemory,
        start_level: Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<Self, HarnessError> {
        let root_address =
            TablePhysAddr::new(PhysAddr(root.phys_addr())).map_err(|_| HarnessError::Memory)?;
        // SAFETY: TestMemory guarantees a constant physical-to-virtual offset.
        let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
        // SAFETY: The offset maps every arena physical address to its reserved VA.
        let access = unsafe { OffsetTableAccess::new(VirtAddr(offset)) };
        let root = RootTable::new(root_address, start_level, input_bits, output_bits);
        let inner = Mapper::new_offline(root, access, ArenaFrameProvider::new(memory))
            .map_err(|_| HarnessError::InvalidState)?;
        Ok(Self {
            inner,
            _regime: PhantomData,
        })
    }

    pub fn translate(&self, input: u64) -> Result<Option<MappingInspection>, HarnessError> {
        self.inner
            .translate(WalkInputAddr::new(input))
            .map(|mapping| {
                mapping.map(|mapping| MappingInspection {
                    output: mapping.output().0,
                    level: LookupLevel::new(mapping.level().as_i8())
                        .expect("a mapper result always has an architectural lookup level"),
                })
            })
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn inspect_walk(&self, input: u64) -> Result<WalkInspection, HarnessError>
    where
        F: TestFormat + HasLayout<StageOf<R>, G>,
    {
        inspect_walk_with_access::<R, G, F, _>(self.inner.root(), self.inner.access(), input)
    }
}

impl<R, G, F> TestMapper<R, G, F>
where
    R: TestRegimeFor<G>,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
    Vmsa64: HasLayout<StageOf<R>, G>,
    <F as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            F,
            StageOf<R>,
            G,
            LeafFields = LeafFieldsOf<Vmsa64, R, G>,
            TableFields = TableFieldsOf<Vmsa64, R, G>,
        >,
    LeafFieldsOf<Vmsa64, R, G>: Copy,
{
    pub(crate) fn prepare_current_runtime(
        &mut self,
        entry: u64,
        payload_data: [u64; 2],
        sandbox_regions: &[(u64, u64)],
    ) -> Result<(), HarnessError> {
        let leaf_level = LookupLevel::new(3).ok_or(HarnessError::InvalidState)?;
        let stack = vmsa_test_architecture::registers::stack_pointer() & !(G::SIZE - 1);
        let stack_start = stack.saturating_sub(15 * G::SIZE);
        let stack_end = stack.saturating_add(16 * G::SIZE);
        let code_regions = [
            entry & !0x7_ffff,
            vmsa_test_architecture::exception::vector_address() & !0x7_ffff,
            vmsa_test_architecture::exception::recovery_vector_address() & !0x7_ffff,
        ];
        let data_pages = [
            payload_data[0] & !(G::SIZE - 1),
            vmsa_test_architecture::exception::runtime_state_address() & !(G::SIZE - 1),
            vmsa_test_architecture::transition::runtime_state_address() & !(G::SIZE - 1),
            payload_data[1] & !(G::SIZE - 1),
            0x1c09_0000 & !(G::SIZE - 1),
            0x1c0a_0000 & !(G::SIZE - 1),
        ];
        for index in 0..code_regions.len() {
            let region = code_regions[index];
            if code_regions[..index].contains(&region) {
                continue;
            }
            let end = region.checked_add(0x8_0000).ok_or(HarnessError::Memory)?;
            let mut address = region;
            while address < end {
                let sandbox_data = sandbox_regions.iter().any(|(input, _)| *input == address);
                if !(stack_start..stack_end).contains(&address)
                    && !data_pages.contains(&address)
                    && !sandbox_data
                {
                    self.map_attributes_leaf(
                        address,
                        address,
                        leaf_level,
                        MappingAttributes {
                            writable: false,
                            executable: true,
                            user_accessible: false,
                        },
                    )?;
                }
                address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        let mut address = stack_start;
        while address < stack_end {
            self.map_attributes_leaf(address, address, leaf_level, MappingAttributes::READ_WRITE)?;
            address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
        for index in 0..data_pages.len() {
            let address = data_pages[index];
            if data_pages[..index].contains(&address) {
                continue;
            }
            if sandbox_regions.iter().any(|(input, _)| *input == address) {
                continue;
            }
            let contains_code = code_regions
                .iter()
                .any(|region| (*region..*region + 0x8_0000).contains(&address));
            self.map_attributes_leaf(
                address,
                address,
                leaf_level,
                MappingAttributes {
                    writable: true,
                    executable: contains_code,
                    user_accessible: false,
                },
            )?;
        }
        for &(input, output) in sandbox_regions {
            if input & (G::SIZE - 1) != 0 || output & (G::SIZE - 1) != 0 {
                return Err(HarnessError::InvalidState);
            }
            if let Some(mapping) = self
                .inner
                .translate(WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
            {
                if mapping.output().0 != output || mapping.level() != Level::L3 {
                    return Err(HarnessError::InvalidState);
                }
            } else {
                self.map_attributes_leaf(input, output, leaf_level, MappingAttributes::READ_WRITE)?;
            }
        }
        Ok(())
    }

    /// Makes every arena-owned table frame reachable through the candidate
    /// translation, including tables allocated while establishing this mapping.
    ///
    /// This is the table-access portion of transition preparation. The method
    /// reaches a bounded fixed point because each pass consumes an allocation
    /// already owned by the scoped arena and the arena has a fixed allocation
    /// capacity.
    pub fn prepare_transition_table_access(&mut self) -> Result<(), HarnessError> {
        let memory = self.inner.frames().memory();
        let mut index = 0usize;
        while index < unsafe { memory.as_ref() }.allocation_count() {
            let region = unsafe { memory.as_ref() }.table_allocation_region(index);
            index = index.checked_add(1).ok_or(HarnessError::Memory)?;
            let Some(region) = region else {
                continue;
            };
            if region.virtual_address & (G::SIZE - 1) != 0
                || region.physical_address & (G::SIZE - 1) != 0
                || region.bytes == 0
                || region.bytes as u64 & (G::SIZE - 1) != 0
            {
                return Err(HarnessError::InvalidState);
            }
            let end = region
                .virtual_address
                .checked_add(region.bytes as u64)
                .ok_or(HarnessError::Memory)?;
            let mut virtual_address = region.virtual_address;
            let mut physical_address = region.physical_address;
            while virtual_address < end {
                if let Some(mapping) = self
                    .inner
                    .translate(WalkInputAddr::new(virtual_address))
                    .map_err(|_| HarnessError::InvalidState)?
                {
                    if mapping.output().0 != physical_address || mapping.level() != Level::L3 {
                        return Err(HarnessError::InvalidState);
                    }
                } else {
                    self.inner
                        .map_leaf(
                            WalkInputAddr::new(virtual_address),
                            PhysAddr(physical_address),
                            Level::L3,
                            R::raw_leaf(MappingAttributes::READ_WRITE)?,
                            R::raw_table()?,
                        )
                        .map_err(|_| HarnessError::InvalidState)?;
                }
                virtual_address = virtual_address
                    .checked_add(G::SIZE)
                    .ok_or(HarnessError::Memory)?;
                physical_address = physical_address
                    .checked_add(G::SIZE)
                    .ok_or(HarnessError::Memory)?;
            }
        }
        Ok(())
    }

    pub fn map_attributes_leaf(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                R::raw_leaf(attributes)?,
                R::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }
}

impl<R: TestRegime, G: TestGranule> TestMapper<R, G, Vmsa64>
where
    R: TestRegimeFor<G>,
    Vmsa64: HasLayout<StageOf<R>, G>,
    LeafFieldsOf<Vmsa64, R, G>: Copy,
{
    pub fn map_block(
        &mut self,
        input: u64,
        output: u64,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::L3,
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_leaf(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }
}

impl<R: TestRegime, G: TestGranule> TestMapper<R, G, Vmsa64Lpa2>
where
    R: TestRegimeFor<G>,
    Vmsa64: HasLayout<StageOf<R>, G>,
    Vmsa64Lpa2: HasLayout<StageOf<R>, G>,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            Vmsa64Lpa2,
            StageOf<R>,
            G,
            LeafFields = LeafFieldsOf<Vmsa64, R, G>,
            TableFields = TableFieldsOf<Vmsa64, R, G>,
        >,
    LeafFieldsOf<Vmsa64, R, G>: Copy,
{
    pub fn map_page(
        &mut self,
        input: u64,
        output: u64,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::L3,
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_leaf(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }
}

impl<R: TestRegime> TestMapper<R, Granule4KiB, Vmsa128>
where
    Vmsa128: HasLayout<StageOf<R>, Granule4KiB>,
    <Vmsa128 as HasLayout<StageOf<R>, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa128,
            StageOf<R>,
            Granule4KiB,
            LeafFields = RawVmsa128Stage1LeafAttrs,
            TableFields = RawVmsa128Stage1TableAttrs,
        >,
{
    fn d128_fields_with_state(
        permissions: D128MappingPermissions,
        access_flag: bool,
        dirty: bool,
    ) -> Result<(RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs), HarnessError> {
        let zero = FourBit::new(0).map_err(|_| HarnessError::InvalidState)?;
        let permission = FourBit::new(match permissions {
            D128MappingPermissions::ReadExecute => 0,
            D128MappingPermissions::ReadWrite => 1,
        })
        .map_err(|_| HarnessError::InvalidState)?;
        Ok((
            RawVmsa128Stage1LeafAttrs {
                attr_index: zero,
                bbm_nt: false,
                not_dirty: Stage1NotDirty::new(!dirty),
                shareability: RawShareability::from_bits(0)
                    .map_err(|_| HarnessError::InvalidState)?,
                access_flag,
                alias_bit: false,
                contiguous: false,
                guarded: false,
                protected: false,
                permissions: PermissionIndices {
                    pi: permission,
                    po: permission,
                },
                ns: false,
                software: TenBit::new(0).map_err(|_| HarnessError::InvalidState)?,
            },
            RawVmsa128Stage1TableAttrs {
                access_flag: true,
                ..RawVmsa128Stage1TableAttrs::default()
            },
        ))
    }

    fn d128_fields(
        executable: bool,
    ) -> Result<(RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs), HarnessError> {
        Self::d128_fields_with_state(
            if executable {
                D128MappingPermissions::ReadExecute
            } else {
                D128MappingPermissions::ReadWrite
            },
            true,
            true,
        )
    }

    fn map_d128_runtime_page(
        &mut self,
        input: u64,
        output: u64,
        executable: bool,
    ) -> Result<(), HarnessError> {
        let (leaf, table) = Self::d128_fields(executable)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::L3,
                leaf,
                table,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub(crate) fn prepare_current_runtime_d128(
        &mut self,
        entry: u64,
        payload_data: [u64; 2],
        sandbox_regions: &[(u64, u64)],
    ) -> Result<(), HarnessError> {
        const PAGE_SIZE: u64 = 4096;
        const CODE_WINDOW: u64 = 512 * 1024;
        let stack = vmsa_test_architecture::registers::stack_pointer() & !(PAGE_SIZE - 1);
        let stack_start = stack.saturating_sub(15 * PAGE_SIZE);
        let stack_end = stack.saturating_add(16 * PAGE_SIZE);
        let code_regions = [
            entry & !(CODE_WINDOW - 1),
            vmsa_test_architecture::exception::vector_address() & !(CODE_WINDOW - 1),
            vmsa_test_architecture::exception::recovery_vector_address() & !(CODE_WINDOW - 1),
        ];
        let data_pages = [
            payload_data[0] & !(PAGE_SIZE - 1),
            vmsa_test_architecture::exception::runtime_state_address() & !(PAGE_SIZE - 1),
            vmsa_test_architecture::transition::runtime_state_address() & !(PAGE_SIZE - 1),
            payload_data[1] & !(PAGE_SIZE - 1),
            0x1c09_0000 & !(PAGE_SIZE - 1),
            0x1c0a_0000 & !(PAGE_SIZE - 1),
        ];
        for index in 0..code_regions.len() {
            let region = code_regions[index];
            if code_regions[..index].contains(&region) {
                continue;
            }
            let end = region
                .checked_add(CODE_WINDOW)
                .ok_or(HarnessError::Memory)?;
            let mut address = region;
            while address < end {
                let sandbox_data = sandbox_regions.iter().any(|(input, _)| *input == address);
                if !(stack_start..stack_end).contains(&address)
                    && !data_pages.contains(&address)
                    && !sandbox_data
                {
                    self.map_d128_runtime_page(address, address, true)?;
                }
                address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        let mut address = stack_start;
        while address < stack_end {
            self.map_d128_runtime_page(address, address, false)?;
            address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
        }
        for index in 0..data_pages.len() {
            let address = data_pages[index];
            if data_pages[..index].contains(&address)
                || sandbox_regions.iter().any(|(input, _)| *input == address)
            {
                continue;
            }
            let executable = code_regions
                .iter()
                .any(|region| (*region..*region + CODE_WINDOW).contains(&address));
            self.map_d128_runtime_page(address, address, executable)?;
        }
        for &(input, output) in sandbox_regions {
            if input & (PAGE_SIZE - 1) != 0 || output & (PAGE_SIZE - 1) != 0 {
                return Err(HarnessError::InvalidState);
            }
            if let Some(mapping) = self
                .inner
                .translate(WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
            {
                if mapping.output().0 != output || mapping.level() != Level::L3 {
                    return Err(HarnessError::InvalidState);
                }
            } else {
                self.map_d128_runtime_page(input, output, false)?;
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_transition_table_access_d128(&mut self) -> Result<(), HarnessError> {
        const PAGE_SIZE: u64 = 4096;
        let memory = self.inner.frames().memory();
        let mut index = 0usize;
        while index < unsafe { memory.as_ref() }.allocation_count() {
            let region = unsafe { memory.as_ref() }.table_allocation_region(index);
            index = index.checked_add(1).ok_or(HarnessError::Memory)?;
            let Some(region) = region else {
                continue;
            };
            if region.virtual_address & (PAGE_SIZE - 1) != 0
                || region.physical_address & (PAGE_SIZE - 1) != 0
                || region.bytes == 0
                || region.bytes as u64 & (PAGE_SIZE - 1) != 0
            {
                return Err(HarnessError::InvalidState);
            }
            let end = region
                .virtual_address
                .checked_add(region.bytes as u64)
                .ok_or(HarnessError::Memory)?;
            let mut input = region.virtual_address;
            let mut output = region.physical_address;
            while input < end {
                if let Some(mapping) = self
                    .inner
                    .translate(WalkInputAddr::new(input))
                    .map_err(|_| HarnessError::InvalidState)?
                {
                    if mapping.output().0 != output || mapping.level() != Level::L3 {
                        return Err(HarnessError::InvalidState);
                    }
                } else {
                    self.map_d128_runtime_page(input, output, false)?;
                }
                input = input.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
                output = output.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        Ok(())
    }

    pub fn map_page(&mut self, input: u64, output: u64) -> Result<(), HarnessError> {
        let (leaf, table) = Self::d128_fields(false)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::L3,
                leaf,
                table,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_hardware_managed_page(
        &mut self,
        input: u64,
        output: u64,
        attributes: D128HardwareManagedAttributes,
    ) -> Result<(), HarnessError> {
        let (leaf, table) = Self::d128_fields_with_state(
            attributes.permissions,
            attributes.access_flag,
            attributes.dirty,
        )?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::L3,
                leaf,
                table,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }
}

impl<R: TestRegime> TestMapper<R, Granule4KiB, Vmsa128>
where
    R::WalkProfile: TranslationWalkProfile<Stage = Stage2>,
    Vmsa128: HasLayout<Stage2, Granule4KiB>,
    <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout: DescriptorLayout<
            Vmsa128,
            Stage2,
            Granule4KiB,
            LeafFields = RawVmsa128Stage2LeafAttrs,
            TableFields = RawVmsa128Stage2TableAttrs,
        >,
{
    pub fn map_stage2_page(
        &mut self,
        input: u64,
        output: u64,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        let level = LookupLevel::new(3).ok_or(HarnessError::InvalidState)?;
        self.map_stage2_leaf(input, output, level, attributes)
    }

    pub fn map_stage2_leaf(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: MappingAttributes,
    ) -> Result<(), HarnessError> {
        let (leaf, table) = d128_stage2_fields(attributes)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                leaf,
                table,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }
}
