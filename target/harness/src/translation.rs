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

pub(crate) const fn infrastructure_stage1_start_level(
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
    if bits < 32 || bits > maximum {
        return None;
    }
    let level = match (format, granule) {
        (TranslationFormat::Vmsa128, Granule::Size4KiB) => {
            if bits <= 36 {
                1
            } else if bits <= 44 {
                0
            } else if bits <= 52 {
                -1
            } else {
                -2
            }
        }
        (TranslationFormat::Vmsa128, Granule::Size16KiB) => {
            if bits <= 34 {
                2
            } else if bits <= 44 {
                1
            } else {
                0
            }
        }
        (TranslationFormat::Vmsa128, Granule::Size64KiB) => {
            if bits <= 40 {
                2
            } else {
                1
            }
        }
        (_, Granule::Size4KiB) => {
            if bits <= 39 {
                1
            } else if bits <= 48 {
                0
            } else {
                -1
            }
        }
        (_, Granule::Size16KiB) => {
            if bits <= 36 {
                2
            } else if bits <= 47 {
                1
            } else {
                0
            }
        }
        (_, Granule::Size64KiB) => {
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
    pir: u64,
    pire0: u64,
}

impl Stage1MemoryControls {
    /// Runtime permission indices used by the harness's D128 transition maps:
    /// index 0 is privileged read/execute and index 1 is privileged read/write.
    /// Both entries disable permission overlays; unused entries default to
    /// read/write so that they cannot accidentally make transition code
    /// executable.
    pub const D128_RUNTIME_PIR: u64 = 0xcccc_cccc_cccc_ccca;
    /// The transition runtime is privileged-only.  Keeping every
    /// unprivileged permission entry at NoAccess also prevents host-regime
    /// accesses from becoming subject to PAN merely because they share the
    /// same PI index as the privileged mapping.
    pub const D128_RUNTIME_PIRE0: u64 = 0;

    pub const DEFAULT: Self = Self {
        mair: 0x0000_ff44,
        mair2: 0,
        pir: Self::D128_RUNTIME_PIR,
        pire0: Self::D128_RUNTIME_PIRE0,
    };

    pub const fn empty() -> Self {
        Self {
            mair: 0,
            mair2: 0,
            pir: Self::D128_RUNTIME_PIR,
            pire0: Self::D128_RUNTIME_PIRE0,
        }
    }

    /// Installs an architecturally encoded MAIR byte for translation setup.
    ///
    /// This deliberately accepts the register encoding rather than semantic
    /// attributes. Semantic encoding is behavior of the crate under test and
    /// must go through its `AttributeCodec`, never through harness logic.
    pub fn with_raw_attribute(mut self, slot: MemoryAttributeSlot, encoded: u8) -> Self {
        let index = slot.index();
        let (register, shift) = if index < 8 {
            (&mut self.mair, u32::from(index) * 8)
        } else {
            (&mut self.mair2, u32::from(index - 8) * 8)
        };
        *register = (*register & !(0xff_u64 << shift)) | (u64::from(encoded) << shift);
        self
    }

    /// Installs raw architectural stage-1 permission-indirection registers.
    /// The values are register encodings, not permissions derived by the
    /// harness from crate output.
    pub const fn with_raw_permission_registers(
        mut self,
        privileged: u64,
        unprivileged: u64,
    ) -> Self {
        self.pir = privileged;
        self.pire0 = unprivileged;
        self
    }

    pub(crate) const fn registers(self) -> (u64, u64, u64, u64) {
        (self.mair, self.mair2, self.pir, self.pire0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D128MappingPermissions {
    ReadExecute,
    ReadWrite,
    ReadWriteExecute,
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
    lpa2_el2_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

pub const fn lpa2_el2_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() != 52 {
        return None;
    }
    let ps = match output_bits.get() {
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    // In the non-host EL2 layout, SL2 selects the level -1 initial lookup
    // used by a 52-bit, 4 KiB LPA2 walk. Other granules begin at level 1 for
    // this geometry and require SL2 to remain clear.
    let sl2 = match granule {
        Granule::Size4KiB => 1u64 << 33,
        Granule::Size16KiB | Granule::Size64KiB => 0,
    };
    Some(TranslationControls::from_bits(
        12 | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (ps << 16)
            | (1 << 23)
            | (1 << 31)
            | (1 << 32)
            | sl2,
    ))
}

pub const fn lpa2_el3_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    lpa2_el3_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

/// Encodes LPA2 stage-1 controls for the live current-EL register layout.
///
/// When EL2 is in host mode, TCR_EL2 uses the EL1-format field positions;
/// non-host EL2 and EL3 use the EL2/EL3 layout instead.
pub fn lpa2_current_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    lpa2_current_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

/// Encodes LPA2 stage-1 controls for the executing current-EL register layout.
///
/// EL2 uses the EL1-format TCR field positions while HCR_EL2.E2H is set and
/// the non-host EL2 positions otherwise. Selecting from the live mode is
/// required before replacing the current translation regime: encoding the
/// other layout can invalidate the executing code, stack, and vectors as soon
/// as SCTLR_EL2.M is re-enabled.
pub fn lpa2_current_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    match vmsa_test_architecture::registers::current_el() {
        // Current-EL coverage uses the typed non-host EL2 regime and the
        // transactional installer clears E2H while that candidate is live.
        // Encoding from the firmware's pre-install E2H value would pair host
        // TCR fields with non-host descriptors and can make even the vector
        // page untranslatable.
        2 => lpa2_el2_stage1_controls(granule, input_bits, output_bits),
        3 => lpa2_el3_stage1_controls(granule, input_bits, output_bits),
        _ => None,
    }
}

const fn lpa2_el2_stage1_controls_for_mode(
    host_mode: bool,
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if host_mode {
        lpa2_el1_stage1_controls(granule, input_bits, output_bits)
    } else {
        lpa2_el2_stage1_controls(granule, input_bits, output_bits)
    }
}

pub const fn lpa2_el3_stage1_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    let Some(controls) = lpa2_el2_stage1_controls(granule, input_bits, output_bits) else {
        return None;
    };
    Some(TranslationControls::from_bits(controls.bits()))
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
    if input_bits.get() != 52 {
        return None;
    }
    let ips = match output_bits.get() {
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
        12 | (1 << 8) | (1 << 10) | (3 << 12) | (tg0 << 14) | (1 << 23) | (ips << 32) | (1 << 59),
    ))
}

const _: () = {
    let bits = match AddressBits::new(52) {
        Some(bits) => bits,
        None => panic!("52-bit LPA2 geometry must be valid"),
    };
    let host = match lpa2_el2_stage1_controls_for_mode(true, Granule::Size4KiB, bits, bits) {
        Some(controls) => controls.bits(),
        None => panic!("host EL2 LPA2 controls must be encodable"),
    };
    let non_host = match lpa2_el2_stage1_controls_for_mode(false, Granule::Size4KiB, bits, bits) {
        Some(controls) => controls.bits(),
        None => panic!("non-host EL2 LPA2 controls must be encodable"),
    };
    assert!(host & (1 << 59) != 0);
    assert!((host >> 32) & 0x7 == 6);
    assert!(non_host & (1 << 59) == 0);
    assert!((non_host >> 16) & 0x7 == 6);
};

pub const fn d128_el1_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    d128_el1_stage1_controls(Granule::Size4KiB, input_bits, output_bits)
}

pub const fn d128_el1_stage1_controls(
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
        12 | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (6 << 16)
            | (1 << 23)
            | (1 << 31)
            | (1 << 32),
    ))
}

pub const fn d128_el2_stage1_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    if input_bits.get() < 44 || input_bits.get() > 52 {
        return None;
    }
    let ips = match output_bits.get() {
        48 => 5u64,
        52 => 6u64,
        _ => return None,
    };
    // A 128-bit TTBR0_EL2 is defined only for the EL2&0 host regime. These
    // are therefore the HCR_EL2.E2H=1 TCR fields: disable TTBR1 with a legal
    // 4-KiB geometry, and encode output size in IPS[34:32]. TCR_EL2.DS[59]
    // is RES0 while TCR2_EL2.D128 is set.
    Some(TranslationControls::from_bits(
        (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (16 << 16)
            | (1 << 23)
            | (1 << 31)
            | (ips << 32),
    ))
}

pub const fn vmsa64_stage2_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
    start_level: LookupLevel,
) -> Option<TranslationControls> {
    vmsa64_stage2_controls(Granule::Size4KiB, input_bits, output_bits, start_level)
}

pub const fn vmsa64_stage2_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
    start_level: LookupLevel,
) -> Option<TranslationControls> {
    let (minimum_input, maximum_input, sl0) = match (granule, start_level.get()) {
        (Granule::Size4KiB, 0) => (40, 48, 2u64),
        (Granule::Size4KiB, 1) => (31, 39, 1u64),
        (Granule::Size4KiB, 2) => (22, 30, 0u64),
        (Granule::Size4KiB, 3) => (12, 21, 3u64),
        (Granule::Size16KiB, 1) => (37, 47, 2u64),
        (Granule::Size16KiB, 2) => (25, 36, 1u64),
        (Granule::Size16KiB, 3) => (14, 24, 0u64),
        (Granule::Size64KiB, 1) => (43, 48, 2u64),
        (Granule::Size64KiB, 2) => (29, 42, 1u64),
        (Granule::Size64KiB, 3) => (16, 28, 0u64),
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
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    Some(TranslationControls::from_bits(
        (1 << 31)
            | (64 - input_bits.get() as u64)
            | (sl0 << 6)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (ps << 16),
    ))
}

pub const fn lpa2_stage2_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    lpa2_stage2_controls(
        Granule::Size4KiB,
        input_bits,
        output_bits,
        LookupLevel::new(-1).unwrap(),
    )
}

pub const fn lpa2_stage2_controls(
    granule: Granule,
    input_bits: AddressBits,
    output_bits: AddressBits,
    start_level: LookupLevel,
) -> Option<TranslationControls> {
    if input_bits.get() != 52 || output_bits.get() != 52 {
        return None;
    }
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    let ds = match granule {
        Granule::Size4KiB | Granule::Size16KiB => 1u64 << 32,
        Granule::Size64KiB => 0,
    };
    let (sl0, sl2) = match (granule, start_level.get()) {
        (Granule::Size4KiB, -1) => (0u64, 1u64 << 33),
        (Granule::Size4KiB, 0) => (2u64, 0u64),
        (Granule::Size4KiB, 1) => (1u64, 0u64),
        (Granule::Size16KiB, 0) => (3u64, 0u64),
        (Granule::Size16KiB, 1) | (Granule::Size64KiB, 1) => (2u64, 0u64),
        (Granule::Size16KiB, 2) | (Granule::Size64KiB, 2) => (1u64, 0u64),
        (Granule::Size16KiB, 3) | (Granule::Size64KiB, 3) => (0u64, 0u64),
        _ => return None,
    };
    Some(TranslationControls::from_bits(
        (1 << 31)
            | 12
            | (sl0 << 6)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
            | (6 << 16)
            | ds
            | sl2,
    ))
}

pub const fn d128_stage2_controls_4k(
    input_bits: AddressBits,
    output_bits: AddressBits,
) -> Option<TranslationControls> {
    d128_stage2_controls(Granule::Size4KiB, input_bits, output_bits)
}

pub const fn d128_stage2_controls(
    granule: Granule,
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
    let tg0 = match granule {
        Granule::Size4KiB => 0u64,
        Granule::Size16KiB => 2u64,
        Granule::Size64KiB => 1u64,
    };
    Some(TranslationControls::from_bits(
        (1 << 31)
            | (64 - input_bits.get() as u64)
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (tg0 << 14)
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
            // TG1 uses a different encoding from TG0. Keep the disabled
            // TTBR1 region on its valid 4 KiB encoding rather than RES0/00.
            | (2 << 30)
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

use aarch64_vmsa::address::{GranuleKind, Level, PhysAddr, TranslationGranule, VirtAddr};
use aarch64_vmsa::config::format::{Vmsa64, Vmsa64Lpa2, Vmsa128};
use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
use aarch64_vmsa::low_level::raw::{
    FourBit, LeafAp, PermissionIndices, RawShareability, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs,
    RawVmsa128Stage2TableAttrs, Stage1NotDirty, Stage2Ap, Stage2Dirty, Stage2ExecuteNever, TableAp,
    TenBit, ThreeBit,
};
use aarch64_vmsa::mapper::{Mapper, Offline};
use aarch64_vmsa::regime::TranslationRegime;
use aarch64_vmsa::table::{
    OffsetTableAccess, RecursiveTableAccess, RootTable, TableAccess, TableAccessMut, TableAddr,
    TableAllocLayout, TableFrameProvider, TableShape, TableTransition,
};
use aarch64_vmsa::translation::walk::{WalkEntry, WalkInputAddr, Walker};
use aarch64_vmsa::translation::{Stage1, Stage2};

type StageOf<R> = <R as TranslationRegime>::Stage;
type LeafFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeLeafFields<F, R, G>;
type TableFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeTableFields<F, R, G>;

fn arena_table_access(memory: NonNull<TestMemory>) -> OffsetTableAccess {
    // SAFETY: TestMemory owns one stable, contiguous direct-map region for its
    // full lifetime; table addresses handed to the crate are allocated within it.
    let memory = unsafe { memory.as_ref() };
    let region = unsafe {
        aarch64_vmsa::table::DirectMapRegion::from_raw_parts(
            VirtAddr(memory.physical_to_virtual_offset()),
            memory.physical_base(),
            memory.capacity_bytes(),
        )
    };
    OffsetTableAccess::new(region)
}

/// Compatibility surface used by payloads while preserving the crate's public
/// semantic attribute families as the source of truth.
pub trait AttributeCodecCompat<R, G, Cfg>: aarch64_vmsa::attrs::AttributeCodec<R, G, Cfg>
where
    R: TranslationRegime,
    G: aarch64_vmsa::address::TranslationGranule,
    Self: aarch64_vmsa::attrs::SemanticAttributeTypes<
            R::Stage,
            R,
            Leaf = Self::SemanticLeaf,
            Table = Self::SemanticTable,
        >,
{
    type SemanticLeaf;
    type SemanticTable;
    type RawLeaf;
    type RawTable;

    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticLeaf,
    ) -> Result<Self::RawLeaf, aarch64_vmsa::attrs::AttrError>;
    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticTable,
    ) -> Result<Self::RawTable, aarch64_vmsa::attrs::AttrError>;
}

impl<F, R, G, Cfg> AttributeCodecCompat<R, G, Cfg> for F
where
    R: TranslationRegime,
    G: aarch64_vmsa::address::TranslationGranule,
    F: aarch64_vmsa::attrs::AttributeCodec<R, G, Cfg>,
{
    type SemanticLeaf = aarch64_vmsa::attrs::SemanticLeafAttrs<F, R>;
    type SemanticTable = aarch64_vmsa::attrs::SemanticTableAttrs<F, R>;
    type RawLeaf = LeafFieldsOf<F, R, G>;
    type RawTable = TableFieldsOf<F, R, G>;

    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticLeaf,
    ) -> Result<Self::RawLeaf, aarch64_vmsa::attrs::AttrError> {
        <F as aarch64_vmsa::attrs::AttributeCodec<R, G, Cfg>>::encode_leaf(config, level, attrs)
    }

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticTable,
    ) -> Result<Self::RawTable, aarch64_vmsa::attrs::AttrError> {
        <F as aarch64_vmsa::attrs::AttributeCodec<R, G, Cfg>>::encode_table(config, level, attrs)
    }
}

trait RootTableCompat<F, R, G> {
    fn new(addr: TableAddr<G>, level: Level, addr_bits: u8, output_addr_bits: u8) -> Self
    where
        F: DescriptorFormat,
        R: TranslationRegime,
        G: aarch64_vmsa::address::TranslationGranule;
}

impl<F, R, G> RootTableCompat<F, R, G> for RootTable<F, R, G>
where
    F: DescriptorFormat,
    R: TranslationRegime,
    G: aarch64_vmsa::address::TranslationGranule,
{
    fn new(addr: TableAddr<G>, level: Level, addr_bits: u8, output_addr_bits: u8) -> Self {
        Self::from_geometry(
            aarch64_vmsa::table::RootTableGeometry::new_at_level(
                addr,
                level,
                addr_bits,
                output_addr_bits,
            )
            .expect("validated translation geometry"),
        )
    }
}
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::HarnessError;
use crate::memory::{RootTableMemory, TestMemory};

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
    const MUTABLE_FIRMWARE_CODE: bool;
    const CURRENT_STACK_WINDOW: u64;
    fn default_input_bits(capabilities: crate::Capabilities) -> u8;
}

pub trait TestRegimeFor<G: TranslationGranule>: TestRegime
where
    Vmsa64: HasLayout<StageOf<Self>, G>,
{
    fn raw_leaf(
        attributes: MappingAttributes,
    ) -> Result<LeafFieldsOf<Vmsa64, Self, G>, HarnessError>;
    fn raw_leaf_for_format(
        attributes: MappingAttributes,
        _format: TranslationFormat,
    ) -> Result<LeafFieldsOf<Vmsa64, Self, G>, HarnessError> {
        Self::raw_leaf(attributes)
    }
    fn raw_table() -> Result<TableFieldsOf<Vmsa64, Self, G>, HarnessError>;
}

fn lpa2_uses_ds<G: TranslationGranule>(format: TranslationFormat) -> bool {
    matches!(format, TranslationFormat::Vmsa64Lpa2)
        && matches!(G::kind(), GranuleKind::Size4KiB | GranuleKind::Size16KiB)
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
    ($regime:ty, $granule:ty, $alias_bit:expr) => {
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
                    alias_bit: $alias_bit,
                    dirty_bit_modifier: false,
                    contiguous: false,
                    privileged_execute_never: false,
                    unprivileged_execute_never: !attributes.executable,
                    guarded: false,
                    software: FourBit::new(0).map_err(|_| HarnessError::InvalidState)?,
                })
            }

            fn raw_leaf_for_format(
                attributes: MappingAttributes,
                format: TranslationFormat,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let mut fields = <Self as TestRegimeFor<$granule>>::raw_leaf(attributes)?;
                if lpa2_uses_ds::<$granule>(format) {
                    fields.shareability =
                        RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?;
                }
                Ok(fields)
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
    ($regime:ty, $alias_bit:expr, $mutable_firmware_code:expr, $stack_window:expr) => {
        impl TestRegime for $regime {
            const MUTABLE_FIRMWARE_CODE: bool = $mutable_firmware_code;
            const CURRENT_STACK_WINDOW: u64 = $stack_window;
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.va_bits.min(48)
            }
        }
        stage1_test_regime_for_granule!($regime, Granule4KiB, $alias_bit);
        stage1_test_regime_for_granule!($regime, Granule16KiB, $alias_bit);
        stage1_test_regime_for_granule!($regime, Granule64KiB, $alias_bit);
    };
}

stage1_test_regime!(
    aarch64_vmsa::config::regime::NonSecureEl2Stage1,
    false,
    false,
    256 * 1024
);
stage1_test_regime!(
    aarch64_vmsa::config::regime::SecureEl2Stage1,
    false,
    false,
    256 * 1024
);
stage1_test_regime!(
    aarch64_vmsa::config::regime::RealmEl2Stage1,
    false,
    false,
    256 * 1024
);
// In the Root regime descriptor bit 11 is NSE, not nG. Root output PAS is
// encoded as NS=0,NSE=1; leaving the shared runtime mapper's old zero value
// selected Secure PAS and produced a GPT-backed EL3 permission fault as soon
// as the candidate began fetching instructions.
stage1_test_regime!(
    aarch64_vmsa::config::regime::RootEl3Stage1,
    true,
    true,
    64 * 1024
);

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

            fn raw_leaf_for_format(
                attributes: MappingAttributes,
                format: TranslationFormat,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let mut fields = <Self as TestRegimeFor<$granule>>::raw_leaf(attributes)?;
                if lpa2_uses_ds::<$granule>(format) {
                    fields.shareability =
                        RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?;
                }
                Ok(fields)
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
            const MUTABLE_FIRMWARE_CODE: bool = false;
            const CURRENT_STACK_WINDOW: u64 = 256 * 1024;
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.va_bits.min(48)
            }
        }
        two_privilege_test_regime_for_granule!($regime, Granule4KiB);
        two_privilege_test_regime_for_granule!($regime, Granule16KiB);
        two_privilege_test_regime_for_granule!($regime, Granule64KiB);
    };
}

two_privilege_test_regime!(aarch64_vmsa::config::regime::NonSecureEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::config::regime::SecureEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::config::regime::RealmEl1Stage1);
two_privilege_test_regime!(aarch64_vmsa::config::regime::NonSecureEl2HostStage1);
two_privilege_test_regime!(aarch64_vmsa::config::regime::SecureEl2HostStage1);
two_privilege_test_regime!(aarch64_vmsa::config::regime::RealmEl2HostStage1);

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

            fn raw_leaf_for_format(
                attributes: MappingAttributes,
                format: TranslationFormat,
            ) -> Result<LeafFieldsOf<Vmsa64, Self, $granule>, HarnessError> {
                let mut fields = <Self as TestRegimeFor<$granule>>::raw_leaf(attributes)?;
                if lpa2_uses_ds::<$granule>(format) {
                    fields.shareability =
                        RawShareability::from_bits(0).map_err(|_| HarnessError::InvalidState)?;
                }
                Ok(fields)
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
            const MUTABLE_FIRMWARE_CODE: bool = false;
            const CURRENT_STACK_WINDOW: u64 = 256 * 1024;
            fn default_input_bits(capabilities: crate::Capabilities) -> u8 {
                capabilities.pa_bits.min(48)
            }
        }
        stage2_test_regime_for_granule!($regime, Granule4KiB);
        stage2_test_regime_for_granule!($regime, Granule16KiB);
        stage2_test_regime_for_granule!($regime, Granule64KiB);
    };
}

stage2_test_regime!(aarch64_vmsa::config::regime::NonSecureEl2Stage2);
stage2_test_regime!(
    aarch64_vmsa::config::regime::NonSecureEl2Stage2<
        aarch64_vmsa::config::stage2::Stage2XnxPermissions,
    >
);
stage2_test_regime!(aarch64_vmsa::config::regime::SecureEl2SecureIpaStage2);
stage2_test_regime!(
    aarch64_vmsa::config::regime::SecureEl2SecureIpaStage2<
        aarch64_vmsa::config::stage2::Stage2XnxPermissions,
    >
);
stage2_test_regime!(aarch64_vmsa::config::regime::SecureEl2NonSecureIpaStage2);
stage2_test_regime!(
    aarch64_vmsa::config::regime::SecureEl2NonSecureIpaStage2<
        aarch64_vmsa::config::stage2::Stage2XnxPermissions,
    >
);
stage2_test_regime!(aarch64_vmsa::config::regime::RealmEl2Stage2);
stage2_test_regime!(
    aarch64_vmsa::config::regime::RealmEl2Stage2<
        aarch64_vmsa::config::stage2::Stage2XnxPermissions,
    >
);

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

unsafe impl<G: aarch64_vmsa::address::TranslationGranule> TableFrameProvider<G>
    for ArenaFrameProvider
{
    type Error = crate::MemoryError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error> {
        // SAFETY: TestContext serializes access to the arena for the mapper lifetime.
        <TestMemory as TableFrameProvider<G>>::allocate_zeroed_table(
            unsafe { self.memory.as_mut() },
            layout,
        )
    }

    fn reclaim_table(
        &mut self,
        reclaim: aarch64_vmsa::table::TableReclaim<G>,
    ) -> Result<(), Self::Error> {
        // SAFETY: TestContext serializes access to the arena for the mapper lifetime.
        <TestMemory as TableFrameProvider<G>>::reclaim_table(
            unsafe { self.memory.as_mut() },
            reclaim,
        )
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

pub trait TestFormat:
    DescriptorFormat + aarch64_vmsa::descriptor::SupportsLiveDescriptorIo
{
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

unsafe impl<F, G> aarch64_vmsa::mapper::MapperInvalidation<F, G> for ArchitecturalInvalidation
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

    fn before_table_frame_reclaim(&mut self, _: TableAddr<G>, _: TableAllocLayout) {
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
    let root_address = TableAddr::new(setup.root.get()).map_err(|_| HarnessError::Memory)?;
    let transition = TableTransition::new(
        TableShape::<Vmsa64, Granule4KiB>::root(root_level)
            .map_err(|_| HarnessError::InvalidState)?,
        TableShape::<Vmsa64, Granule4KiB>::root(child_level)
            .map_err(|_| HarnessError::InvalidState)?,
    )
    .map_err(|_| HarnessError::InvalidState)?;
    type Layout<R> = <Vmsa64 as HasLayout<StageOf<R>, Granule4KiB>>::Layout;
    let descriptor = <Layout<R> as DescriptorLayout<StageOf<R>, Granule4KiB>>::table_descriptor(
        root_address,
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
    let root_address = TableAddr::new(setup.root.get()).map_err(|_| HarnessError::Memory)?;
    // SAFETY: The installed translation root and all descendant tables are
    // allocated from the live per-test arena with a constant physical offset.
    let access = arena_table_access(memory);
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
    let removed = unsafe { mapper.unmap(WalkInputAddr::new(input)) }
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
    R: aarch64_vmsa::regime::TranslationRegime<Stage = Stage1>,
    Vmsa128: HasLayout<Stage1, Granule4KiB>,
    <Vmsa128 as HasLayout<Stage1, Granule4KiB>>::Layout: DescriptorLayout<
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
        D128MappingPermissions::ReadWriteExecute => 2,
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
    R: aarch64_vmsa::regime::TranslationRegime<Stage = Stage2>,
    Vmsa128: HasLayout<Stage2, Granule4KiB>,
    <Vmsa128 as HasLayout<Stage2, Granule4KiB>>::Layout: DescriptorLayout<
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
    stack_physical_top: u64,
    exception_stack_top: u64,
    exception_stack_physical_top: u64,
    runtime_data: [u64; 4],
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
            StageOf<R>,
            Granule4KiB,
            LeafFields = LeafFieldsOf<Vmsa64, R, Granule4KiB>,
            TableFields = TableFieldsOf<Vmsa64, R, Granule4KiB>,
        >,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, Granule16KiB>>::Layout: DescriptorLayout<
            StageOf<R>,
            Granule16KiB,
            LeafFields = LeafFieldsOf<Vmsa64, R, Granule16KiB>,
            TableFields = TableFieldsOf<Vmsa64, R, Granule16KiB>,
        >,
    <Vmsa64Lpa2 as HasLayout<StageOf<R>, Granule64KiB>>::Layout: DescriptorLayout<
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
            prepare_lower_runtime_for::<R, Vmsa64, Granule4KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
            )
        }
        (TranslationFormat::Vmsa64, Granule::Size16KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64, Granule16KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
            )
        }
        (TranslationFormat::Vmsa64, Granule::Size64KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64, Granule64KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
            )
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size4KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule4KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
            )
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size16KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule16KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
            )
        }
        (TranslationFormat::Vmsa64Lpa2, Granule::Size64KiB) => {
            prepare_lower_runtime_for::<R, Vmsa64Lpa2, Granule64KiB>(
                memory,
                setup,
                entry,
                stack_top,
                stack_physical_top,
                exception_stack_top,
                exception_stack_physical_top,
                runtime_data,
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
    stack_physical_top: u64,
    exception_stack_top: u64,
    exception_stack_physical_top: u64,
    runtime_data: [u64; 4],
) -> Result<(), HarnessError>
where
    R: TestRegimeFor<G>,
    G: TestGranule,
    Vmsa64: HasLayout<StageOf<R>, G>,
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    <F as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            StageOf<R>,
            G,
            LeafFields = LeafFieldsOf<Vmsa64, R, G>,
            TableFields = TableFieldsOf<Vmsa64, R, G>,
        >,
    LeafFieldsOf<Vmsa64, R, G>: Copy + PartialEq,
{
    use crate::TransitionPreparationError;

    if setup.granule != G::GRANULE
        || entry == 0
        || stack_top < G::SIZE
        || stack_physical_top < G::SIZE
        || exception_stack_top < G::SIZE
        || exception_stack_physical_top < G::SIZE
    {
        return Err(HarnessError::TransitionPreparation(
            TransitionPreparationError::RecoveryMapper,
        ));
    }

    let start_level = setup.start_level.ok_or(HarnessError::InvalidState)?;
    let root_address = TableAddr::new(setup.root.get()).map_err(|_| HarnessError::Memory)?;

    let memory = NonNull::from(memory);

    // SAFETY: The adapter supplies the same reserved contiguous arena used by
    // the frame provider and keeps it live through lower translation restore.
    let access = arena_table_access(memory);

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
    .map_err(|_| {
        HarnessError::TransitionPreparation(TransitionPreparationError::RecoveryRuntime)
    })?;

    const LINKED_CODE_REGION: u64 = 1024 * 1024;
    const RUNTIME_DATA_WINDOW: u64 = 64 * 1024;

    let code_window = G::SIZE.max(LINKED_CODE_REGION);

    let code_fields = R::raw_leaf_for_format(
        MappingAttributes {
            writable: false,
            executable: true,
            user_accessible: true,
        },
        setup.format,
    )?;

    let data_fields = R::raw_leaf_for_format(
        MappingAttributes {
            writable: true,
            executable: false,
            user_accessible: true,
        },
        setup.format,
    )?;

    let exception_stack_fields = R::raw_leaf_for_format(
        MappingAttributes {
            writable: true,
            executable: false,
            user_accessible: false,
        },
        setup.format,
    )?;

    let table_fields = R::raw_table()?;

    let code_windows = [
        entry & !(code_window - 1),
        vmsa_test_architecture::exception::vector_address() & !(code_window - 1),
        vmsa_test_architecture::exception::recovery_vector_address() & !(code_window - 1),
        vmsa_test_architecture::exception::runtime_code_address() & !(code_window - 1),
        vmsa_test_architecture::transition::runtime_code_address() & !(code_window - 1),
    ];

    let stack_page = G::align_down(stack_top - 1);
    let stack_physical_page = G::align_down(stack_physical_top - 1);
    let exception_stack_page = G::align_down(exception_stack_top - 1);
    let exception_stack_physical_page = G::align_down(exception_stack_physical_top - 1);

    let state_pages = [
        G::align_down(vmsa_test_architecture::exception::runtime_state_address()),
        G::align_down(vmsa_test_architecture::transition::runtime_state_address()),
    ];

    let linkage_page = G::align_down(vmsa_test_architecture::exception::linkage_data_address());

    let data_windows = [
        runtime_data[0] & !(RUNTIME_DATA_WINDOW - 1),
        runtime_data[1] & !(RUNTIME_DATA_WINDOW - 1),
    ];

    let is_state_page = |address: u64| state_pages.contains(&address);

    let is_data_window_page = |address: u64| {
        data_windows
            .iter()
            .any(|start| (*start..start.saturating_add(RUNTIME_DATA_WINDOW)).contains(&address))
            || is_state_page(address)
            || address == linkage_page
    };

    let arena_start = G::align_down(unsafe { memory.as_ref() }.physical_base());
    let arena_end = unsafe { memory.as_ref() }
        .physical_base()
        .checked_add(unsafe { memory.as_ref() }.byte_len() as u64)
        .ok_or(HarnessError::Memory)?;
    let arena_last = G::align_down(arena_end.saturating_sub(1));

    let is_code_page = |address: u64| {
        code_windows
            .iter()
            .any(|start| (*start..start.saturating_add(code_window)).contains(&address))
            && !is_data_window_page(address)
            && !(arena_start..=arena_last).contains(&address)
    };

    macro_rules! ensure_data_page {
        ($address:expr) => {{
            let address = $address;

            if let Some(mapping) = mapper.translate(WalkInputAddr::new(address)).map_err(|_| {
                HarnessError::TransitionPreparation(TransitionPreparationError::RecoveryInspection)
            })? {
                if mapping.output().0 != address
                    || mapping.level() != Level::L3
                    || *mapping.fields() != data_fields
                {
                    return Err(HarnessError::TransitionPreparation(
                        TransitionPreparationError::RecoveryIdentity,
                    ));
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
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            TransitionPreparationError::CandidateRuntime,
                        )
                    })?;
            }
        }};
    }

    macro_rules! ensure_runtime_stack_page {
        ($input:expr, $output:expr, $fields:expr) => {{
            let input = $input;
            let output = $output;
            let fields = $fields;

            if let Some(mapping) = mapper
                .translate(WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
            {
                if mapping.level() != Level::L3 {
                    return Err(HarnessError::InvalidState);
                }

                if mapping.output().0 != output || *mapping.fields() != fields {
                    unsafe { mapper.unmap(WalkInputAddr::new(input)) }
                        .map_err(|_| HarnessError::InvalidState)?;

                    mapper
                        .map_leaf(
                            WalkInputAddr::new(input),
                            PhysAddr(output),
                            Level::L3,
                            fields,
                            table_fields,
                        )
                        .map_err(|_| HarnessError::InvalidState)?;
                }
            } else {
                mapper
                    .map_leaf(
                        WalkInputAddr::new(input),
                        PhysAddr(output),
                        Level::L3,
                        fields,
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
            .checked_add(code_window)
            .ok_or(HarnessError::Memory)?;

        while address < end {
            if is_code_page(address)
                && address != stack_page
                && address != exception_stack_page
                && !is_state_page(address)
            {
                if let Some(mapping) =
                    mapper.translate(WalkInputAddr::new(address)).map_err(|_| {
                        HarnessError::TransitionPreparation(
                            TransitionPreparationError::RecoveryInspection,
                        )
                    })?
                {
                    if mapping.output().0 != address
                        || mapping.level() != Level::L3
                        || *mapping.fields() != code_fields
                    {
                        return Err(HarnessError::TransitionPreparation(
                            TransitionPreparationError::RecoveryIdentity,
                        ));
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
                        .map_err(|_| {
                            HarnessError::TransitionPreparation(
                                TransitionPreparationError::CandidateRuntime,
                            )
                        })?;
                }
            }

            address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
    }

    if is_code_page(stack_page) || is_state_page(stack_page) {
        return Err(HarnessError::TransitionPreparation(
            TransitionPreparationError::CandidateTableAccess,
        ));
    }

    ensure_runtime_stack_page!(stack_page, stack_physical_page, data_fields);

    if is_code_page(exception_stack_page) || is_state_page(exception_stack_page) {
        return Err(HarnessError::TransitionPreparation(
            TransitionPreparationError::CandidateTableAccess,
        ));
    }

    ensure_runtime_stack_page!(
        exception_stack_page,
        exception_stack_physical_page,
        exception_stack_fields
    );

    for index in 0..state_pages.len() {
        let page = state_pages[index];

        if state_pages[..index].contains(&page) {
            continue;
        }

        ensure_data_page!(page);
    }

    for index in 0..data_windows.len() {
        let start = data_windows[index];

        if data_windows[..index].contains(&start) {
            continue;
        }

        let end = start
            .checked_add(RUNTIME_DATA_WINDOW)
            .ok_or(HarnessError::Memory)?;
        let mut page = start;

        while page < end {
            if page != stack_page
                && page != exception_stack_page
                && !is_code_page(page)
                && !is_state_page(page)
            {
                ensure_data_page!(page);
            }

            page = page.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
    }

    if linkage_page != stack_page
        && linkage_page != exception_stack_page
        && !is_state_page(linkage_page)
    {
        ensure_data_page!(linkage_page);
    }

    let mut address = arena_start;

    while address <= arena_last {
        if address != stack_page && address != exception_stack_page && !is_state_page(address) {
            ensure_data_page!(address);
        }

        address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
    }

    for uart_page in [
        G::align_down(0x1c09_0000),
        G::align_down(0x1c0a_0000),
        G::align_down(0x1c0b_0000),
        G::align_down(0x1c0c_0000),
    ] {
        if !is_code_page(uart_page)
            && !(arena_start..=arena_last).contains(&uart_page)
            && uart_page != stack_page
            && uart_page != exception_stack_page
            && !is_state_page(uart_page)
        {
            ensure_data_page!(uart_page);
        }
    }

    if !vmsa_test_architecture::barriers::clean_data_cache_range(
        unsafe { memory.as_ref() }.virtual_base(),
        unsafe { memory.as_ref() }.byte_len(),
    ) {
        return Err(HarnessError::Environment);
    }

    vmsa_test_architecture::barriers::dsb_ish();
    Ok(())
}
#[doc(hidden)]
pub fn prepare_lower_runtime_d128<R, G>(
    memory: &mut TestMemory,
    setup: TranslationSetup,
    entry: u64,
    stack_top: u64,
    exception_stack_top: u64,
    lower_runtime_state: u64,
) -> Result<(), HarnessError>
where
    R: TranslationRegime,
    G: TestGranule,
    Vmsa128: HasLayout<StageOf<R>, G>,
    <Vmsa128 as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            StageOf<R>,
            G,
            LeafFields = RawVmsa128Stage1LeafAttrs,
            TableFields = RawVmsa128Stage1TableAttrs,
        >,
{
    if setup.format != TranslationFormat::Vmsa128
        || setup.granule != G::GRANULE
        || entry == 0
        || stack_top < 4096
        || exception_stack_top < 4096
        || lower_runtime_state == 0
    {
        return Err(HarnessError::InvalidState);
    }
    let start_level = setup.start_level.ok_or(HarnessError::InvalidState)?;
    let root_address = TableAddr::new(setup.root.get()).map_err(|_| HarnessError::Memory)?;
    let memory = NonNull::from(memory);
    let access = arena_table_access(memory);
    let root = RootTable::new(
        root_address,
        Level::new(start_level.get()),
        setup.input_bits.get(),
        setup.output_bits.get(),
    );
    let mut mapper = Mapper::<Vmsa128, R, G, _, _, Offline>::new_offline(
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
    const CODE_WINDOW: u64 = 1024 * 1024;
    let page_size = G::SIZE;
    let state_window = page_size;
    let code_windows = [
        entry & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::vector_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::exception::runtime_code_address() & !(CODE_WINDOW - 1),
        vmsa_test_architecture::transition::runtime_code_address() & !(CODE_WINDOW - 1),
    ];
    let stack_page = G::align_down(stack_top - 1);
    let exception_stack_page = G::align_down(exception_stack_top - 1);
    let state_windows = [
        G::align_down(vmsa_test_architecture::exception::runtime_state_address()),
        G::align_down(vmsa_test_architecture::transition::runtime_state_address()),
        G::align_down(vmsa_test_architecture::exception::linkage_data_address()),
        G::align_down(lower_runtime_state),
    ];
    let is_state_page = |address: u64| {
        state_windows
            .iter()
            .any(|start| (*start..*start + state_window).contains(&address))
    };
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
    for index in 0..code_windows.len() {
        if code_windows[..index].contains(&code_windows[index]) {
            continue;
        }
        let mut address = code_windows[index];
        let end = address
            .checked_add(CODE_WINDOW)
            .ok_or(HarnessError::Memory)?;
        while address < end {
            if !(arena_start..=arena_last).contains(&address)
                && address != stack_page
                && address != exception_stack_page
                && !is_state_page(address)
            {
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
            address = address.checked_add(page_size).ok_or(HarnessError::Memory)?;
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
    if !is_state_page(exception_stack_page) {
        mapper
            .map_leaf(
                WalkInputAddr::new(exception_stack_page),
                PhysAddr(exception_stack_page),
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
        let end = page.checked_add(state_window).ok_or(HarnessError::Memory)?;
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
            page = page.checked_add(page_size).ok_or(HarnessError::Memory)?;
        }
    }
    let mut address = arena_start;
    while address <= arena_last {
        if address != stack_page && address != exception_stack_page && !is_state_page(address) {
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
        address = address.checked_add(page_size).ok_or(HarnessError::Memory)?;
    }
    for uart_page in [
        G::align_down(0x1c09_0000),
        G::align_down(0x1c0a_0000),
        G::align_down(0x1c0b_0000),
        G::align_down(0x1c0c_0000),
    ] {
        if !is_code_page(uart_page)
            && !(arena_start..=arena_last).contains(&uart_page)
            && uart_page != stack_page
            && uart_page != exception_stack_page
            && !is_state_page(uart_page)
        {
            mapper
                .map_leaf(
                    WalkInputAddr::new(uart_page),
                    PhysAddr(uart_page),
                    Level::L3,
                    data_fields,
                    table_fields,
                )
                .map_err(|_| HarnessError::InvalidState)?;
        }
    }
    if !vmsa_test_architecture::barriers::clean_data_cache_range(
        unsafe { memory.as_ref() }.virtual_base(),
        unsafe { memory.as_ref() }.byte_len(),
    ) {
        return Err(HarnessError::Environment);
    }
    vmsa_test_architecture::barriers::dsb_ish();
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

#[derive(Clone, Copy)]
struct ProbeInvalidation {
    marker: u64,
    events: [u8; 16],
    event_count: usize,
}

impl ProbeInvalidation {
    const LEAF_INSERTED: u8 = 1;
    const LEAF_REMOVED: u8 = 2;
    const TABLE_INSERTED: u8 = 3;
    const TABLE_REMOVED: u8 = 4;
    const BEFORE_RECLAIM: u8 = 5;
    const SYNCHRONIZE: u8 = 6;

    fn record(&mut self, event: u8) {
        if let Some(slot) = self.events.get_mut(self.event_count) {
            *slot = event;
        }
        self.event_count = self.event_count.saturating_add(1);
    }

    fn clear_events(&mut self) {
        self.events = [0; 16];
        self.event_count = 0;
    }

    fn events(&self) -> &[u8] {
        &self.events[..self.event_count.min(self.events.len())]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeAccessError {
    Read,
    Write,
    Inner,
}

struct ProbeTableAccess {
    inner: OffsetTableAccess,
    fail_read: bool,
    fail_write: bool,
}

unsafe impl TableAccess<Vmsa64, Granule4KiB> for ProbeTableAccess {
    type Error = ProbeAccessError;

    fn table_at<'a>(
        &'a self,
        location: aarch64_vmsa::table::TableAccessLocation<'a, Vmsa64, Granule4KiB>,
    ) -> Result<aarch64_vmsa::table::TranslationTable<'a, Vmsa64, Granule4KiB>, Self::Error> {
        if self.fail_read {
            Err(ProbeAccessError::Read)
        } else {
            self.inner
                .table_at(location)
                .map_err(|_| ProbeAccessError::Inner)
        }
    }
}

unsafe impl TableAccessMut<Vmsa64, Granule4KiB> for ProbeTableAccess {
    fn table_at_mut<'a>(
        &'a mut self,
        location: aarch64_vmsa::table::TableAccessLocation<'a, Vmsa64, Granule4KiB>,
    ) -> Result<aarch64_vmsa::table::TranslationTableMut<'a, Vmsa64, Granule4KiB>, Self::Error>
    {
        if self.fail_write {
            Err(ProbeAccessError::Write)
        } else {
            self.inner
                .table_at_mut(location)
                .map_err(|_| ProbeAccessError::Inner)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeFrameError {
    Allocate,
    Free,
    Inner,
}

struct ProbeFrameProvider {
    inner: ArenaFrameProvider,
    fail_allocate: bool,
    fail_free: bool,
}

unsafe impl TableFrameProvider<Granule4KiB> for ProbeFrameProvider {
    type Error = ProbeFrameError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<Granule4KiB>, Self::Error> {
        if self.fail_allocate {
            Err(ProbeFrameError::Allocate)
        } else {
            self.inner
                .allocate_zeroed_table(layout)
                .map_err(|_| ProbeFrameError::Inner)
        }
    }

    fn reclaim_table(
        &mut self,
        reclaim: aarch64_vmsa::table::TableReclaim<Granule4KiB>,
    ) -> Result<(), Self::Error> {
        if self.fail_free {
            Err(ProbeFrameError::Free)
        } else {
            self.inner
                .reclaim_table(reclaim)
                .map_err(|_| ProbeFrameError::Inner)
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum MapperProviderProbe {
    TableRead,
    DescriptorWrite,
    FrameAllocate,
    FrameFree,
}

pub(crate) fn verify_mapper_provider_probe(
    memory: NonNull<TestMemory>,
    root_memory: &mut RootTableMemory,
    probe: MapperProviderProbe,
) -> bool {
    use aarch64_vmsa::config::regime::NonSecureEl2Stage1;
    use aarch64_vmsa::mapper::{Mapper, MapperError, Offline};
    use aarch64_vmsa::translation::walk::WalkInputAddr;

    let root_level = if matches!(
        probe,
        MapperProviderProbe::TableRead | MapperProviderProbe::DescriptorWrite
    ) {
        Level::L3
    } else {
        Level::L0
    };
    let input_bits = if root_level == Level::L3 { 12 } else { 48 };
    let Ok(root_address) = TableAddr::new(root_memory.phys_addr()) else {
        return false;
    };
    let access = ProbeTableAccess {
        inner: arena_table_access(memory),
        fail_read: matches!(probe, MapperProviderProbe::TableRead),
        fail_write: matches!(probe, MapperProviderProbe::DescriptorWrite),
    };
    let frames = ProbeFrameProvider {
        inner: ArenaFrameProvider::new(memory),
        fail_allocate: matches!(probe, MapperProviderProbe::FrameAllocate),
        fail_free: matches!(probe, MapperProviderProbe::FrameFree),
    };
    let root = RootTable::new(root_address, root_level, input_bits, 48);
    let Ok(mut mapper) =
        Mapper::<Vmsa64, NonSecureEl2Stage1, Granule4KiB, _, _, Offline>::new_offline(
            root, access, frames,
        )
    else {
        return false;
    };
    let leaf = match <NonSecureEl2Stage1 as TestRegimeFor<Granule4KiB>>::raw_leaf(
        MappingAttributes::READ_WRITE,
    ) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let table = match <NonSecureEl2Stage1 as TestRegimeFor<Granule4KiB>>::raw_table() {
        Ok(value) => value,
        Err(_) => return false,
    };
    match probe {
        MapperProviderProbe::TableRead => matches!(
            mapper.translate(WalkInputAddr::new(0)),
            Err(MapperError::Access(ProbeAccessError::Read))
        ),
        MapperProviderProbe::DescriptorWrite => {
            mapper.map_leaf(WalkInputAddr::new(0), PhysAddr(0), Level::L3, leaf, table)
                == Err(MapperError::Access(ProbeAccessError::Write))
        }
        MapperProviderProbe::FrameAllocate => {
            mapper.map_leaf(WalkInputAddr::new(0), PhysAddr(0), Level::L3, leaf, table)
                == Err(MapperError::Frame(ProbeFrameError::Allocate))
        }
        MapperProviderProbe::FrameFree => {
            if mapper
                .map_leaf(WalkInputAddr::new(0), PhysAddr(0), Level::L3, leaf, table)
                .is_err()
            {
                return false;
            }
            matches!(
                unsafe { mapper.unmap_reclaim(WalkInputAddr::new(0)) },
                Err(MapperError::Frame(ProbeFrameError::Free))
            )
        }
    }
}

unsafe impl<F, G> aarch64_vmsa::mapper::MapperInvalidation<F, G> for ProbeInvalidation
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn leaf_inserted(
        &mut self,
        _: aarch64_vmsa::table::TableAccessLocation<F, G>,
        _: usize,
        _: F::Raw,
        _: F::Raw,
    ) {
        self.record(Self::LEAF_INSERTED);
    }
    fn leaf_removed(
        &mut self,
        _: aarch64_vmsa::table::TableAccessLocation<F, G>,
        _: usize,
        _: F::Raw,
    ) {
        self.record(Self::LEAF_REMOVED);
    }
    fn table_descriptor_inserted(
        &mut self,
        _: aarch64_vmsa::table::TableAccessLocation<F, G>,
        _: usize,
        _: F::Raw,
        _: F::Raw,
    ) {
        self.record(Self::TABLE_INSERTED);
    }
    fn table_descriptor_removed(
        &mut self,
        _: aarch64_vmsa::table::TableAccessLocation<F, G>,
        _: usize,
        _: F::Raw,
    ) {
        self.record(Self::TABLE_REMOVED);
    }
    fn before_table_frame_reclaim(&mut self, _: TableAddr<G>, _: TableAllocLayout) {
        self.record(Self::BEFORE_RECLAIM);
    }
    fn synchronize(&mut self) {
        self.record(Self::SYNCHRONIZE);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapperConstructionError {
    UnalignedRoot {
        address: u64,
        align: u64,
    },
    InvalidRootLevel {
        root_level: i8,
        lowest_level: i8,
        final_level: i8,
    },
    InvalidRootAddressBits {
        addr_bits: u8,
        max_addr_bits: u8,
    },
    InvalidConfiguredOutputAddressBits {
        output_address_bits: u8,
        format_max_bits: u8,
    },
    RootAddressOutOfRange {
        address: u64,
        output_address_bits: u8,
    },
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapperOperationError {
    AccessProvider(aarch64_vmsa::table::AccessError),
    FrameProvider(crate::MemoryError),
    AccessLocation(aarch64_vmsa::table::AccessError),
    Table(aarch64_vmsa::table::TableError),
    TableAddress(aarch64_vmsa::table::TableAddressError),
    Descriptor(aarch64_vmsa::descriptor::DescriptorError),
    Cursor(aarch64_vmsa::translation::walk::WalkCursorError),
    InvalidLeafLevel {
        level: i8,
        root_level: i8,
        final_level: i8,
    },
    InputAddressOutOfRange {
        address: u64,
        address_bits: u8,
    },
    AddressOverflow,
    InvalidLevel {
        level: i8,
    },
    OutputAddressOverflow {
        base: u64,
        offset: u64,
    },
    OutputAddressOutOfRange {
        address: u64,
        output_address_bits: u8,
    },
    TableAddressOutOfRange {
        address: u64,
        output_address_bits: u8,
    },
    UnalignedInput {
        address: u64,
        align: u64,
    },
    UnalignedOutput {
        address: u64,
        align: u64,
    },
    InputNotLeafBase {
        input: u64,
        covered_input_base: u64,
        covered_size: u64,
        level: i8,
    },
    AlreadyMapped {
        input: u64,
        level: i8,
        entry_index: usize,
    },
    NotMapped {
        input: u64,
    },
    Unexpected,
}

fn normalize_mapper_operation_error(
    error: aarch64_vmsa::mapper::MapperError<aarch64_vmsa::table::AccessError, crate::MemoryError>,
) -> MapperOperationError {
    use aarch64_vmsa::mapper::MapperError;
    match error {
        MapperError::Access(error) => MapperOperationError::AccessProvider(error),
        MapperError::Frame(error) => MapperOperationError::FrameProvider(error),
        MapperError::AccessLocation(error) => MapperOperationError::AccessLocation(error),
        MapperError::Table(error) => MapperOperationError::Table(error),
        MapperError::TableAddress(error) => MapperOperationError::TableAddress(error),
        MapperError::Descriptor(error) => MapperOperationError::Descriptor(error),
        MapperError::Cursor(error) => MapperOperationError::Cursor(error),
        MapperError::InvalidLeafLevel {
            level,
            root_level,
            final_level,
        } => MapperOperationError::InvalidLeafLevel {
            level: level.as_i8(),
            root_level: root_level.as_i8(),
            final_level: final_level.as_i8(),
        },
        MapperError::InputAddressOutOfRange { addr, addr_bits } => {
            MapperOperationError::InputAddressOutOfRange {
                address: addr,
                address_bits: addr_bits,
            }
        }
        MapperError::AddressOverflow => MapperOperationError::AddressOverflow,
        MapperError::InvalidLevel { level } => MapperOperationError::InvalidLevel {
            level: level.as_i8(),
        },
        MapperError::OutputAddressOverflow { base, offset } => {
            MapperOperationError::OutputAddressOverflow {
                base: base.0,
                offset,
            }
        }
        MapperError::OutputAddressOutOfRange {
            addr,
            output_address_bits,
        } => MapperOperationError::OutputAddressOutOfRange {
            address: addr.0,
            output_address_bits,
        },
        MapperError::TableAddressOutOfRange {
            addr,
            output_address_bits,
        } => MapperOperationError::TableAddressOutOfRange {
            address: addr,
            output_address_bits,
        },
        MapperError::UnalignedInput { addr, align } => MapperOperationError::UnalignedInput {
            address: addr,
            align,
        },
        MapperError::UnalignedOutput { addr, align } => MapperOperationError::UnalignedOutput {
            address: addr.0,
            align,
        },
        MapperError::InputNotLeafBase {
            input,
            covered_input_base,
            covered_size,
            level,
        } => MapperOperationError::InputNotLeafBase {
            input: input.raw(),
            covered_input_base,
            covered_size,
            level: level.as_i8(),
        },
        MapperError::AlreadyMapped {
            input,
            level,
            entry_index,
        } => MapperOperationError::AlreadyMapped {
            input: input.raw(),
            level: level.as_i8(),
            entry_index,
        },
        MapperError::NotMapped { input } => MapperOperationError::NotMapped { input: input.raw() },
        MapperError::WalkPathEntryNotTable { .. }
        | MapperError::InvalidRootLevel { .. }
        | MapperError::InvalidRootAddressBits { .. }
        | MapperError::InvalidConfiguredOutputAddressBits { .. } => {
            MapperOperationError::Unexpected
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapLeafResult {
    pub tables_allocated: u8,
    pub level: LookupLevel,
    pub kind: WalkDescriptorKind,
    pub covered_size: u64,
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
    pub fn table_geometry(&self) -> aarch64_vmsa::table::TableGeometry<F, G> {
        self.inner.table_geometry()
    }

    pub fn map_semantic_leaf<Cfg>(
        &mut self,
        config: &Cfg,
        input: u64,
        output: u64,
        level: LookupLevel,
        leaf: <F as AttributeCodecCompat<R, G, Cfg>>::SemanticLeaf,
        table: <F as AttributeCodecCompat<R, G, Cfg>>::SemanticTable,
    ) -> Result<(), HarnessError>
    where
        F: AttributeCodecCompat<
                R,
                G,
                Cfg,
                RawLeaf = LeafFieldsOf<F, R, G>,
                RawTable = TableFieldsOf<F, R, G>,
            >,
        LeafFieldsOf<F, R, G>: Copy,
    {
        self.inner
            .map_semantic_leaf::<Cfg>(
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
                aarch64_vmsa::mapper::SemanticMapperError::Mapper(_) => {
                    HarnessError::CrateBehavior {
                        expected: 1,
                        actual: 0,
                    }
                }
            })
    }

    pub fn isolated_malformed_table(&mut self) -> IsolatedMalformedTable<'_, R, G, F> {
        IsolatedMalformedTable { mapper: self }
    }

    pub fn inspect_semantic_leaf<Cfg>(
        &mut self,
        input: u64,
        config: &Cfg,
    ) -> Result<Option<<F as AttributeCodecCompat<R, G, Cfg>>::SemanticLeaf>, HarnessError>
    where
        F: AttributeCodecCompat<
                R,
                G,
                Cfg,
                RawLeaf = LeafFieldsOf<F, R, G>,
                RawTable = TableFieldsOf<F, R, G>,
            >,
        LeafFieldsOf<F, R, G>: Copy,
    {
        let mapping = self
            .inner
            .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
            .map_err(|_| HarnessError::InvalidState)?;
        mapping
            .map(|mapping| {
                aarch64_vmsa::mapper::decode_semantic_leaf::<F, R, G, Cfg>(
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
        let (cursor, entry_index, original) = {
            let walker = Walker::<F, R, G, _>::new(root, self.mapper.inner.access())
                .map_err(|_| HarnessError::InvalidState)?;
            match walker
                .start_at(WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
                .finish()
                .map_err(|_| HarnessError::InvalidState)?
            {
                aarch64_vmsa::translation::walk::WalkOutcome::Leaf(leaf) => {
                    (leaf.cursor().table(), leaf.entry_index(), Some(leaf.raw()))
                }
                aarch64_vmsa::translation::walk::WalkOutcome::Invalid(invalid) => {
                    (invalid.cursor().table(), invalid.entry_index(), None)
                }
            }
        };
        let replacement = F::raw_descriptor(replacement).ok_or(HarnessError::InvalidState)?;
        let address = self
            .mapper
            .inner
            .access()
            .offset()
            .0
            .checked_add(cursor.current().raw())
            .ok_or(HarnessError::InvalidState)?;
        let pointer = NonNull::new(address as *mut F::Raw).ok_or(HarnessError::InvalidState)?;
        // SAFETY: The isolated mapper owns the live arena table identified by
        // the crate-produced cursor, and no table borrow survives this point.
        let mut table = unsafe {
            aarch64_vmsa::table::TranslationTableMut::from_raw_parts(pointer, cursor.shape())
        };
        let original = original
            .or_else(|| table.read(entry_index))
            .ok_or(HarnessError::InvalidState)?;
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
    root: RootTable<F, R, G>,
    access: &A,
    input: u64,
) -> Result<WalkInspection, HarnessError>
where
    R: TranslationRegime,
    G: TestGranule,
    F: TestFormat + HasLayout<StageOf<R>, G>,
    A: TableAccess<F, G>,
{
    let walker = Walker::<F, R, G, _>::new(root, access).map_err(|_| HarnessError::InvalidState)?;
    let mut walk = walker
        .start_at(WalkInputAddr::new(input))
        .map_err(|_| HarnessError::InvalidState)?;
    let mut inspection = WalkInspection {
        steps: [None; 6],
        length: 0,
    };
    loop {
        match walk.step().map_err(|_| HarnessError::InvalidState)? {
            WalkEntry::Invalid(invalid) => {
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
            WalkEntry::Leaf(leaf) => {
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
                    output: Some(
                        walk.output(&leaf)
                            .map_err(|_| HarnessError::InvalidState)?
                            .0,
                    ),
                })?;
                return Ok(inspection);
            }
            WalkEntry::Table(table) => {
                inspection.push(WalkDescriptorInspection {
                    level: LookupLevel::new(table.level().as_i8())
                        .ok_or(HarnessError::InvalidState)?,
                    entry_index: table.entry_index(),
                    kind: WalkDescriptorKind::Table,
                    raw: Some(F::descriptor_bits(table.raw())),
                    next_table: Some(table.next().raw()),
                    output: None,
                })?;
                walk.step_in(table)
                    .map_err(|_| HarnessError::InvalidState)?;
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
    pub fn verify_offline_accessors_into_parts(self) -> bool {
        let expected_root = self.inner.root();
        let expected_offset = self.inner.access().offset();
        let expected_memory = self.inner.frames().memory();
        let (root, access, frames) = self.inner.into_parts();
        root.addr().raw() == expected_root.addr().raw()
            && root.level() == expected_root.level()
            && root.addr_bits() == expected_root.addr_bits()
            && root.output_addr_bits() == expected_root.output_addr_bits()
            && access.offset() == expected_offset
            && frames.memory() == expected_memory
    }

    pub fn verify_live_accessors_into_parts(self) -> bool
    where
        F: aarch64_vmsa::descriptor::SupportsLiveDescriptorIo,
    {
        let (root, access, frames) = self.inner.into_parts();
        let expected_root = root;
        let expected_offset = access.offset();
        let expected_memory = frames.memory();
        let Ok(mut mapper) = Mapper::<F, R, G, _, _, aarch64_vmsa::mapper::Live<_>>::new_live(
            root,
            access,
            frames,
            ProbeInvalidation {
                marker: 0x51a7_e001,
                events: [0; 16],
                event_count: 0,
            },
        ) else {
            return false;
        };
        if mapper.root().addr().raw() != expected_root.addr().raw()
            || mapper.root().level() != expected_root.level()
            || mapper.root().addr_bits() != expected_root.addr_bits()
            || mapper.root().output_addr_bits() != expected_root.output_addr_bits()
            || mapper.access().offset() != expected_offset
            || mapper.frames().memory() != expected_memory
            || mapper.invalidation().marker != 0x51a7_e001
        {
            return false;
        }
        let (root, access, frames, mut invalidation) = mapper.into_parts();
        invalidation.marker = 0x51a7_e002;
        root.addr().raw() == expected_root.addr().raw()
            && root.level() == expected_root.level()
            && root.addr_bits() == expected_root.addr_bits()
            && root.output_addr_bits() == expected_root.output_addr_bits()
            && access.offset() == expected_offset
            && frames.memory() == expected_memory
            && invalidation.marker == 0x51a7_e002
    }

    pub(crate) fn validate_new(
        memory: NonNull<TestMemory>,
        root: &crate::RootTableMemory,
        start_level: Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<(), MapperConstructionError> {
        Self::validate_new_at(
            memory,
            root.phys_addr(),
            start_level,
            input_bits,
            output_bits,
        )
    }

    pub(crate) fn validate_new_at(
        memory: NonNull<TestMemory>,
        root_address: u64,
        start_level: Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<(), MapperConstructionError> {
        let root_address = TableAddr::new(root_address).map_err(|error| match error {
            aarch64_vmsa::table::TableAddressError::Unaligned { addr, align } => {
                MapperConstructionError::UnalignedRoot {
                    address: addr,
                    align,
                }
            }
        })?;
        let access = arena_table_access(memory);
        let geometry = aarch64_vmsa::table::RootTableGeometry::<F, G>::new_at_level(
            root_address,
            start_level,
            input_bits,
            output_bits,
        )
        .map_err(|error| match error {
            aarch64_vmsa::table::RootGeometryError::InvalidLevel => {
                MapperConstructionError::InvalidRootLevel {
                    root_level: start_level.as_i8(),
                    lowest_level: F::EXTENDED_LOWEST_ROOT_LEVEL.as_i8(),
                    final_level: F::FINAL_LEVEL.as_i8(),
                }
            }
            aarch64_vmsa::table::RootGeometryError::InvalidInputAddressBits {
                requested,
                maximum,
            } => MapperConstructionError::InvalidRootAddressBits {
                addr_bits: requested,
                max_addr_bits: maximum,
            },
            aarch64_vmsa::table::RootGeometryError::InvalidOutputAddressBits {
                requested,
                maximum,
            } => MapperConstructionError::InvalidConfiguredOutputAddressBits {
                output_address_bits: requested,
                format_max_bits: maximum,
            },
            aarch64_vmsa::table::RootGeometryError::TableAddressOutOfRange => {
                MapperConstructionError::RootAddressOutOfRange {
                    address: root_address.raw(),
                    output_address_bits: output_bits,
                }
            }
        })?;
        let root = RootTable::from_geometry(geometry);
        Mapper::<F, R, G, _, _, Offline>::new_offline(root, access, ArenaFrameProvider::new(memory))
            .map(|_| ())
            .map_err(|error| match error {
                aarch64_vmsa::mapper::MapperError::InvalidRootLevel {
                    root_level,
                    lowest_level,
                    final_level,
                } => MapperConstructionError::InvalidRootLevel {
                    root_level: root_level.as_i8(),
                    lowest_level: lowest_level.as_i8(),
                    final_level: final_level.as_i8(),
                },
                aarch64_vmsa::mapper::MapperError::InvalidRootAddressBits {
                    addr_bits,
                    max_addr_bits,
                } => MapperConstructionError::InvalidRootAddressBits {
                    addr_bits,
                    max_addr_bits,
                },
                aarch64_vmsa::mapper::MapperError::InvalidConfiguredOutputAddressBits {
                    output_address_bits,
                    format_max_bits,
                } => MapperConstructionError::InvalidConfiguredOutputAddressBits {
                    output_address_bits,
                    format_max_bits,
                },
                aarch64_vmsa::mapper::MapperError::OutputAddressOutOfRange {
                    addr,
                    output_address_bits,
                } => MapperConstructionError::RootAddressOutOfRange {
                    address: addr.0,
                    output_address_bits,
                },
                aarch64_vmsa::mapper::MapperError::TableAddressOutOfRange {
                    addr,
                    output_address_bits,
                } => MapperConstructionError::RootAddressOutOfRange {
                    address: addr,
                    output_address_bits,
                },
                _ => MapperConstructionError::Unexpected,
            })
    }

    pub(crate) fn new(
        memory: NonNull<TestMemory>,
        root: &crate::RootTableMemory,
        start_level: Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<Self, HarnessError> {
        let root_address = TableAddr::new(root.phys_addr()).map_err(|_| HarnessError::Memory)?;
        // SAFETY: TestMemory guarantees a constant physical-to-virtual offset.
        let offset = unsafe { memory.as_ref() }.physical_to_virtual_offset();
        // SAFETY: The offset maps every arena physical address to its reserved VA.
        let access = arena_table_access(memory);
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
            StageOf<R>,
            G,
            LeafFields = LeafFieldsOf<Vmsa64, R, G>,
            TableFields = TableFieldsOf<Vmsa64, R, G>,
        >,
    LeafFieldsOf<Vmsa64, R, G>: Copy,
{
    pub(crate) fn mapping_matches_attributes(
        &self,
        input: u64,
        output: u64,
        attributes: MappingAttributes,
    ) -> Result<bool, HarnessError>
    where
        LeafFieldsOf<Vmsa64, R, G>: PartialEq,
    {
        let expected = R::raw_leaf_for_format(attributes, F::FORMAT)?;
        self.inner
            .translate(WalkInputAddr::new(input))
            .map(|mapping| {
                mapping.is_some_and(|mapping| {
                    mapping.output().0 == output
                        && mapping.level() == Level::L3
                        && *mapping.fields() == expected
                })
            })
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn verify_break_before_make_ordering(self) -> bool
    where
        F: aarch64_vmsa::descriptor::SupportsLiveDescriptorIo,
    {
        let Ok(leaf) = R::raw_leaf(MappingAttributes::READ_WRITE) else {
            return false;
        };
        let Ok(table) = R::raw_table() else {
            return false;
        };
        let (root, access, frames) = self.inner.into_parts();
        let Ok(mut mapper) = Mapper::<F, R, G, _, _, aarch64_vmsa::mapper::Live<_>>::new_live(
            root,
            access,
            frames,
            ProbeInvalidation {
                marker: 0,
                events: [0; 16],
                event_count: 0,
            },
        ) else {
            return false;
        };
        if mapper
            .map_leaf(WalkInputAddr::new(0), PhysAddr(0), Level::L3, leaf, table)
            .is_err()
        {
            return false;
        }
        let (root, access, frames, mut invalidation) = mapper.into_parts();
        invalidation.clear_events();
        let Ok(mut mapper) = Mapper::new_live(root, access, frames, invalidation) else {
            return false;
        };
        if unsafe { mapper.unmap(WalkInputAddr::new(0)) }.is_err()
            || mapper
                .map_leaf(WalkInputAddr::new(0), PhysAddr(0), Level::L3, leaf, table)
                .is_err()
        {
            return false;
        }
        mapper.invalidation().events()
            == [
                ProbeInvalidation::LEAF_REMOVED,
                ProbeInvalidation::SYNCHRONIZE,
                ProbeInvalidation::LEAF_INSERTED,
                ProbeInvalidation::SYNCHRONIZE,
            ]
    }

    pub(crate) fn prepare_current_runtime(
        &mut self,
        entry: u64,
        payload_data: [u64; 4],
        sandbox_regions: &[(u64, u64)],
        user_accessible: bool,
    ) -> Result<(), HarnessError>
    where
        LeafFieldsOf<Vmsa64, R, G>: PartialEq,
    {
        const CODE_WINDOW: u64 = 1024 * 1024;
        const LINKAGE_DATA_PREFIX: u64 = 256 * 1024;
        const LINKAGE_DATA_WINDOW: u64 = LINKAGE_DATA_PREFIX + 64 * 1024;
        const LINKED_RUNTIME_DATA_WINDOW: u64 = 64 * 1024;
        let leaf_level = LookupLevel::new(3).ok_or(HarnessError::InvalidState)?;
        let memory = self.inner.frames().memory();
        let arena_start = G::align_down(unsafe { memory.as_ref() }.physical_base());
        let arena_end = unsafe { memory.as_ref() }
            .physical_base()
            .checked_add(unsafe { memory.as_ref() }.byte_len() as u64)
            .ok_or(HarnessError::Memory)?;
        let stack_pointer = vmsa_test_architecture::registers::stack_pointer();
        let stack = G::align_down(stack_pointer);
        let (stack_start, stack_end) = if G::SIZE == 64 * 1024 {
            (
                stack.saturating_sub(G::SIZE),
                stack.saturating_add(2 * G::SIZE),
            )
        } else {
            (
                stack.saturating_sub(R::CURRENT_STACK_WINDOW),
                stack.saturating_add(R::CURRENT_STACK_WINDOW),
            )
        };
        let runtime_code_addresses = [
            entry,
            vmsa_test_architecture::exception::vector_address(),
            vmsa_test_architecture::exception::recovery_vector_address(),
            vmsa_test_architecture::exception::runtime_code_address(),
            vmsa_test_architecture::transition::runtime_code_address(),
            payload_data[1],
            payload_data[3],
        ];
        let code_regions = runtime_code_addresses.map(|address| address & !(CODE_WINDOW - 1));
        const PRIVILEGED_CODE_WINDOW: u64 = 64 * 1024;
        let privileged_code_regions = [
            vmsa_test_architecture::exception::vector_address() & !(PRIVILEGED_CODE_WINDOW - 1),
            vmsa_test_architecture::exception::recovery_vector_address()
                & !(PRIVILEGED_CODE_WINDOW - 1),
        ];
        let runtime_data_addresses = [
            payload_data[0],
            vmsa_test_architecture::exception::runtime_state_address(),
            vmsa_test_architecture::transition::runtime_state_address(),
            vmsa_test_architecture::exception::linkage_data_address(),
            payload_data[2],
            0x1c09_0000,
            0x1c0a_0000,
            0x1c0b_0000,
            0x1c0c_0000,
        ];
        let data_pages = runtime_data_addresses.map(|address| G::align_down(address));
        let linked_runtime_data_regions = [
            vmsa_test_architecture::exception::runtime_state_address()
                & !(LINKED_RUNTIME_DATA_WINDOW - 1),
            vmsa_test_architecture::transition::runtime_state_address()
                & !(LINKED_RUNTIME_DATA_WINDOW - 1),
        ];
        let runtime_tail_start = code_regions[0]
            .checked_add(CODE_WINDOW)
            .ok_or(HarnessError::Memory)?;
        let runtime_tail_end = vmsa_test_architecture::exception::linkage_data_address();
        let is_linked_runtime_data = |address: u64| {
            linked_runtime_data_regions.iter().any(|start| {
                (*start..start.saturating_add(LINKED_RUNTIME_DATA_WINDOW)).contains(&address)
            })
        };
        // Payloads can place writable runtime state either before or after
        // executable text. Map each known code window independently instead of
        // inferring a single code span from the relative section order.
        for index in 0..code_regions.len() {
            if runtime_code_addresses[index] == 0 {
                continue;
            }
            let start = code_regions[index];
            if runtime_code_addresses[..index]
                .iter()
                .enumerate()
                .any(|(previous, address)| *address != 0 && code_regions[previous] == start)
            {
                continue;
            }
            let window_end = start.checked_add(CODE_WINDOW).ok_or(HarnessError::Memory)?;
            let end = linked_runtime_data_regions
                .iter()
                .copied()
                .filter(|data_start| *data_start > start && *data_start < window_end)
                .min()
                .unwrap_or(window_end);
            let mut address = start;
            while address < end {
                let sandbox_data = sandbox_regions.iter().any(|(input, _)| *input == address);
                if !(stack_start..stack_end).contains(&address)
                    && !(arena_start..arena_end).contains(&address)
                    && !data_pages.contains(&address)
                    && !is_linked_runtime_data(address)
                    && !sandbox_data
                {
                    self.map_attributes_leaf(
                        address,
                        address,
                        leaf_level,
                        MappingAttributes {
                            writable: !user_accessible && R::MUTABLE_FIRMWARE_CODE,
                            executable: true,
                            user_accessible: user_accessible
                                && !privileged_code_regions.iter().any(|start| {
                                    (*start..*start + PRIVILEGED_CODE_WINDOW).contains(&address)
                                }),
                        },
                    )
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::VmsaRuntimeCode,
                        )
                    })?;
                }
                address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        // Compiler-generated constants and lookup tables can land after the
        // fixed executable window but before relocation-backed linkage data.
        // Keep that linked-image tail available to privileged helpers.
        let mut address = G::align_down(runtime_tail_start);
        while address < runtime_tail_end {
            if !(stack_start..stack_end).contains(&address)
                && !(arena_start..arena_end).contains(&address)
                && !data_pages.contains(&address)
                && !is_linked_runtime_data(address)
                && !sandbox_regions.iter().any(|(input, _)| *input == address)
                && self
                    .inner
                    .translate(WalkInputAddr::new(address))
                    .map_err(|_| HarnessError::InvalidState)?
                    .is_none()
            {
                self.map_attributes_leaf(
                    address,
                    address,
                    leaf_level,
                    MappingAttributes {
                        writable: false,
                        executable: false,
                        user_accessible: false,
                    },
                )
                .map_err(|_| {
                    HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::VmsaRuntimeLinkageData,
                    )
                })?;
            }
            address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
        // Compiler support globals (for example the stack protector) share a
        // bounded linked data neighborhood with the exception runtime state.
        // They are accessed by privileged transition and recovery code, so
        // mapping them as EL0 code would make PAN turn ordinary helper calls
        // into recursive faults.
        for index in 0..linked_runtime_data_regions.len() {
            let start = linked_runtime_data_regions[index];
            if linked_runtime_data_regions[..index].contains(&start) {
                continue;
            }
            let end = start
                .checked_add(LINKED_RUNTIME_DATA_WINDOW)
                .ok_or(HarnessError::Memory)?;
            let mut address = start;
            while address < end {
                if !(stack_start..stack_end).contains(&address)
                    && !(arena_start..arena_end).contains(&address)
                    && !sandbox_regions.iter().any(|(input, _)| *input == address)
                {
                    self.map_attributes_leaf(
                        address,
                        address,
                        leaf_level,
                        MappingAttributes {
                            writable: true,
                            executable: false,
                            user_accessible: false,
                        },
                    )
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::VmsaRuntimeData,
                        )
                    })?;
                }
                address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        // Keep the relocation-backed linkage window readable as privileged
        // data regardless of whether the linker places it before or after text.
        for start in [G::align_down(
            vmsa_test_architecture::exception::linkage_data_address()
                .saturating_sub(LINKAGE_DATA_PREFIX),
        )] {
            let end = start
                .checked_add(LINKAGE_DATA_WINDOW)
                .ok_or(HarnessError::Memory)?;
            let mut address = start;
            while address < end {
                if !(stack_start..stack_end).contains(&address)
                    && !sandbox_regions.iter().any(|(input, _)| *input == address)
                    && self
                        .inner
                        .translate(WalkInputAddr::new(address))
                        .map_err(|_| HarnessError::InvalidState)?
                        .is_none()
                {
                    self.map_attributes_leaf(
                        address,
                        address,
                        leaf_level,
                        MappingAttributes {
                            writable: true,
                            executable: false,
                            user_accessible: false,
                        },
                    )
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::VmsaRuntimeLinkageData,
                        )
                    })?;
                }
                address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        let mut address = stack_start;
        while address < stack_end {
            let Some(par) = vmsa_test_architecture::translation::current_stage1(
                address,
                vmsa_test_architecture::translation::TranslationAccess::Write,
            ) else {
                return Err(HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::VmsaRuntimeStack,
                ));
            };
            if par & 1 != 0 {
                // Firmware is not required to map the entire conservative
                // stack window. Preserve every live page it does map, while
                // requiring the page containing the current SP itself.
                if address == stack {
                    return Err(HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::VmsaRuntimeStack,
                    ));
                }
                address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
                continue;
            }
            // Preserve the live virtual-to-physical stack relationship. Some
            // firmware (notably Hafnium) executes payload text at an identity
            // address while keeping SP in a high virtual window. Mapping that
            // window to itself creates an invalid output address and makes the
            // first exception recurse in the vector prologue.
            let physical = (par & 0x000f_ffff_ffff_f000) | (address & 0xfff);
            self.map_attributes_leaf(
                address,
                physical,
                leaf_level,
                MappingAttributes {
                    writable: true,
                    executable: false,
                    // Current-EL exception entry can set PAN before the vector
                    // prologue touches this stack. Keep the current-EL stack
                    // privileged even when the candidate also serves EL0.
                    user_accessible: false,
                },
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::VmsaRuntimeStack,
                )
            })?;
            address = address.checked_add(G::SIZE).ok_or(HarnessError::Memory)?;
        }
        for index in 0..data_pages.len() {
            if runtime_data_addresses[index] == 0 {
                continue;
            }
            let address = data_pages[index];
            if runtime_data_addresses[..index]
                .iter()
                .enumerate()
                .any(|(previous, source)| *source != 0 && data_pages[previous] == address)
            {
                continue;
            }
            // A coarse candidate granule can place runtime data in the same
            // leaf as the active stack.  The stack loop has already installed
            // the required read/write, non-executable identity mapping.
            if (stack_start..stack_end).contains(&address) {
                continue;
            }
            if sandbox_regions.iter().any(|(input, _)| *input == address) {
                continue;
            }
            if is_linked_runtime_data(address) {
                continue;
            }
            let contains_code = runtime_code_addresses
                .iter()
                .any(|code| *code != 0 && G::align_down(*code) == address);
            let privileged_code = privileged_code_regions
                .iter()
                .any(|start| (*start..*start + PRIVILEGED_CODE_WINDOW).contains(&address));
            let attributes = MappingAttributes {
                writable: true,
                // A coarse granule can contain both runtime data and payload
                // code. Its leaf must satisfy both occupants: EL2 needs to
                // update the state while EL0 still needs to execute the code
                // sharing that leaf.
                executable: contains_code,
                user_accessible: user_accessible
                    && (contains_code || address == (payload_data[2] & !(G::SIZE - 1)))
                    && !privileged_code,
            };
            let expected_fields = R::raw_leaf_for_format(attributes, F::FORMAT)?;
            if let Some(mapping) = self
                .inner
                .translate(WalkInputAddr::new(address))
                .map_err(|_| HarnessError::InvalidState)?
            {
                // Linked-state/linkage windows can already have installed the
                // same runtime-data page. Accept only the exact identity leaf
                // with the attributes required here; any other overlap is a
                // genuine candidate-construction conflict.
                if mapping.output().0 != address
                    || mapping.level() != Level::L3
                    || *mapping.fields() != expected_fields
                {
                    return Err(HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::VmsaRuntimeDataPage,
                    ));
                }
            } else {
                self.map_attributes_leaf(address, address, leaf_level, attributes)
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::VmsaRuntimeDataPage,
                        )
                    })?;
            }
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
                self.map_attributes_leaf(
                    input,
                    output,
                    leaf_level,
                    MappingAttributes {
                        writable: true,
                        executable: false,
                        user_accessible,
                    },
                )
                .map_err(|_| {
                    HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::VmsaRuntimeSandbox,
                    )
                })?;
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
                            R::raw_leaf_for_format(MappingAttributes::READ_WRITE, F::FORMAT)?,
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
        // Offline mapper writes are ordinary data accesses.  A candidate
        // translation can select different walk-cacheability controls from
        // the firmware regime, so barriers alone do not guarantee that the
        // table walker observes the completed hierarchy.  Publish every table
        // allocation after the fixed point, including frames allocated while
        // mapping earlier table frames.
        let allocation_count = unsafe { memory.as_ref() }.allocation_count();
        for allocation in 0..allocation_count {
            let Some(region) = unsafe { memory.as_ref() }.table_allocation_region(allocation)
            else {
                continue;
            };
            if !vmsa_test_architecture::barriers::clean_data_cache_range(
                region.virtual_address,
                region.bytes,
            ) {
                return Err(HarnessError::Environment);
            }
        }
        if !vmsa_test_architecture::barriers::clean_data_cache_range(
            unsafe { memory.as_ref() }.virtual_base(),
            unsafe { memory.as_ref() }.byte_len(),
        ) {
            return Err(HarnessError::Environment);
        }
        vmsa_test_architecture::barriers::dsb_ish();
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
                R::raw_leaf_for_format(attributes, F::FORMAT)?,
                R::raw_table()?,
            )
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_attributes_leaf_exact(
        &mut self,
        input: u64,
        output: u64,
        level: i8,
        attributes: MappingAttributes,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let leaf = R::raw_leaf(attributes).map_err(|_| MapperOperationError::Unexpected)?;
        let table = R::raw_table().map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level),
                leaf,
                table,
            )
            .map(|outcome| MapLeafResult {
                tables_allocated: outcome.tables_allocated(),
                level: LookupLevel::new(outcome.level().as_i8())
                    .expect("mapper leaf levels are architectural"),
                kind: match outcome.kind() {
                    aarch64_vmsa::translation::walk::WalkLeafKind::Block => {
                        WalkDescriptorKind::Block
                    }
                    aarch64_vmsa::translation::walk::WalkLeafKind::Page => WalkDescriptorKind::Page,
                },
                covered_size: outcome.covered_size(),
            })
            .map_err(normalize_mapper_operation_error)
    }

    pub fn unmap_exact(&mut self, input: u64) -> Result<MappingInspection, MapperOperationError> {
        unsafe { self.inner.unmap(WalkInputAddr::new(input)) }
            .map(|outcome| MappingInspection {
                output: outcome.old().output().0,
                level: LookupLevel::new(outcome.old().level().as_i8())
                    .expect("mapper leaf levels are architectural"),
            })
            .map_err(normalize_mapper_operation_error)
    }

    pub fn unmap_reclaim_exact(&mut self, input: u64) -> Result<UnmapResult, MapperOperationError> {
        unsafe { self.inner.unmap_reclaim(WalkInputAddr::new(input)) }
            .map(|outcome| UnmapResult {
                mapping: MappingInspection {
                    output: outcome.old().output().0,
                    level: LookupLevel::new(outcome.old().level().as_i8())
                        .expect("mapper leaf levels are architectural"),
                },
                tables_freed: outcome.tables_freed(),
                root_now_empty: outcome.root_now_empty(),
            })
            .map_err(normalize_mapper_operation_error)
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

impl<R: TestRegime, G: TestGranule> TestMapper<R, G, Vmsa128>
where
    Vmsa128: HasLayout<StageOf<R>, G>,
    <Vmsa128 as HasLayout<StageOf<R>, G>>::Layout: DescriptorLayout<
            StageOf<R>,
            G,
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
            D128MappingPermissions::ReadWriteExecute => 2,
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
        permissions: D128MappingPermissions,
    ) -> Result<(RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs), HarnessError> {
        Self::d128_fields_with_state(permissions, true, true)
    }

    fn map_d128_runtime_page(
        &mut self,
        input: u64,
        output: u64,
        permissions: D128MappingPermissions,
    ) -> Result<(), HarnessError> {
        if let Some(mapping) = self
            .inner
            .translate(WalkInputAddr::new(input))
            .map_err(|_| HarnessError::InvalidState)?
        {
            return if mapping.output().0 == output && mapping.level() == Level::L3 {
                Ok(())
            } else {
                Err(HarnessError::InvalidState)
            };
        }
        let (leaf, table) = Self::d128_fields(permissions)?;
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
        payload_data: [u64; 4],
        sandbox_regions: &[(u64, u64)],
    ) -> Result<(), HarnessError> {
        const PAGE_SIZE: u64 = 4096;
        const CODE_WINDOW: u64 = 1024 * 1024;
        const LINKAGE_DATA_WINDOW: u64 = 64 * 1024;
        let memory = self.inner.frames().memory();
        let arena_start = unsafe { memory.as_ref() }.physical_base() & !(PAGE_SIZE - 1);
        let arena_end = unsafe { memory.as_ref() }
            .physical_base()
            .checked_add(unsafe { memory.as_ref() }.byte_len() as u64)
            .ok_or(HarnessError::Memory)?;
        let stack = vmsa_test_architecture::registers::stack_pointer() & !(PAGE_SIZE - 1);
        let stack_start = stack.saturating_sub(15 * PAGE_SIZE);
        let stack_end = stack.saturating_add(16 * PAGE_SIZE);
        let code_regions = [
            entry & !(CODE_WINDOW - 1),
            vmsa_test_architecture::exception::vector_address() & !(CODE_WINDOW - 1),
            vmsa_test_architecture::exception::recovery_vector_address() & !(CODE_WINDOW - 1),
            payload_data[3] & !(CODE_WINDOW - 1),
        ];
        let data_pages = [
            payload_data[0] & !(PAGE_SIZE - 1),
            vmsa_test_architecture::exception::runtime_state_address() & !(PAGE_SIZE - 1),
            vmsa_test_architecture::transition::runtime_state_address() & !(PAGE_SIZE - 1),
            vmsa_test_architecture::exception::linkage_data_address() & !(PAGE_SIZE - 1),
            payload_data[1] & !(PAGE_SIZE - 1),
            payload_data[2] & !(PAGE_SIZE - 1),
            0x1c09_0000 & !(PAGE_SIZE - 1),
            0x1c0a_0000 & !(PAGE_SIZE - 1),
            0x1c0b_0000 & !(PAGE_SIZE - 1),
            0x1c0c_0000 & !(PAGE_SIZE - 1),
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
                    && !(arena_start..arena_end).contains(&address)
                    && !data_pages.contains(&address)
                    && !sandbox_data
                {
                    self.map_d128_runtime_page(
                        address,
                        address,
                        D128MappingPermissions::ReadExecute,
                    )
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::D128RuntimeCode,
                        )
                    })?;
                }
                address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        for index in 0..code_regions.len() {
            let start = code_regions[index]
                .checked_add(CODE_WINDOW)
                .ok_or(HarnessError::Memory)?;
            if code_regions[..index]
                .iter()
                .any(|region| region.checked_add(CODE_WINDOW) == Some(start))
            {
                continue;
            }
            let end = start
                .checked_add(LINKAGE_DATA_WINDOW)
                .ok_or(HarnessError::Memory)?;
            let mut address = start;
            while address < end {
                if !(stack_start..stack_end).contains(&address)
                    && !sandbox_regions.iter().any(|(input, _)| *input == address)
                    && self
                        .inner
                        .translate(WalkInputAddr::new(address))
                        .map_err(|_| HarnessError::InvalidState)?
                        .is_none()
                {
                    self.map_d128_runtime_page(address, address, D128MappingPermissions::ReadWrite)
                        .map_err(|_| {
                            HarnessError::TransitionPreparation(
                                crate::TransitionPreparationError::D128RuntimeData,
                            )
                        })?;
                }
                address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        let mut address = stack_start;
        while address < stack_end {
            self.map_d128_runtime_page(address, address, D128MappingPermissions::ReadWrite)
                .map_err(|_| {
                    HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::D128RuntimeStack,
                    )
                })?;
            address = address.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
        }
        for index in 0..data_pages.len() {
            let address = data_pages[index];
            if data_pages[..index].contains(&address)
                || (stack_start..stack_end).contains(&address)
                || sandbox_regions.iter().any(|(input, _)| *input == address)
            {
                continue;
            }
            let executable = [
                entry,
                vmsa_test_architecture::exception::vector_address(),
                vmsa_test_architecture::exception::recovery_vector_address(),
                vmsa_test_architecture::exception::runtime_code_address(),
                vmsa_test_architecture::transition::runtime_code_address(),
                payload_data[3],
            ]
            .iter()
            .any(|code| (*code & !(PAGE_SIZE - 1)) == address);
            self.map_d128_runtime_page(
                address,
                address,
                if executable {
                    D128MappingPermissions::ReadWriteExecute
                } else {
                    D128MappingPermissions::ReadWrite
                },
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::D128RuntimeData,
                )
            })?;
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
                self.map_d128_runtime_page(input, output, D128MappingPermissions::ReadWrite)
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::D128RuntimeSandbox,
                        )
                    })?;
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
                    self.map_d128_runtime_page(input, output, D128MappingPermissions::ReadWrite)?;
                }
                input = input.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
                output = output.checked_add(PAGE_SIZE).ok_or(HarnessError::Memory)?;
            }
        }
        let allocation_count = unsafe { memory.as_ref() }.allocation_count();
        for allocation in 0..allocation_count {
            let Some(region) = unsafe { memory.as_ref() }.table_allocation_region(allocation)
            else {
                continue;
            };
            if !vmsa_test_architecture::barriers::clean_data_cache_range(
                region.virtual_address,
                region.bytes,
            ) {
                return Err(HarnessError::Environment);
            }
        }
        if !vmsa_test_architecture::barriers::clean_data_cache_range(
            unsafe { memory.as_ref() }.virtual_base(),
            unsafe { memory.as_ref() }.byte_len(),
        ) {
            return Err(HarnessError::Environment);
        }
        vmsa_test_architecture::barriers::dsb_ish();
        Ok(())
    }

    pub fn map_page(&mut self, input: u64, output: u64) -> Result<(), HarnessError> {
        let (leaf, table) = Self::d128_fields(D128MappingPermissions::ReadWrite)?;
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

    fn d128_map_leaf_outcome(outcome: aarch64_vmsa::mapper::MapLeafOutcome) -> MapLeafResult {
        MapLeafResult {
            tables_allocated: outcome.tables_allocated(),
            level: LookupLevel::new(outcome.level().as_i8())
                .expect("mapper leaf levels are architectural"),
            kind: match outcome.kind() {
                aarch64_vmsa::translation::walk::WalkLeafKind::Block => WalkDescriptorKind::Block,
                aarch64_vmsa::translation::walk::WalkLeafKind::Page => WalkDescriptorKind::Page,
            },
            covered_size: outcome.covered_size(),
        }
    }

    pub fn map_d128_leaf_step_by_one_exact(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let (leaf, table) = Self::d128_fields(D128MappingPermissions::ReadWrite)
            .map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf_with_plan(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                leaf,
                aarch64_vmsa::mapper::StepByOneTablePlan::new(table),
            )
            .map(Self::d128_map_leaf_outcome)
            .map_err(normalize_mapper_operation_error)
    }

    pub fn map_d128_leaf_bounded_skl_exact(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        maximum_table_bytes: u64,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let (leaf, table) = Self::d128_fields(D128MappingPermissions::ReadWrite)
            .map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf_with_plan(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                leaf,
                aarch64_vmsa::mapper::BoundedSklTablePlan::new(table, maximum_table_bytes),
            )
            .map(Self::d128_map_leaf_outcome)
            .map_err(normalize_mapper_operation_error)
    }

    pub fn map_d128_leaf_maximum_skl_exact(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let (leaf, table) = Self::d128_fields(D128MappingPermissions::ReadWrite)
            .map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf_with_plan(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                leaf,
                aarch64_vmsa::mapper::MaxSklTablePlan::new(table),
            )
            .map(Self::d128_map_leaf_outcome)
            .map_err(normalize_mapper_operation_error)
    }

    pub fn map_hardware_managed_page(
        &mut self,
        input: u64,
        output: u64,
        attributes: D128HardwareManagedAttributes,
    ) -> Result<(), HarnessError> {
        self.map_hardware_managed_leaf_exact(input, output, 3, attributes)
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_hardware_managed_leaf_exact(
        &mut self,
        input: u64,
        output: u64,
        level: i8,
        attributes: D128HardwareManagedAttributes,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let (leaf, table) = Self::d128_fields_with_state(
            attributes.permissions,
            attributes.access_flag,
            attributes.dirty,
        )
        .map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level),
                leaf,
                table,
            )
            .map(|outcome| MapLeafResult {
                tables_allocated: outcome.tables_allocated(),
                level: LookupLevel::new(outcome.level().as_i8())
                    .expect("mapper leaf levels are architectural"),
                kind: match outcome.kind() {
                    aarch64_vmsa::translation::walk::WalkLeafKind::Block => {
                        WalkDescriptorKind::Block
                    }
                    aarch64_vmsa::translation::walk::WalkLeafKind::Page => WalkDescriptorKind::Page,
                },
                covered_size: outcome.covered_size(),
            })
            .map_err(normalize_mapper_operation_error)
    }
}

impl<R: TestRegime, G: TestGranule> TestMapper<R, G, Vmsa128>
where
    R: aarch64_vmsa::regime::TranslationRegime<Stage = Stage2>,
    Vmsa128: HasLayout<Stage2, G>,
    <Vmsa128 as HasLayout<Stage2, G>>::Layout: DescriptorLayout<
            Stage2,
            G,
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
        self.map_stage2_leaf_exact(input, output, level, attributes)
            .map(|_| ())
            .map_err(|_| HarnessError::InvalidState)
    }

    pub fn map_stage2_leaf_exact(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: MappingAttributes,
    ) -> Result<MapLeafResult, MapperOperationError> {
        let (leaf, table) =
            d128_stage2_fields(attributes).map_err(|_| MapperOperationError::Unexpected)?;
        self.inner
            .map_leaf(
                WalkInputAddr::new(input),
                PhysAddr(output),
                Level::new(level.get()),
                leaf,
                table,
            )
            .map(|outcome| MapLeafResult {
                tables_allocated: outcome.tables_allocated(),
                level: LookupLevel::new(outcome.level().as_i8())
                    .expect("mapper leaf levels are architectural"),
                kind: match outcome.kind() {
                    aarch64_vmsa::translation::walk::WalkLeafKind::Block => {
                        WalkDescriptorKind::Block
                    }
                    aarch64_vmsa::translation::walk::WalkLeafKind::Page => WalkDescriptorKind::Page,
                },
                covered_size: outcome.covered_size(),
            })
            .map_err(normalize_mapper_operation_error)
    }
}
