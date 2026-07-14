use crate::{LookupLevel, access::AccessKind};
use vmsa_test_architecture::exception::RawFault;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultClass {
    DataAbort,
    InstructionAbort,
    Other(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultStatus {
    Translation,
    Permission,
    AccessFlag,
    Alignment,
    AddressSize,
    GranuleProtection,
    TagCheck,
    TlbConflict,
    UnsupportedAtomicUpdate,
    External,
    Other(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultStage {
    Stage1,
    Stage2,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedFault {
    pub class: FaultClass,
    pub status: FaultStatus,
    pub level: Option<LookupLevel>,
    pub address: u64,
    pub ipa: Option<u64>,
    pub access: AccessKind,
    pub stage: FaultStage,
}

impl ObservedFault {
    pub(crate) fn from_raw(raw: RawFault, requested: AccessKind) -> Self {
        let ec = ((raw.esr >> 26) & 0x3f) as u8;
        let iss = raw.esr & 0x01ff_ffff;
        let fsc = (iss & 0x3f) as u8;
        let class = match ec {
            0x20 | 0x21 => FaultClass::InstructionAbort,
            0x24 | 0x25 => FaultClass::DataAbort,
            other => FaultClass::Other(other),
        };
        let access = match class {
            FaultClass::InstructionAbort => AccessKind::Execute,
            FaultClass::DataAbort if iss & (1 << 6) != 0 => AccessKind::Write,
            FaultClass::DataAbort => AccessKind::Read,
            FaultClass::Other(_) => requested,
        };
        let status = match fsc {
            0b000000..=0b000011 => FaultStatus::AddressSize,
            0b000100..=0b000111 => FaultStatus::Translation,
            0b001000..=0b001011 => FaultStatus::AccessFlag,
            0b001100..=0b001111 => FaultStatus::Permission,
            0b100001 => FaultStatus::Alignment,
            0b101000 | 0b101001 | 0b101010 | 0b101100..=0b101111 => FaultStatus::GranuleProtection,
            0b010001 => FaultStatus::TagCheck,
            0b110000 => FaultStatus::TlbConflict,
            0b110001 => FaultStatus::UnsupportedAtomicUpdate,
            0b010000
            | 0b010010
            | 0b010011
            | 0b010100..=0b010111
            | 0b011000
            | 0b011100..=0b011111 => FaultStatus::External,
            other => FaultStatus::Other(other),
        };
        let level = match status {
            FaultStatus::AddressSize
            | FaultStatus::Translation
            | FaultStatus::AccessFlag
            | FaultStatus::Permission => LookupLevel::new((fsc & 0x3) as i8),
            FaultStatus::External => match fsc {
                0b010010 => LookupLevel::new(-1),
                0b010011 => LookupLevel::new(-2),
                0b010100..=0b010111 | 0b011100..=0b011111 => LookupLevel::new((fsc & 0x3) as i8),
                _ => None,
            },
            FaultStatus::GranuleProtection => match fsc {
                0b101001 => LookupLevel::new(-1),
                0b101010 => LookupLevel::new(-2),
                0b101100..=0b101111 => LookupLevel::new((fsc & 0x3) as i8),
                _ => None,
            },
            _ => None,
        };
        let stage2 = raw.hpfar.is_some() && matches!(ec, 0x20 | 0x24);
        let ipa = if stage2 {
            raw.hpfar
                .map(|hpfar| ((hpfar & 0x0000_ffff_ffff_fff0) << 8) | (raw.far & 0xfff))
        } else {
            None
        };
        Self {
            class,
            status,
            level,
            address: raw.far,
            ipa,
            access,
            stage: if !matches!(class, FaultClass::DataAbort | FaultClass::InstructionAbort) {
                FaultStage::Unknown
            } else if stage2 {
                FaultStage::Stage2
            } else {
                FaultStage::Stage1
            },
        }
    }

    pub const fn status_code(self) -> u64 {
        match self.status {
            FaultStatus::AddressSize => 1,
            FaultStatus::Translation => 2,
            FaultStatus::AccessFlag => 3,
            FaultStatus::Permission => 4,
            FaultStatus::Alignment => 5,
            FaultStatus::External => 6,
            FaultStatus::GranuleProtection => 7,
            FaultStatus::TagCheck => 8,
            FaultStatus::TlbConflict => 9,
            FaultStatus::UnsupportedAtomicUpdate => 10,
            FaultStatus::Other(value) => 0x100 | value as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedFault {
    pub status: Option<FaultStatus>,
    pub access: Option<AccessKind>,
    pub stage: Option<FaultStage>,
    pub level: Option<LookupLevel>,
}

impl ExpectedFault {
    pub const fn address_size_read_stage1() -> Self {
        Self {
            status: Some(FaultStatus::AddressSize),
            access: Some(AccessKind::Read),
            stage: Some(FaultStage::Stage1),
            level: None,
        }
    }

    pub const fn translation_read_stage1() -> Self {
        Self {
            status: Some(FaultStatus::Translation),
            access: Some(AccessKind::Read),
            stage: Some(FaultStage::Stage1),
            level: None,
        }
    }
    pub const fn granule_protection_read_stage1() -> Self {
        Self {
            status: Some(FaultStatus::GranuleProtection),
            access: Some(AccessKind::Read),
            stage: Some(FaultStage::Stage1),
            level: None,
        }
    }
    pub const fn permission_write() -> Self {
        Self {
            status: Some(FaultStatus::Permission),
            access: Some(AccessKind::Write),
            stage: None,
            level: None,
        }
    }
    pub const fn permission_write_stage2() -> Self {
        Self {
            status: Some(FaultStatus::Permission),
            access: Some(AccessKind::Write),
            stage: Some(FaultStage::Stage2),
            level: None,
        }
    }
    pub const fn translation_read_stage2() -> Self {
        Self {
            status: Some(FaultStatus::Translation),
            access: Some(AccessKind::Read),
            stage: Some(FaultStage::Stage2),
            level: None,
        }
    }
    pub const fn translation(stage: FaultStage) -> Self {
        Self {
            status: Some(FaultStatus::Translation),
            access: None,
            stage: Some(stage),
            level: None,
        }
    }
    pub fn matches(self, fault: ObservedFault) -> bool {
        (self.status.is_none() || self.status == Some(fault.status))
            && (self.access.is_none() || self.access == Some(fault.access))
            && (self.stage.is_none() || self.stage == Some(fault.stage))
            && (self.level.is_none() || self.level == fault.level)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultMatcher {
    expected: ExpectedFault,
    class: Option<FaultClass>,
    address: Option<u64>,
    ipa: Option<Option<u64>>,
}

impl FaultMatcher {
    pub const fn new(expected: ExpectedFault) -> Self {
        Self {
            expected,
            class: None,
            address: None,
            ipa: None,
        }
    }

    pub const fn with_class(mut self, class: FaultClass) -> Self {
        self.class = Some(class);
        self
    }

    pub const fn at_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    pub const fn with_ipa(mut self, ipa: Option<u64>) -> Self {
        self.ipa = Some(ipa);
        self
    }

    pub fn matches(self, fault: ObservedFault) -> bool {
        self.expected.matches(fault)
            && self.class.is_none_or(|class| fault.class == class)
            && self.address.is_none_or(|address| fault.address == address)
            && self.ipa.is_none_or(|ipa| fault.ipa == ipa)
    }
}

pub(crate) fn normalization_self_check() -> bool {
    const FAR: u64 = 0x1234_5678_9abc;
    let raw = |ec: u8, fsc: u8, write: bool, hpfar: Option<u64>| RawFault {
        esr: (u64::from(ec) << 26) | u64::from(fsc) | (u64::from(write) << 6),
        far: FAR,
        hpfar,
        elr: 0,
        spsr: 0,
    };
    let access_flag = ObservedFault::from_raw(raw(0x25, 0x08, false, None), AccessKind::Read);
    let address_size = ObservedFault::from_raw(raw(0x24, 0x03, false, None), AccessKind::Read);
    let permission = ObservedFault::from_raw(raw(0x25, 0x0c, true, None), AccessKind::Write);
    let stage2 =
        ObservedFault::from_raw(raw(0x20, 0x07, false, Some(0x1234_5670)), AccessKind::Read);
    let gpc = ObservedFault::from_raw(raw(0x24, 0x2a, false, None), AccessKind::Read);
    let other = ObservedFault::from_raw(raw(0x15, 0, false, None), AccessKind::Read);
    access_flag.status == FaultStatus::AccessFlag
        && access_flag.level == LookupLevel::new(0)
        && access_flag.class == FaultClass::DataAbort
        && access_flag.access == AccessKind::Read
        && access_flag.stage == FaultStage::Stage1
        && address_size.status == FaultStatus::AddressSize
        && address_size.level == LookupLevel::new(3)
        && address_size.address == FAR
        && address_size.ipa.is_none()
        && permission.status == FaultStatus::Permission
        && permission.level == LookupLevel::new(0)
        && permission.access == AccessKind::Write
        && stage2.class == FaultClass::InstructionAbort
        && stage2.status == FaultStatus::Translation
        && stage2.level == LookupLevel::new(3)
        && stage2.access == AccessKind::Execute
        && stage2.stage == FaultStage::Stage2
        && stage2.ipa == Some(((0x1234_5670 & 0x0000_ffff_ffff_fff0) << 8) | (FAR & 0xfff))
        && gpc.status == FaultStatus::GranuleProtection
        && gpc.level == LookupLevel::new(-2)
        && other.class == FaultClass::Other(0x15)
        && other.stage == FaultStage::Unknown
}
