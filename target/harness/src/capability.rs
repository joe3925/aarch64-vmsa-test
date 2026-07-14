use vmsa_test_architecture::registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub el2: bool,
    pub el3: bool,
    pub el2_and0: bool,
    pub rme: bool,
    pub sel2: bool,
    pub stage2: bool,
    pub xnx: bool,
    pub lpa2: bool,
    pub d128: bool,
    pub d128_stage2: bool,
    pub extended_input_address: bool,
    pub extended_output_address: bool,
    pub security_states: u8,
    pub granule_4k: bool,
    pub granule_16k: bool,
    pub granule_64k: bool,
    pub pa_bits: u8,
    pub va_bits: u8,
}

impl Capabilities {
    pub(crate) fn read() -> Self {
        let mmfr0 = registers::id_aa64mmfr0_el1();
        let mmfr2 = registers::id_aa64mmfr2_el1();
        let mmfr3 = registers::id_aa64mmfr3_el1();
        let pfr0 = registers::id_aa64pfr0_el1();
        let granule_4k = field(mmfr0, 28) != 0xf;
        let granule_16k = field(mmfr0, 20) != 0xf;
        let granule_64k = field(mmfr0, 24) != 0xf;
        let lpa2 = field(mmfr0, 28) == 1 || field(mmfr0, 20) == 2;
        let pa_bits = match field(mmfr0, 0) {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            6 => 52,
            7 => 56,
            _ => 0,
        };
        let varange = field(mmfr2, 16);
        let mmfr1 = registers::id_aa64mmfr1_el1();
        let el2 = matches!(field(pfr0, 8), 1 | 2);
        let el3 = matches!(field(pfr0, 12), 1 | 2);
        let sel2 = field(pfr0, 36) == 1;
        let rme = matches!(field(pfr0, 52), 1..=3);
        let d128 = field(mmfr3, 32) == 1;
        let d128_stage2 = field(mmfr3, 36) == 1;
        let mut security_states = 1;
        if sel2 || (!rme && el3) {
            security_states |= 1 << 1;
        }
        if rme {
            security_states |= 1 << 2;
            if el3 {
                security_states |= 1 << 3;
            }
        }
        Self {
            el2,
            el3,
            el2_and0: field(mmfr1, 8) == 1,
            rme,
            sel2,
            stage2: el2,
            xnx: field(mmfr1, 28) == 1,
            lpa2,
            d128,
            d128_stage2,
            extended_input_address: matches!(varange, 1 | 2) || lpa2 || d128 || d128_stage2,
            extended_output_address: matches!(field(mmfr0, 0), 6 | 7) || d128 || d128_stage2,
            security_states,
            granule_4k,
            granule_16k,
            granule_64k,
            pa_bits,
            va_bits: if varange >= 1 { 52 } else { 48 },
        }
    }
}

const fn field(register: u64, shift: u8) -> u8 {
    ((register >> shift) & 0xf) as u8
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirements {
    features: u16,
    min_pa_bits: u8,
    min_va_bits: u8,
}

impl Requirements {
    pub const NONE: Self = Self::new(0, 0, 0);
    pub const RME: Self = Self::new(1 << 0, 0, 0);
    pub const SEL2: Self = Self::new(1 << 1, 0, 0);
    pub const LPA2: Self = Self::new(1 << 2, 0, 0);
    pub const D128: Self = Self::new(1 << 3, 0, 0);
    pub const GRANULE_4K: Self = Self::new(1 << 4, 0, 0);
    pub const GRANULE_16K: Self = Self::new(1 << 5, 0, 0);
    pub const GRANULE_64K: Self = Self::new(1 << 6, 0, 0);
    pub const EL2: Self = Self::new(1 << 7, 0, 0);
    pub const EL3: Self = Self::new(1 << 8, 0, 0);
    pub const EL2_AND0: Self = Self::new(1 << 9, 0, 0);
    pub const STAGE2: Self = Self::new(1 << 10, 0, 0);
    pub const XNX: Self = Self::new(1 << 11, 0, 0);
    pub const D128_STAGE2: Self = Self::new(1 << 12, 0, 0);
    pub const EXTENDED_INPUT_ADDRESS: Self = Self::new(1 << 13, 0, 0);
    pub const EXTENDED_OUTPUT_ADDRESS: Self = Self::new(1 << 14, 0, 0);

    const fn new(features: u16, min_pa_bits: u8, min_va_bits: u8) -> Self {
        Self {
            features,
            min_pa_bits,
            min_va_bits,
        }
    }

    pub const fn minimum_pa(bits: u8) -> Self {
        Self::new(0, bits, 0)
    }
    pub const fn minimum_va(bits: u8) -> Self {
        Self::new(0, 0, bits)
    }

    pub const fn union(self, other: Self) -> Self {
        Self::new(
            self.features | other.features,
            if self.min_pa_bits > other.min_pa_bits {
                self.min_pa_bits
            } else {
                other.min_pa_bits
            },
            if self.min_va_bits > other.min_va_bits {
                self.min_va_bits
            } else {
                other.min_va_bits
            },
        )
    }

    pub const fn supported_by(self, capabilities: Capabilities) -> bool {
        (!self.has(0) || capabilities.rme)
            && (!self.has(1) || capabilities.sel2)
            && (!self.has(2) || capabilities.lpa2)
            && (!self.has(3) || capabilities.d128)
            && (!self.has(4) || capabilities.granule_4k)
            && (!self.has(5) || capabilities.granule_16k)
            && (!self.has(6) || capabilities.granule_64k)
            && (!self.has(7) || capabilities.el2)
            && (!self.has(8) || capabilities.el3)
            && (!self.has(9) || capabilities.el2_and0)
            && (!self.has(10) || capabilities.stage2)
            && (!self.has(11) || capabilities.xnx)
            && (!self.has(12) || capabilities.d128_stage2)
            && (!self.has(13) || capabilities.extended_input_address)
            && (!self.has(14) || capabilities.extended_output_address)
            && capabilities.pa_bits >= self.min_pa_bits
            && capabilities.va_bits >= self.min_va_bits
    }

    const fn has(self, bit: u8) -> bool {
        self.features & (1 << bit) != 0
    }
}
