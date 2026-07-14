use vmsa_test_architecture::registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub rme: bool,
    pub sel2: bool,
    pub lpa2: bool,
    pub d128: bool,
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
        Self {
            rme: field(pfr0, 52) == 1,
            sel2: field(pfr0, 36) == 1,
            lpa2,
            d128: field(mmfr3, 32) == 1,
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
            && capabilities.pa_bits >= self.min_pa_bits
            && capabilities.va_bits >= self.min_va_bits
    }

    const fn has(self, bit: u8) -> bool {
        self.features & (1 << bit) != 0
    }
}
