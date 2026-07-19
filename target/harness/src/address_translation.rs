#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationQueryAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationQueryResult {
    Success {
        physical_address: u64,
        attributes: u64,
    },
    Fault {
        status: u8,
        stage2: bool,
        raw: u64,
    },
    Unsupported,
}

impl TranslationQueryResult {
    const SUCCESS_ATTRIBUTES_MASK: u64 = 0xff00_0000_0000_0f80;

    pub(crate) fn from_par(address: u64, par: u64) -> Self {
        if par & 1 == 0 {
            Self::Success {
                physical_address: (par & 0x000f_ffff_ffff_f000) | (address & 0xfff),
                attributes: par & Self::SUCCESS_ATTRIBUTES_MASK,
            }
        } else {
            Self::Fault {
                status: ((par >> 1) & 0x3f) as u8,
                stage2: par & (1 << 9) != 0,
                raw: par,
            }
        }
    }

    pub(crate) fn from_par128(address: u64, low: u64, high: u64) -> Self {
        // PAR_EL1.D128 is bit 64, hence bit 0 of the high word returned by
        // MRRS. A zero value explicitly selects the ordinary 64-bit layout.
        if high & 1 == 0 {
            return Self::from_par(address, low);
        }

        if low & 1 == 0 {
            // In the 128-bit success layout PAR_EL1[119:76] contains output
            // address[55:12]. Those bits occupy high-word[55:12], so no
            // cross-word shifting is required.
            Self::Success {
                physical_address: (high & 0x00ff_ffff_ffff_f000) | (address & 0xfff),
                attributes: low & Self::SUCCESS_ATTRIBUTES_MASK,
            }
        } else {
            Self::Fault {
                status: ((low >> 1) & 0x3f) as u8,
                stage2: low & (1 << 9) != 0,
                raw: low,
            }
        }
    }

    #[doc(hidden)]
    pub fn from_raw_par_for_test(address: u64, par: u64) -> Self {
        Self::from_par(address, par)
    }

    #[doc(hidden)]
    pub fn from_raw_par128_for_test(address: u64, low: u64, high: u64) -> Self {
        Self::from_par128(address, low, high)
    }
}
