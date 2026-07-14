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
    pub(crate) fn from_par(address: u64, par: u64) -> Self {
        if par & 1 == 0 {
            Self::Success {
                physical_address: (par & 0x000f_ffff_ffff_f000) | (address & 0xfff),
                attributes: par & 0x0ff0_0000_0000_0f80,
            }
        } else {
            Self::Fault {
                status: ((par >> 1) & 0x3f) as u8,
                stage2: par & (1 << 9) != 0,
                raw: par,
            }
        }
    }
}
