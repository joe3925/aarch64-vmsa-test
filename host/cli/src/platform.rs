#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Platform {
    FvpRevC,
    FvpRdN2,
}

impl Platform {
    pub const ALL: [Self; 2] = [Self::FvpRevC, Self::FvpRdN2];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FvpRevC => "fvp-revc",
            Self::FvpRdN2 => "fvp-rdn2",
        }
    }

    /// Optional platform-local cap applied in addition to the user-selected
    /// global runtime concurrency.
    pub const fn runtime_concurrency_limit(self) -> Option<usize> {
        match self {
            Self::FvpRevC => None,
            Self::FvpRdN2 => Some(1),
        }
    }
}
