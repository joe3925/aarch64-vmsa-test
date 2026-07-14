use vmsa_test_architecture::AccessWidth;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum LowerElTarget {
    El1 = 0,
    El0 = 1,
    El2El0 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, u64)]
pub enum LowerElCommand {
    Read {
        address: u64,
        width: AccessWidth,
    },
    Write {
        address: u64,
        width: AccessWidth,
        value: u64,
    },
    Execute {
        address: u64,
    },
    Translate {
        address: u64,
        write: bool,
    },
    ReadAcquire {
        address: u64,
    },
    WriteRelease {
        address: u64,
        value: u64,
    },
    AtomicSwap {
        address: u64,
        value: u64,
    },
    ExclusiveAdd {
        address: u64,
        value: u64,
    },
    ReadPair {
        address: u64,
    },
    WritePair {
        address: u64,
        first: u64,
        second: u64,
    },
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowerElRequest {
    pub command: LowerElCommand,
    pub target: LowerElTarget,
}

impl LowerElRequest {
    pub const fn read(address: u64, width: AccessWidth) -> Self {
        Self {
            command: LowerElCommand::Read { address, width },
            target: LowerElTarget::El1,
        }
    }

    pub const fn write(address: u64, width: AccessWidth, value: u64) -> Self {
        Self {
            command: LowerElCommand::Write {
                address,
                width,
                value,
            },
            target: LowerElTarget::El1,
        }
    }

    pub const fn execute(address: u64) -> Self {
        Self {
            command: LowerElCommand::Execute { address },
            target: LowerElTarget::El1,
        }
    }

    pub const fn exit() -> Self {
        Self {
            command: LowerElCommand::Exit,
            target: LowerElTarget::El1,
        }
    }

    pub const fn translate(address: u64, write: bool) -> Self {
        Self {
            command: LowerElCommand::Translate { address, write },
            target: LowerElTarget::El1,
        }
    }

    pub const fn read_acquire(address: u64) -> Self {
        Self {
            command: LowerElCommand::ReadAcquire { address },
            target: LowerElTarget::El1,
        }
    }

    pub const fn write_release(address: u64, value: u64) -> Self {
        Self {
            command: LowerElCommand::WriteRelease { address, value },
            target: LowerElTarget::El1,
        }
    }

    pub const fn atomic_swap(address: u64, value: u64) -> Self {
        Self {
            command: LowerElCommand::AtomicSwap { address, value },
            target: LowerElTarget::El1,
        }
    }

    pub const fn exclusive_add(address: u64, value: u64) -> Self {
        Self {
            command: LowerElCommand::ExclusiveAdd { address, value },
            target: LowerElTarget::El1,
        }
    }

    pub const fn read_pair(address: u64) -> Self {
        Self {
            command: LowerElCommand::ReadPair { address },
            target: LowerElTarget::El1,
        }
    }

    pub const fn write_pair(address: u64, first: u64, second: u64) -> Self {
        Self {
            command: LowerElCommand::WritePair {
                address,
                first,
                second,
            },
            target: LowerElTarget::El1,
        }
    }

    pub const fn at_el0(mut self) -> Self {
        self.target = LowerElTarget::El0;
        self
    }

    pub const fn at_el2_el0(mut self) -> Self {
        self.target = LowerElTarget::El2El0;
        self
    }
}
