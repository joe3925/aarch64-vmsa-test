use crate::fault::ObservedFault;
use crate::test::HarnessError;
use vmsa_test_architecture::AccessWidth;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessOperation {
    Plain,
    Acquire,
    Release,
    AtomicSwap,
    ExclusiveAdd,
    PairRead,
    PairWrite,
    Translate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub kind: AccessKind,
    pub address: u64,
    pub width: AccessWidth,
    pub value: u64,
    pub second_value: u64,
    pub operation: AccessOperation,
}

impl AccessRequest {
    pub const fn read(address: u64, width: AccessWidth) -> Self {
        Self {
            kind: AccessKind::Read,
            address,
            width,
            value: 0,
            second_value: 0,
            operation: AccessOperation::Plain,
        }
    }
    pub const fn write(address: u64, width: AccessWidth, value: u64) -> Self {
        Self {
            kind: AccessKind::Write,
            address,
            width,
            value,
            second_value: 0,
            operation: AccessOperation::Plain,
        }
    }
    pub const fn execute(address: u64) -> Self {
        Self {
            kind: AccessKind::Execute,
            address,
            width: AccessWidth::Double,
            value: 0,
            second_value: 0,
            operation: AccessOperation::Plain,
        }
    }
    pub const fn read_acquire(address: u64) -> Self {
        Self {
            kind: AccessKind::Read,
            address,
            width: AccessWidth::Double,
            value: 0,
            second_value: 0,
            operation: AccessOperation::Acquire,
        }
    }
    pub const fn write_release(address: u64, value: u64) -> Self {
        Self {
            kind: AccessKind::Write,
            address,
            width: AccessWidth::Double,
            value,
            second_value: 0,
            operation: AccessOperation::Release,
        }
    }
    pub const fn atomic_swap(address: u64, value: u64) -> Self {
        Self {
            kind: AccessKind::Write,
            address,
            width: AccessWidth::Double,
            value,
            second_value: 0,
            operation: AccessOperation::AtomicSwap,
        }
    }
    pub const fn exclusive_add(address: u64, value: u64) -> Self {
        Self {
            kind: AccessKind::Write,
            address,
            width: AccessWidth::Double,
            value,
            second_value: 0,
            operation: AccessOperation::ExclusiveAdd,
        }
    }
    pub const fn read_pair(address: u64) -> Self {
        Self {
            kind: AccessKind::Read,
            address,
            width: AccessWidth::Double,
            value: 0,
            second_value: 0,
            operation: AccessOperation::PairRead,
        }
    }
    pub const fn write_pair(address: u64, first: u64, second: u64) -> Self {
        Self {
            kind: AccessKind::Write,
            address,
            width: AccessWidth::Double,
            value: first,
            second_value: second,
            operation: AccessOperation::PairWrite,
        }
    }

    pub const fn translate(address: u64, write: bool) -> Self {
        Self {
            kind: if write {
                AccessKind::Write
            } else {
                AccessKind::Read
            },
            address,
            width: AccessWidth::Double,
            value: 0,
            second_value: 0,
            operation: AccessOperation::Translate,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessResult {
    Completed { value: u64 },
    CompletedPair { first: u64, second: u64 },
    Fault(ObservedFault),
    HarnessFailure(HarnessError),
}
