use crate::{AccessKind, AccessResult, ExpectedFault, FaultMatcher, FaultStage, FaultStatus};
use core::convert::Infallible;
use core::ops::FromResidual;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessError {
    Memory,
    Environment,
    EnvironmentDetail(u64),
    GuardBusy,
    InvalidState,
    CrateBehavior { expected: u64, actual: u64 },
    Cleanup,
    InjectedFailure,
    Attribute(crate::AttributeError),
    TransitionPreparation(TransitionPreparationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionPreparationError {
    RecoveryMapper,
    RecoveryRuntime,
    RecoveryInspection,
    RecoveryIdentity,
    CandidateRuntime,
    CandidateTableAccess,
    D128RuntimeCode,
    D128RuntimeStack,
    D128RuntimeData,
    D128RuntimeSandbox,
    VmsaRuntimeCode,
    VmsaRuntimeStack,
    VmsaRuntimeData,
    VmsaRuntimeSandbox,
    VmsaRuntimeLinkageData,
    VmsaRuntimeDataPage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    UnexpectedFault,
    MissingFault,
    WrongFault,
    WrongValue,
    Harness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestFailure {
    pub kind: FailureKind,
    pub expected: u64,
    pub actual: u64,
}

impl From<HarnessError> for TestFailure {
    fn from(error: HarnessError) -> Self {
        if let HarnessError::CrateBehavior { expected, actual } = error {
            return Self {
                kind: FailureKind::WrongValue,
                expected,
                actual,
            };
        }
        Self {
            kind: FailureKind::Harness,
            expected: 0,
            actual: match error {
                HarnessError::Memory => 1,
                HarnessError::Environment => 2,
                HarnessError::EnvironmentDetail(code) => 0x400 + code,
                HarnessError::GuardBusy => 3,
                HarnessError::InvalidState => 4,
                HarnessError::CrateBehavior { .. } => unreachable!(),
                HarnessError::Cleanup => 5,
                HarnessError::InjectedFailure => 6,
                HarnessError::Attribute(error) => 0x200 + error.code(),
                HarnessError::TransitionPreparation(stage) => 0x100 + stage as u64,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestResult {
    Pass,
    Fail(TestFailure),
    Skip(SkipReason),
}

impl From<HarnessError> for TestResult {
    fn from(error: HarnessError) -> Self {
        Self::Fail(error.into())
    }
}

impl FromResidual<Result<Infallible, HarnessError>> for TestResult {
    fn from_residual(residual: Result<Infallible, HarnessError>) -> Self {
        match residual {
            Err(error) => error.into(),
            Ok(never) => match never {},
        }
    }
}

pub fn expect_completed(result: AccessResult) -> TestResult {
    match result {
        AccessResult::Completed { .. } | AccessResult::CompletedPair { .. } => TestResult::Pass,
        AccessResult::Fault(_) => fail(FailureKind::UnexpectedFault, 0, 0),
        AccessResult::HarnessFailure(_) => fail(FailureKind::Harness, 0, 0),
    }
}
pub fn expect_value(result: AccessResult, expected: u64) -> TestResult {
    match result {
        AccessResult::Completed { value } if value == expected => TestResult::Pass,
        AccessResult::Completed { value } => fail(FailureKind::WrongValue, expected, value),
        AccessResult::CompletedPair { .. } => fail(FailureKind::Harness, expected, 0),
        AccessResult::Fault(_) => fail(FailureKind::UnexpectedFault, expected, 0),
        AccessResult::HarnessFailure(_) => fail(FailureKind::Harness, expected, 0),
    }
}
pub fn expect_fault(result: AccessResult, expected: ExpectedFault) -> TestResult {
    match result {
        AccessResult::Fault(fault) if expected.matches(fault) => TestResult::Pass,
        AccessResult::Fault(fault) => {
            let actual = if expected.status.is_some() && expected.status != Some(fault.status) {
                fault.status_code()
            } else if expected.access.is_some() && expected.access != Some(fault.access) {
                match fault.access {
                    AccessKind::Read => 0x200,
                    AccessKind::Write => 0x201,
                    AccessKind::Execute => 0x202,
                }
            } else if expected.stage.is_some() && expected.stage != Some(fault.stage) {
                match fault.stage {
                    FaultStage::Stage1 => 0x300,
                    FaultStage::Stage2 => 0x301,
                    FaultStage::Unknown => 0x302,
                }
            } else {
                0x400 | fault.level.map_or(0xff, |level| level.get() as i64 as u64)
            };
            fail(FailureKind::WrongFault, 0, actual)
        }
        AccessResult::Completed { .. } | AccessResult::CompletedPair { .. } => {
            fail(FailureKind::MissingFault, 0, 0)
        }
        AccessResult::HarnessFailure(_) => fail(FailureKind::Harness, 0, 0),
    }
}

pub fn expect_matching_fault(result: AccessResult, expected: FaultMatcher) -> TestResult {
    match result {
        AccessResult::Fault(fault) if expected.matches(fault) => TestResult::Pass,
        AccessResult::Fault(fault) => TestResult::Fail(TestFailure {
            kind: FailureKind::WrongFault,
            expected: 1,
            actual: fault.diagnostic_code(),
        }),
        AccessResult::Completed { value } => TestResult::Fail(TestFailure {
            kind: FailureKind::MissingFault,
            expected: 1,
            actual: value,
        }),
        AccessResult::CompletedPair { first, .. } => TestResult::Fail(TestFailure {
            kind: FailureKind::MissingFault,
            expected: 1,
            actual: first,
        }),
        AccessResult::HarnessFailure(error) => TestResult::Fail(error.into()),
    }
}
pub fn expect_translation_fault(result: AccessResult, stage: FaultStage) -> TestResult {
    expect_fault(result, ExpectedFault::translation(stage))
}
pub fn expect_permission_fault(result: AccessResult) -> TestResult {
    expect_fault(
        result,
        ExpectedFault {
            status: Some(FaultStatus::Permission),
            access: None,
            stage: None,
            level: None,
        },
    )
}
pub fn expect_stage2_fault(result: AccessResult) -> TestResult {
    expect_fault(
        result,
        ExpectedFault {
            status: None,
            access: None,
            stage: Some(FaultStage::Stage2),
            level: None,
        },
    )
}
const fn fail(kind: FailureKind, expected: u64, actual: u64) -> TestResult {
    TestResult::Fail(TestFailure {
        kind,
        expected,
        actual,
    })
}
