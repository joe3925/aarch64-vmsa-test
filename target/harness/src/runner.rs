use crate::environment::Environment;
use crate::report::ReportEvent;
use crate::{
    BootProfile, FailureKind, IsolationRequirement, LogicalTest, Requirements, SecurityEnvironment,
    TestContext, TestResult, tests_for,
};

pub struct RunOptions<'a> {
    pub target: &'static str,
    pub profile: BootProfile,
    pub filter: Option<&'a str>,
    pub baseline: Requirements,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerOutcome {
    Complete {
        passed: u32,
        failed: u32,
        skipped: u32,
    },
    BaselineCapabilityMissing,
    HarnessCorrupted,
}

pub fn run_catalog_tests<E: Environment>(
    environment: &mut E,
    security_environment: SecurityEnvironment,
    dispatch: for<'a> fn(LogicalTest, &mut TestContext<'a, E>) -> Option<TestResult>,
    options: RunOptions<'_>,
) -> RunnerOutcome {
    run_suite(
        environment,
        tests_for(security_environment, options.profile),
        options,
        dispatch,
    )
}

fn run_suite<E, I>(
    environment: &mut E,
    tests: I,
    options: RunOptions<'_>,
    dispatch: for<'a> fn(LogicalTest, &mut TestContext<'a, E>) -> Option<TestResult>,
) -> RunnerOutcome
where
    E: Environment,
    I: IntoIterator<Item = &'static crate::CatalogEntry>,
{
    let capabilities = environment.capabilities();
    if !options.baseline.supported_by(capabilities) {
        return RunnerOutcome::BaselineCapabilityMissing;
    }
    environment.report(ReportEvent::Begin {
        target: options.target,
    });
    report_capabilities(environment, capabilities);
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    let mut corrupted = false;
    for test in tests {
        let name = test.name;
        if test.architecture.isolation != IsolationRequirement::Sequential
            && options.filter != Some(name)
        {
            continue;
        }
        if options.filter.is_some_and(|filter| !name.contains(filter)) {
            continue;
        }
        if !test.model.supported_by(capabilities) {
            environment.report(ReportEvent::Skip {
                name,
                reason: "unsupported",
            });
            skipped = skipped.saturating_add(1);
            continue;
        }
        if environment.begin_test_scope().is_err() {
            environment.mark_corrupted();
            corrupted = true;
            break;
        }
        let scope = match environment.memory().begin_scope() {
            Ok(scope) => scope,
            Err(_) => {
                environment.mark_corrupted();
                corrupted = true;
                break;
            }
        };
        environment.report(ReportEvent::Run { name });
        let (result, cleanup_failed, memory_scope) = {
            let mut context = TestContext::new(environment, scope);
            let result = dispatch(test.id, &mut context);
            (result, context.cleanup_failed(), context.memory_scope())
        };
        environment.emergency_restore();
        let reset_failed = environment.memory().reset(memory_scope).is_err();
        if cleanup_failed || reset_failed {
            environment.mark_corrupted();
            environment.report(ReportEvent::Fail {
                name,
                reason: "cleanup",
            });
            failed = failed.saturating_add(1);
            corrupted = true;
            break;
        }
        let Some(result) = result else {
            environment.report(ReportEvent::Fail {
                name,
                reason: "adapter-missing",
            });
            failed = failed.saturating_add(1);
            environment.mark_corrupted();
            corrupted = true;
            break;
        };
        match result {
            TestResult::Pass => {
                environment.report(ReportEvent::Pass { name });
                passed = passed.saturating_add(1);
            }
            TestResult::Fail(failure) => {
                environment.report(ReportEvent::Fail {
                    name,
                    reason: failure_reason(failure),
                });
                failed = failed.saturating_add(1);
                if failure.kind == FailureKind::Harness {
                    environment.mark_corrupted();
                    corrupted = true;
                    break;
                }
            }
            TestResult::Skip(reason) => {
                environment.report(ReportEvent::Skip {
                    name,
                    reason: skip_reason(reason),
                });
                skipped = skipped.saturating_add(1);
            }
        }
        if environment.end_test_scope().is_err() {
            environment.mark_corrupted();
            corrupted = true;
            break;
        }
    }
    environment.report(ReportEvent::End {
        passed,
        failed,
        skipped,
    });
    if corrupted {
        RunnerOutcome::HarnessCorrupted
    } else if environment.finish().is_err() {
        environment.mark_corrupted();
        RunnerOutcome::HarnessCorrupted
    } else {
        RunnerOutcome::Complete {
            passed,
            failed,
            skipped,
        }
    }
}

const fn skip_reason(reason: crate::SkipReason) -> &'static str {
    match reason {
        crate::SkipReason::Unsupported => "unsupported",
    }
}

const fn failure_reason(failure: crate::TestFailure) -> &'static str {
    match failure.kind {
        FailureKind::UnexpectedFault => "unexpected-fault",
        FailureKind::MissingFault => "missing-fault",
        FailureKind::WrongFault => match failure.actual {
            1 => "wrong-fault-address-size",
            2 => "wrong-fault-translation",
            3 => "wrong-fault-access-flag",
            4 => "wrong-fault-permission",
            5 => "wrong-fault-alignment",
            6 => "wrong-fault-external",
            7 => "wrong-fault-granule-protection",
            0x200 => "wrong-fault-read",
            0x201 => "wrong-fault-write",
            0x202 => "wrong-fault-execute",
            0x300 => "wrong-fault-stage1",
            0x301 => "wrong-fault-stage2",
            0x302 => "wrong-fault-stage-unknown",
            0x400..=0x4ff => "wrong-fault-level",
            _ => "wrong-fault-other",
        },
        FailureKind::WrongValue => "wrong-value",
        FailureKind::Harness => match failure.actual {
            1 => "harness-memory",
            2 => "harness-environment",
            3 => "harness-guard-busy",
            4 => "harness-invalid-state",
            5 => "harness-cleanup",
            0x100 => "transition-recovery-mapper",
            0x101 => "transition-recovery-runtime",
            0x102 => "transition-recovery-inspection",
            0x103 => "transition-recovery-identity",
            0x104 => "transition-candidate-runtime",
            0x105 => "transition-candidate-table-access",
            _ => "harness",
        },
    }
}

fn report_capabilities<E: Environment>(environment: &mut E, capabilities: crate::Capabilities) {
    for (name, value) in [
        ("rme", capabilities.rme as u64),
        ("sel2", capabilities.sel2 as u64),
        ("lpa2", capabilities.lpa2 as u64),
        ("d128", capabilities.d128 as u64),
        ("granule_4k", capabilities.granule_4k as u64),
        ("granule_16k", capabilities.granule_16k as u64),
        ("granule_64k", capabilities.granule_64k as u64),
        ("pa_bits", capabilities.pa_bits as u64),
        ("va_bits", capabilities.va_bits as u64),
    ] {
        environment.report(ReportEvent::Capability { name, value });
    }
}
