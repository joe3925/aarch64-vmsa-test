use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::podman;
use crate::protocol::{Counts, Event, Parser};
use crate::settings::{
    BUILD_TIMEOUT, REALM_STAGE2_STARTUP_TIMEOUT, STARTUP_TIMEOUT, SUITE_TIMEOUT, TEST_TIMEOUT,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct Line {
    stream: Stream,
    text: String,
}

#[derive(Debug)]
pub enum Failure {
    Build(String),
    Startup(String),
    Capability(String),
    Malformed(String),
    Timeout(String),
    Io(String),
    Cancelled(String),
}

#[derive(Debug)]
pub struct Completed {
    pub counts: Counts,
}

#[derive(Clone, Copy)]
struct SupervisorLimits {
    initial: Duration,
    build: Duration,
    startup: Duration,
    suite: Duration,
    test: Duration,
    shutdown: Duration,
}

#[derive(Clone, Copy)]
struct ExpectedRun<'a> {
    target: &'a str,
    termination: Option<&'a str>,
}

impl SupervisorLimits {
    fn production(expected_target: &str) -> Self {
        Self {
            initial: BUILD_TIMEOUT,
            build: BUILD_TIMEOUT,
            startup: if expected_target == "realm-stage2" {
                REALM_STAGE2_STARTUP_TIMEOUT
            } else {
                STARTUP_TIMEOUT
            },
            suite: SUITE_TIMEOUT,
            test: TEST_TIMEOUT,
            shutdown: crate::settings::SHUTDOWN_TIMEOUT,
        }
    }

    const fn doctor() -> Self {
        let short = Duration::from_millis(300);
        Self {
            initial: Duration::from_secs(5),
            build: short,
            startup: short,
            suite: short,
            test: short,
            shutdown: short,
        }
    }
}

pub fn run(
    command: Command,
    container_name: &str,
    expected_target: &str,
    output_directory: &Path,
    stream_live: bool,
    expected_termination: Option<&str>,
) -> Result<Completed, Failure> {
    run_with_limits(
        command,
        container_name,
        expected_target,
        output_directory,
        stream_live,
        expected_termination,
        SupervisorLimits::production(expected_target),
    )
}

fn run_with_limits(
    mut command: Command,
    container_name: &str,
    expected_target: &str,
    output_directory: &Path,
    stream_live: bool,
    expected_termination: Option<&str>,
    limits: SupervisorLimits,
) -> Result<Completed, Failure> {
    let mut container = ContainerGuard {
        name: container_name,
        active: true,
    };
    let stdout_log = create_log(output_directory, "container.stdout.log")?;
    let stderr_log = create_log(output_directory, "container.stderr.log")?;
    let mut results_log = create_log(output_directory, "results.log")?;
    let mut child = command
        .spawn()
        .map_err(|error| Failure::Startup(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::Io("stdout was not piped".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::Io("stderr was not piped".into()))?;
    let (sender, receiver) = mpsc::channel();
    let stdout_thread = reader_thread(stdout, Stream::Stdout, stdout_log, sender.clone());
    let stderr_thread = reader_thread(stderr, Stream::Stderr, stderr_log, sender);

    let result = supervise(
        &mut child,
        container_name,
        ExpectedRun {
            target: expected_target,
            termination: expected_termination,
        },
        receiver,
        &mut results_log,
        stream_live,
        limits,
    );
    let stdout_join = stdout_thread.join();
    let stderr_join = stderr_thread.join();
    let cleanup = container.cleanup();

    let mut result = result;
    if stdout_join.is_err() {
        result = Err(add_context(result.err(), "stdout reader thread panicked"));
    }
    if stderr_join.is_err() {
        result = Err(add_context(result.err(), "stderr reader thread panicked"));
    }
    if let Err(error) = cleanup {
        result = Err(add_context(
            result.err(),
            &format!("container cleanup failed: {error}"),
        ));
    }
    result
}

struct ContainerGuard<'a> {
    name: &'a str,
    active: bool,
}

impl ContainerGuard<'_> {
    fn cleanup(&mut self) -> Result<(), podman::PodmanError> {
        if !self.active {
            return Ok(());
        }
        podman::stop_container(self.name)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = podman::stop_container(self.name)
        {
            eprintln!("vmsa-test: emergency container cleanup failed: {error}");
        }
    }
}

fn supervise(
    child: &mut Child,
    container_name: &str,
    expected: ExpectedRun<'_>,
    receiver: Receiver<Result<Line, String>>,
    results: &mut File,
    stream_live: bool,
    limits: SupervisorLimits,
) -> Result<Completed, Failure> {
    const BUILD_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

    let started_at = Instant::now();
    let mut deadline = started_at + limits.initial;
    let mut phase = "preparation/build";
    let mut phase_started_at = started_at;
    let mut next_build_progress = started_at + BUILD_PROGRESS_INTERVAL;
    let mut active_test: Option<(String, Instant)> = None;
    let mut parser = Parser::new();
    loop {
        if crate::cancellation::requested() {
            return Err(terminate_then(
                child,
                container_name,
                Failure::Cancelled(format!(
                    "host cancellation requested during {phase} after {:.3}s",
                    phase_started_at.elapsed().as_secs_f64()
                )),
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            if expected.termination.is_some_and(|expected_name| {
                active_test
                    .as_ref()
                    .is_some_and(|(active_name, _)| active_name == expected_name)
                    && parser.observed_counts()
                        == &(Counts {
                            passed: 0,
                            failed: 0,
                            skipped: 0,
                        })
            }) {
                terminate(child, container_name)?;
                return Ok(Completed {
                    counts: Counts {
                        passed: 1,
                        failed: 0,
                        skipped: 0,
                    },
                });
            }
            let detail = active_test.as_ref().map_or_else(
                || {
                    if phase == "startup" {
                        format!(
                            "startup deadline expired after {:.3}s (limit {}s)",
                            phase_started_at.elapsed().as_secs_f64(),
                            limits.startup.as_secs_f64()
                        )
                    } else {
                        format!("{phase} deadline expired")
                    }
                },
                |(name, test_started_at)| {
                    format!(
                        "test {name} watchdog expired after {:.3}s (limit {}s)",
                        test_started_at.elapsed().as_secs_f64(),
                        limits.test.as_secs_f64()
                    )
                },
            );
            return Err(terminate_then(
                child,
                container_name,
                Failure::Timeout(detail),
            ));
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(250));
        match receiver.recv_timeout(wait) {
            Ok(Ok(line)) => {
                if stream_live {
                    stream_terminal(&line);
                }
                match line.text.as_str() {
                    "VMSA-INFRA PHASE prepare-start" => {
                        phase = "preparation";
                        phase_started_at = Instant::now();
                        deadline = phase_started_at + limits.build;
                    }
                    "VMSA-INFRA PHASE prepare-complete" if stream_live => eprintln!(
                        "vmsa-test: preparation completed in {:.3}s",
                        phase_started_at.elapsed().as_secs_f64()
                    ),
                    "VMSA-INFRA PHASE build-start" => {
                        phase = "build";
                        phase_started_at = Instant::now();
                        deadline = phase_started_at + limits.build;
                        next_build_progress = phase_started_at + BUILD_PROGRESS_INTERVAL;
                    }
                    "VMSA-INFRA PHASE build-complete" => {
                        if stream_live {
                            eprintln!(
                                "vmsa-test: firmware build completed in {:.3}s",
                                phase_started_at.elapsed().as_secs_f64()
                            );
                        }
                        phase = "packaging";
                        phase_started_at = Instant::now();
                        deadline = phase_started_at + limits.build;
                    }
                    "VMSA-INFRA PHASE package-complete" if stream_live => eprintln!(
                        "vmsa-test: packaging completed in {:.3}s",
                        phase_started_at.elapsed().as_secs_f64()
                    ),
                    _ => {}
                }
                if line.text == "VMSA-INFRA FVP_START" && !parser.has_begun() {
                    phase_started_at = Instant::now();
                    deadline = phase_started_at + limits.startup;
                    next_build_progress = phase_started_at + BUILD_PROGRESS_INTERVAL;
                    phase = "startup";
                }
                if line.text == "VMSA-INFRA CAPABILITY" && !parser.has_begun() {
                    return Err(terminate_then(
                        child,
                        container_name,
                        Failure::Capability("target baseline capability is unavailable".into()),
                    ));
                }
                if line.text.starts_with("VMSA-INFRA HARNESS_FAILURE") {
                    return Err(terminate_then(
                        child,
                        container_name,
                        Failure::Malformed(
                            "guest reported an unrecoverable harness exception".into(),
                        ),
                    ));
                }
                match parser.parse_line(&line.text) {
                    Ok(Some(event)) => {
                        if let Err(error) =
                            writeln!(results, "{}", line.text).and_then(|_| results.flush())
                        {
                            return Err(terminate_then(child, container_name, io_failure(error)));
                        }
                        if let Event::Begin { target } = &event {
                            if target != expected.target {
                                return Err(terminate_then(
                                    child,
                                    container_name,
                                    Failure::Malformed(format!(
                                        "BEGIN target {target} does not match requested {}",
                                        expected.target
                                    )),
                                ));
                            }
                            deadline = Instant::now() + limits.suite;
                            phase = "suite";
                        }
                        match &event {
                            Event::Run { name } => {
                                deadline = Instant::now() + limits.test;
                                phase = "test";
                                active_test = Some((name.clone(), Instant::now()));
                            }
                            Event::Pass { name } | Event::Fail { name, .. } => {
                                if let Some((active_name, test_started_at)) = active_test.take() {
                                    if stream_live {
                                        eprintln!(
                                            "vmsa-test: test {active_name} completed in {:.3}s \
                                             (watchdog limit {}s)",
                                            test_started_at.elapsed().as_secs_f64(),
                                            limits.test.as_secs_f64()
                                        );
                                    }
                                    debug_assert_eq!(active_name, *name);
                                }
                                deadline = Instant::now() + limits.suite;
                                phase = "suite";
                            }
                            Event::Skip { .. } => {
                                deadline = Instant::now() + limits.suite;
                                phase = "suite";
                            }
                            _ => {}
                        }
                        if matches!(event, Event::End(_)) {
                            deadline = Instant::now() + limits.shutdown;
                            phase = "shutdown";
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Err(terminate_then(
                            child,
                            container_name,
                            Failure::Malformed(error),
                        ));
                    }
                }
            }
            Ok(Err(error)) => {
                return Err(terminate_then(child, container_name, Failure::Io(error)));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if stream_live
                    && matches!(phase, "build" | "packaging")
                    && now >= next_build_progress
                {
                    eprintln!(
                        "vmsa-test: {phase} still running ({:.1}s elapsed, {}s limit)",
                        phase_started_at.elapsed().as_secs_f64(),
                        limits.build.as_secs_f64()
                    );
                    next_build_progress = now + BUILD_PROGRESS_INTERVAL;
                } else if stream_live && phase == "startup" && now >= next_build_progress {
                    eprintln!(
                        "vmsa-test: FVP startup still running ({:.1}s elapsed, {}s limit)",
                        phase_started_at.elapsed().as_secs_f64(),
                        limits.startup.as_secs_f64()
                    );
                    next_build_progress = now + BUILD_PROGRESS_INTERVAL;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().map_err(io_failure)?;
                return finish(status, parser, expected.termination);
            }
        }
    }
}

pub fn validate_lifecycle(output_root: &Path) -> Result<(), String> {
    let root = output_root.join(format!("doctor-supervisor-{}", std::process::id()));
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create supervisor self-check directory: {error}"))?;
    let validation = (|| {
        let success = run_lifecycle_case(
            &root,
            "end-before-exit",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.pass' '@@VMSA PASS host.pass' \
             '@@VMSA RUN host.expected-failure' \
             '@@VMSA FAIL host.expected-failure reason=wrong-value' \
             '@@VMSA END passed=1 failed=1 skipped=0'; sleep 0.1; exit 0",
        );
        match success {
            Ok(completed) if completed.counts.passed == 1 && completed.counts.failed == 1 => {}
            other => return Err(format!("END-before-exit self-check failed: {other:?}")),
        }

        let missing_end = run_lifecycle_case(
            &root,
            "exit-before-end",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.missing-end' '@@VMSA PASS host.missing-end'; exit 0",
        );
        if !matches!(missing_end, Err(Failure::Malformed(ref detail)) if detail.contains("missing END"))
        {
            return Err(format!(
                "exit-before-END self-check was not rejected exactly: {missing_end:?}"
            ));
        }

        let before_begin = run_lifecycle_case(&root, "exit-before-begin", "exit 9");
        if !matches!(before_begin, Err(Failure::Startup(_))) {
            return Err(format!(
                "exit-before-BEGIN self-check was not rejected exactly: {before_begin:?}"
            ));
        }

        let after_end = run_lifecycle_case(
            &root,
            "failure-after-end",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.after-end' '@@VMSA PASS host.after-end' \
             '@@VMSA END passed=1 failed=0 skipped=0'; exit 20",
        );
        if !matches!(after_end, Err(Failure::Build(_))) {
            return Err(format!(
                "failure-after-END self-check was not classified exactly: {after_end:?}"
            ));
        }

        let destructive = run_lifecycle_case_with_termination(
            &root,
            "expected-termination",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive'; exit 9",
            "host.destructive",
        );
        match destructive {
            Ok(completed)
                if completed.counts
                    == (Counts {
                        passed: 1,
                        failed: 0,
                        skipped: 0,
                    }) => {}
            other => {
                return Err(format!("expected-termination self-check failed: {other:?}"));
            }
        }

        let destructive_returned = run_lifecycle_case_with_termination(
            &root,
            "unexpected-destructive-return",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive' '@@VMSA PASS host.destructive' \
             '@@VMSA END passed=1 failed=0 skipped=0'; exit 0",
            "host.destructive",
        );
        if !matches!(destructive_returned, Err(Failure::Malformed(ref detail)) if detail.contains("returned normally"))
        {
            return Err(format!(
                "normal return from destructive test was not rejected exactly: {destructive_returned:?}"
            ));
        }

        let destructive_quiescent = run_lifecycle_case_with_termination(
            &root,
            "expected-destructive-quiescent",
            "printf '%s\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive'; sleep 10",
            "host.destructive",
        );
        if !matches!(
            destructive_quiescent,
            Ok(Completed {
                counts: Counts {
                    passed: 1,
                    failed: 0,
                    skipped: 0
                }
            })
        ) {
            return Err(format!(
                "quiescent destructive termination was not accepted exactly: {destructive_quiescent:?}"
            ));
        }

        for (name, script, expected) in [
            (
                "build-timeout",
                "trap 'exit 0' TERM INT; printf '%s\\n' \
                 'VMSA-INFRA PHASE build-start'; while :; do sleep 1; done",
                "build deadline expired",
            ),
            (
                "package-timeout",
                "trap 'exit 0' TERM INT; printf '%s\\n' \
                 'VMSA-INFRA PHASE build-start' \
                 'VMSA-INFRA PHASE build-complete'; while :; do sleep 1; done",
                "packaging deadline expired",
            ),
            (
                "startup-timeout",
                "trap 'exit 0' TERM INT; printf '%s\\n' \
                 'VMSA-INFRA FVP_START'; while :; do sleep 1; done",
                "startup deadline expired",
            ),
            (
                "suite-timeout",
                "trap 'exit 0' TERM INT; printf '%s\\n' \
                 '@@VMSA BEGIN protocol=1 target=host-self-check'; \
                 while :; do sleep 1; done",
                "suite deadline expired",
            ),
            (
                "test-timeout",
                "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
                 '@@VMSA RUN host.timeout'; trap 'exit 0' TERM INT; \
                 while :; do sleep 1; done",
                "test host.timeout watchdog expired",
            ),
        ] {
            let outcome = run_timeout_case(&root, name, script);
            if !matches!(outcome, Err(Failure::Timeout(ref detail)) if detail.contains(expected)) {
                return Err(format!(
                    "{name} self-check was not classified exactly: {outcome:?}"
                ));
            }
        }
        Ok(())
    })();
    let cleanup = std::fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot remove supervisor self-check directory: {error}"));
    validation.and(cleanup)
}

fn run_timeout_case(root: &Path, name: &str, script: &str) -> Result<Completed, Failure> {
    let directory = root.join(name);
    std::fs::create_dir_all(&directory).map_err(io_failure)?;
    let container_name = format!("vmsa-doctor-{name}-{}", std::process::id());
    let mut command = lifecycle_command(&container_name, script);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    run_with_limits(
        command,
        &container_name,
        "host-self-check",
        &directory,
        false,
        None,
        SupervisorLimits::doctor(),
    )
}

fn run_lifecycle_case(root: &Path, name: &str, script: &str) -> Result<Completed, Failure> {
    run_lifecycle_case_inner(root, name, script, None)
}

fn run_lifecycle_case_with_termination(
    root: &Path,
    name: &str,
    script: &str,
    expected_termination: &str,
) -> Result<Completed, Failure> {
    run_lifecycle_case_inner(root, name, script, Some(expected_termination))
}

fn run_lifecycle_case_inner(
    root: &Path,
    name: &str,
    script: &str,
    expected_termination: Option<&str>,
) -> Result<Completed, Failure> {
    let directory = root.join(name);
    std::fs::create_dir_all(&directory).map_err(io_failure)?;
    let container_name = format!("vmsa-doctor-{name}-{}", std::process::id());
    let mut command = lifecycle_command(&container_name, script);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    run(
        command,
        &container_name,
        "host-self-check",
        &directory,
        false,
        expected_termination,
    )
}

fn lifecycle_command(container_name: &str, script: &str) -> Command {
    let mut command = Command::new("podman");
    command
        .args([
            "run",
            "--rm",
            "--name",
            container_name,
            "--entrypoint",
            "/bin/sh",
        ])
        .arg(crate::settings::CONTAINER_IMAGE)
        .args(["-c", script]);
    command
}

fn finish(
    status: ExitStatus,
    parser: Parser,
    expected_termination: Option<&str>,
) -> Result<Completed, Failure> {
    if let Some(expected) = expected_termination {
        if parser.has_ended() {
            return Err(Failure::Malformed(format!(
                "destructive test {expected} returned normally instead of terminating its boot"
            )));
        }
        if parser.active_test() == Some(expected)
            && parser.observed_counts()
                == &(Counts {
                    passed: 0,
                    failed: 0,
                    skipped: 0,
                })
        {
            return Ok(Completed {
                counts: Counts {
                    passed: 1,
                    failed: 0,
                    skipped: 0,
                },
            });
        }
        return Err(Failure::Malformed(format!(
            "expected destructive termination during {expected}; active test was {:?} and process exited with {status}",
            parser.active_test()
        )));
    }
    if parser.has_ended() {
        let completed = parser
            .finish()
            .map(|counts| Completed { counts })
            .map_err(Failure::Malformed)?;
        return match status.code() {
            Some(0) => Ok(completed),
            Some(20) => Err(Failure::Build(
                "container reported cleanup or packaging failure after END".into(),
            )),
            _ => Err(Failure::Startup(format!(
                "container failed after END with {status}"
            ))),
        };
    }
    if parser.has_begun() {
        return Err(Failure::Malformed(format!(
            "missing END; container exited with {status}"
        )));
    }
    match status.code() {
        Some(20) => Err(Failure::Build("firmware build or packaging failed".into())),
        Some(22) => Err(Failure::Capability(
            "target baseline capability is unavailable".into(),
        )),
        _ => Err(Failure::Startup(format!(
            "container exited before BEGIN with {status}"
        ))),
    }
}

fn terminate(child: &mut Child, container_name: &str) -> Result<(), Failure> {
    let container_error = podman::stop_container(container_name)
        .err()
        .map(|error| format!("container stop failed: {error}"));
    match child.try_wait().map_err(io_failure)? {
        Some(_) => {}
        None => {
            child.kill().map_err(io_failure)?;
            child.wait().map_err(io_failure)?;
        }
    }
    match container_error {
        Some(error) => Err(Failure::Io(error)),
        None => Ok(()),
    }
}

fn terminate_then(child: &mut Child, container_name: &str, failure: Failure) -> Failure {
    match terminate(child, container_name) {
        Ok(()) => failure,
        Err(cleanup) => add_context(Some(failure), &format!("termination failed: {cleanup:?}")),
    }
}

fn add_context(previous: Option<Failure>, context: &str) -> Failure {
    let Some(previous) = previous else {
        return Failure::Io(context.into());
    };
    match previous {
        Failure::Build(detail) => Failure::Build(format!("{detail}; {context}")),
        Failure::Startup(detail) => Failure::Startup(format!("{detail}; {context}")),
        Failure::Capability(detail) => Failure::Capability(format!("{detail}; {context}")),
        Failure::Malformed(detail) => Failure::Malformed(format!("{detail}; {context}")),
        Failure::Timeout(detail) => Failure::Timeout(format!("{detail}; {context}")),
        Failure::Io(detail) => Failure::Io(format!("{detail}; {context}")),
        Failure::Cancelled(detail) => Failure::Cancelled(format!("{detail}; {context}")),
    }
}

fn reader_thread<R>(
    reader: R,
    stream: Stream,
    mut log: File,
    sender: mpsc::Sender<Result<Line, String>>,
) -> thread::JoinHandle<()>
where
    R: io::Read + Send + 'static,
{
    thread::spawn(move || {
        for line in bounded_lines(BufReader::new(reader)) {
            let message = match line {
                Ok(text) => {
                    if let Err(error) = writeln!(log, "{text}").and_then(|_| log.flush()) {
                        Err(format!("failed to write process log: {error}"))
                    } else {
                        Ok(Line { stream, text })
                    }
                }
                Err(error) => Err(format!("failed to read process output: {error}")),
            };
            if sender.send(message).is_err() {
                break;
            }
        }
    })
}

fn bounded_lines<R: io::BufRead>(mut reader: R) -> impl Iterator<Item = Result<String, io::Error>> {
    let mut finished = false;
    std::iter::from_fn(move || {
        if finished {
            return None;
        }
        let mut line = Vec::new();
        loop {
            let available = match reader.fill_buf() {
                Ok(available) => available,
                Err(error) => return Some(Err(error)),
            };
            if available.is_empty() {
                if line.is_empty() {
                    return None;
                }
                break;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(available.len(), |position| position + 1);
            let content = newline.unwrap_or(available.len());
            if line.len().saturating_add(content) > crate::settings::PROCESS_LINE_LIMIT {
                finished = true;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "process output line exceeds {}-byte limit",
                        crate::settings::PROCESS_LINE_LIMIT
                    ),
                )));
            }
            line.extend_from_slice(&available[..content]);
            reader.consume(consumed);
            if newline.is_some() {
                break;
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(
            String::from_utf8(line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })
}

fn stream_terminal(line: &Line) {
    let tone = terminal_tone(&line.text);
    match line.stream {
        Stream::Stdout => println!(
            "{}",
            tone.map_or_else(
                || line.text.clone(),
                |tone| crate::terminal::paint(
                    crate::terminal::stdout_has_color(),
                    tone,
                    &line.text
                )
            )
        ),
        Stream::Stderr => eprintln!(
            "{}",
            tone.map_or_else(
                || line.text.clone(),
                |tone| crate::terminal::paint(
                    crate::terminal::stderr_has_color(),
                    tone,
                    &line.text
                )
            )
        ),
    }
}

fn terminal_tone(line: &str) -> Option<crate::terminal::Tone> {
    use crate::terminal::Tone;

    if line.starts_with("@@VMSA PASS") {
        Some(Tone::Success)
    } else if line.starts_with("@@VMSA FAIL")
        || line.starts_with("VMSA-INFRA HARNESS_FAILURE")
        || line.contains(" PANIC ")
    {
        Some(Tone::Failure)
    } else if line.starts_with("@@VMSA SKIP") || line.starts_with("VMSA-INFRA CAPABILITY") {
        Some(Tone::Skipped)
    } else if line.starts_with("@@VMSA END") {
        Some(if line.contains(" failed=0") {
            Tone::Success
        } else {
            Tone::Failure
        })
    } else if line.starts_with("@@VMSA RUN") || line.contains("FVP_START") {
        Some(Tone::Active)
    } else if line.starts_with("VMSA-INFRA PHASE")
        || line.starts_with("@@VMSA BEGIN")
        || line.starts_with("@@VMSA CAP")
    {
        Some(Tone::Muted)
    } else {
        None
    }
}

fn create_log(directory: &Path, name: &str) -> Result<File, Failure> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(directory.join(name))
        .map_err(io_failure)
}

fn io_failure(error: io::Error) -> Failure {
    Failure::Io(error.to_string())
}
