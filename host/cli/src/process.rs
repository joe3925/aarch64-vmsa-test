use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Condvar, Mutex, OnceLock};
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
    Harness(String),
    Malformed(String),
    Timeout(String),
    TestTimeout { detail: String, counts: Counts },
    Io(String),
    Cancelled(String),
}

#[derive(Debug)]
pub struct Completed {
    pub counts: Counts,
}

pub trait RunObserver: Sync {
    fn event(&self, target: &str, event: &Event, protocol_line: &str);
}

#[derive(Clone, Copy)]
pub struct PreparationProgress<'a> {
    pub target: &'a str,
    pub index: usize,
    pub total: usize,
}

static PREPARATION_RENDERED: AtomicBool = AtomicBool::new(false);
const MAX_PARALLEL_PODMAN_HANDSHAKES: usize = 8;

struct LaunchGate {
    active: Mutex<usize>,
    available: Condvar,
}

struct LaunchPermit(&'static LaunchGate);

impl Drop for LaunchPermit {
    fn drop(&mut self) {
        let mut active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active = active.saturating_sub(1);
        self.0.available.notify_one();
    }
}

fn acquire_launch_permit() -> LaunchPermit {
    static GATE: OnceLock<LaunchGate> = OnceLock::new();
    let gate = GATE.get_or_init(|| LaunchGate {
        active: Mutex::new(0),
        available: Condvar::new(),
    });
    let mut active = gate
        .active
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    while *active >= MAX_PARALLEL_PODMAN_HANDSHAKES {
        active = gate
            .available
            .wait(active)
            .unwrap_or_else(|error| error.into_inner());
    }
    *active += 1;
    LaunchPermit(gate)
}

pub fn begin_preparation_progress() {
    PREPARATION_RENDERED.store(false, Ordering::Release);
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
    observer: Option<&dyn RunObserver>,
) -> Result<Completed, Failure> {
    run_with_limits(
        command,
        container_name,
        expected_target,
        output_directory,
        stream_live,
        expected_termination,
        observer,
        SupervisorLimits::production(expected_target),
    )
}

pub fn prepare(
    mut command: Command,
    container_name: &str,
    output_directory: &Path,
    progress: PreparationProgress<'_>,
) -> Result<(), Failure> {
    let mut container = ContainerGuard {
        name: container_name,
        active: true,
    };
    let stdout_log = create_log(output_directory, "container.stdout.log")?;
    let stderr_log = create_log(output_directory, "container.stderr.log")?;
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
    let mut deadline = Instant::now() + BUILD_TIMEOUT;
    let mut detail_step = 0;
    let mut detail_total = 1;
    render_preparation(
        progress,
        detail_step,
        detail_total,
        "checking firmware cache",
        false,
        false,
    );

    let mut result = loop {
        if crate::cancellation::requested() {
            break Err(terminate_then(
                &mut child,
                container_name,
                Failure::Cancelled(
                    "host cancellation requested during firmware preparation".into(),
                ),
            ));
        }
        if Instant::now() >= deadline {
            break Err(terminate_then(
                &mut child,
                container_name,
                Failure::Timeout("firmware preparation deadline expired".into()),
            ));
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(line)) => {
                match line.text.as_str() {
                    "VMSA-INFRA PHASE prepare-start" => {
                        render_preparation(progress, 0, 1, "preparing sources", false, false);
                    }
                    "VMSA-INFRA PHASE prepare-complete" => {
                        render_preparation(progress, 1, 1, "sources prepared", false, false);
                    }
                    "VMSA-INFRA PHASE build-start" => {
                        render_preparation(progress, 0, 1, "initializing build", false, false);
                    }
                    "VMSA-INFRA PHASE build-complete" => {
                        render_preparation(
                            progress,
                            detail_step,
                            detail_total,
                            "build steps complete",
                            false,
                            false,
                        );
                    }
                    "VMSA-INFRA PHASE package-complete" => {
                        detail_step = detail_total;
                        render_preparation(
                            progress,
                            detail_step,
                            detail_total,
                            "firmware packaged",
                            false,
                            false,
                        );
                    }
                    text if text.starts_with("VMSA-INFRA PHASE firmware-cache-hit ") => {
                        detail_step = 1;
                        detail_total = 1;
                        render_preparation(progress, 1, 1, "firmware cache hit", false, false);
                    }
                    text if text.starts_with("VMSA-INFRA BUILD_STEP ") => {
                        if let Some((index, total, name)) = parse_build_step(text) {
                            detail_step = index - 1;
                            detail_total = total;
                            render_preparation(
                                progress,
                                detail_step,
                                detail_total,
                                &format!("building {}", name.replace('-', " ")),
                                false,
                                false,
                            );
                        } else {
                            stream_terminal(&line);
                        }
                    }
                    _ if !crate::terminal::stderr_is_terminal() => stream_terminal(&line),
                    _ => {}
                }
                if matches!(
                    line.text.as_str(),
                    "VMSA-INFRA PHASE prepare-start"
                        | "VMSA-INFRA PHASE build-start"
                        | "VMSA-INFRA PHASE build-complete"
                ) {
                    deadline = Instant::now() + BUILD_TIMEOUT;
                }
            }
            Ok(Err(error)) => {
                break Err(terminate_then(
                    &mut child,
                    container_name,
                    Failure::Io(error),
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break match child.wait() {
                    Ok(status) if status.success() => Ok(()),
                    Ok(status) => Err(Failure::Build(format!(
                        "firmware preparation container exited with {status}"
                    ))),
                    Err(error) => Err(io_failure(error)),
                };
            }
        }
    };
    if stdout_thread.join().is_err() {
        result = Err(add_context(result.err(), "stdout reader thread panicked"));
    }
    if stderr_thread.join().is_err() {
        result = Err(add_context(result.err(), "stderr reader thread panicked"));
    }
    if let Err(error) = container.cleanup() {
        result = Err(add_context(
            result.err(),
            &format!("container cleanup failed: {error}"),
        ));
    }
    let failed = result.is_err();
    render_preparation(
        progress,
        if result.is_ok() {
            detail_total
        } else {
            detail_step
        },
        detail_total,
        if result.is_ok() { "complete" } else { "failed" },
        true,
        failed,
    );
    result
}

fn render_preparation(
    progress: PreparationProgress<'_>,
    phase: usize,
    phase_total: usize,
    label: &str,
    finished: bool,
    failed: bool,
) {
    let color = crate::terminal::stderr_has_color();
    let overall_done = if finished && !failed && phase == phase_total {
        progress.index
    } else {
        progress.index - 1
    };
    let overall = progress_bar(overall_done, progress.total, 24, color);
    let current = progress_bar(phase, phase_total, 18, color);
    let target = crate::terminal::paint(
        color,
        crate::terminal::Tone::Active,
        &format!("{:<14}", progress.target),
    );
    let label_tone = if failed {
        crate::terminal::Tone::Failure
    } else if finished && phase == phase_total {
        crate::terminal::Tone::Success
    } else {
        crate::terminal::Tone::Active
    };
    let label = crate::terminal::paint(color, label_tone, label);
    let overall_line = format!("firmware {overall} {overall_done}/{}", progress.total);
    let current_line = format!("  {target} {current} {phase}/{phase_total} {label}");
    if crate::terminal::stderr_is_terminal() {
        use std::io::Write as _;

        let rendered = PREPARATION_RENDERED.swap(true, Ordering::AcqRel);
        let prefix = if rendered { "\x1b[2A" } else { "" };
        eprint!("{prefix}\r\x1b[2K{overall_line}\n\r\x1b[2K{current_line}\n");
        let _ = std::io::stderr().flush();
    } else {
        eprintln!("{overall_line}\n{current_line}");
    }
}

fn parse_build_step(text: &str) -> Option<(usize, usize, &str)> {
    let mut fields = text.strip_prefix("VMSA-INFRA BUILD_STEP ")?.split(' ');
    let index = fields.next()?.strip_prefix("index=")?.parse().ok()?;
    let total = fields.next()?.strip_prefix("total=")?.parse().ok()?;
    let name = fields.next()?.strip_prefix("name=")?;
    if index == 0 || index > total || total == 0 || name.is_empty() || fields.next().is_some() {
        return None;
    }
    Some((index, total, name))
}

fn progress_bar(done: usize, total: usize, width: usize, color: bool) -> String {
    let filled = if total == 0 {
        0
    } else {
        done.saturating_mul(width) / total
    }
    .min(width);
    let filled_text = "#".repeat(filled);
    let empty_text = "-".repeat(width - filled);
    format!(
        "[{}{}]",
        crate::terminal::paint(color, crate::terminal::Tone::Success, &filled_text),
        crate::terminal::paint(color, crate::terminal::Tone::Muted, &empty_text)
    )
}

fn run_with_limits(
    mut command: Command,
    container_name: &str,
    expected_target: &str,
    output_directory: &Path,
    stream_live: bool,
    expected_termination: Option<&str>,
    observer: Option<&dyn RunObserver>,
    limits: SupervisorLimits,
) -> Result<Completed, Failure> {
    let mut container = ContainerGuard {
        name: container_name,
        active: true,
    };
    let stdout_log = create_log(output_directory, "container.stdout.log")?;
    let stderr_log = create_log(output_directory, "container.stderr.log")?;
    let mut results_log = create_log(output_directory, "results.log")?;
    // Podman Machine connects through ssh. Its MaxStartups policy starts
    // probabilistically dropping unauthenticated connections above ten, so
    // bound only that short handshake interval. Authenticated FVP sessions
    // still run at the user-requested concurrency.
    let mut launch_permit = Some(acquire_launch_permit());
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
        observer,
        &mut launch_permit,
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
    observer: Option<&dyn RunObserver>,
    launch_permit: &mut Option<LaunchPermit>,
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
            if let Some((name, test_started_at)) = active_test.as_ref() {
                let elapsed = test_started_at.elapsed();
                let detail = format!(
                    "test {name} watchdog expired after {:.3}s (limit {}s)",
                    elapsed.as_secs_f64(),
                    limits.test.as_secs_f64()
                );
                let completion = format!(
                    "@@VMSA FAIL {name} reason=test-watchdog-timeout expected={} actual={}",
                    protocol_millis(limits.test),
                    protocol_millis(elapsed)
                );
                match parser.parse_line(&completion) {
                    Ok(Some(Event::Fail { .. })) => {}
                    Ok(other) => {
                        return Err(terminate_then(
                            child,
                            container_name,
                            Failure::Malformed(format!(
                                "host watchdog completion produced unexpected event: {other:?}"
                            )),
                        ));
                    }
                    Err(error) => {
                        return Err(terminate_then(
                            child,
                            container_name,
                            Failure::Malformed(format!(
                                "host watchdog completion was rejected: {error}"
                            )),
                        ));
                    }
                }
                if let Err(error) = writeln!(results, "{completion}").and_then(|_| results.flush())
                {
                    return Err(terminate_then(child, container_name, io_failure(error)));
                }
                if stream_live {
                    stream_terminal(&Line {
                        stream: Stream::Stdout,
                        text: completion,
                    });
                }
                return Err(terminate_then(
                    child,
                    container_name,
                    Failure::TestTimeout {
                        detail,
                        counts: parser.observed_counts().clone(),
                    },
                ));
            }
            let detail = if phase == "startup" {
                format!(
                    "startup deadline expired after {:.3}s (limit {}s)",
                    phase_started_at.elapsed().as_secs_f64(),
                    limits.startup.as_secs_f64()
                )
            } else {
                format!("{phase} deadline expired")
            };
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
                launch_permit.take();
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
                        Failure::Harness(format!(
                            "guest reported an unrecoverable harness exception while {} was active: {}",
                            parser.active_test().unwrap_or("no test"),
                            line.text
                        )),
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
                        if let Some(observer) = observer {
                            observer.event(expected.target, &event, &line.text);
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
                                if let Some(expected_name) = expected.termination {
                                    if expected_name != name {
                                        return Err(terminate_then(
                                            child,
                                            container_name,
                                            Failure::Malformed(format!(
                                                "destructive completion for {name}; expected {expected_name}"
                                            )),
                                        ));
                                    }
                                    let counts = parser.observed_counts().clone();
                                    terminate(child, container_name)?;
                                    return Ok(Completed { counts });
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

        let harness_failure = run_lifecycle_case(
            &root,
            "guest-harness-failure",
            "printf '%s\n' 'VMSA-INFRA HARNESS_FAILURE kind=unexpected'; sleep 10",
        );
        if !matches!(
            harness_failure,
            Err(Failure::Harness(ref detail)) if detail.contains("kind=unexpected")
        ) {
            return Err(format!(
                "guest harness failure was not classified exactly: {harness_failure:?}"
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

        let destructive_pass = run_lifecycle_case_with_termination(
            &root,
            "expected-destructive-pass",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive' '@@VMSA PASS host.destructive'; sleep 10",
            "host.destructive",
        );
        match destructive_pass {
            Ok(completed)
                if completed.counts
                    == (Counts {
                        passed: 1,
                        failed: 0,
                        skipped: 0,
                    }) => {}
            other => {
                return Err(format!(
                    "expected destructive PASS self-check failed: {other:?}"
                ));
            }
        }

        let destructive_fail = run_lifecycle_case_with_termination(
            &root,
            "expected-destructive-fail",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive' \
             '@@VMSA FAIL host.destructive reason=wrong-fatal-kind expected=0 actual=1'; \
             sleep 10",
            "host.destructive",
        );
        match destructive_fail {
            Ok(completed)
                if completed.counts
                    == (Counts {
                        passed: 0,
                        failed: 1,
                        skipped: 0,
                    }) => {}
            other => {
                return Err(format!(
                    "expected destructive FAIL self-check failed: {other:?}"
                ));
            }
        }

        let destructive_returned = run_lifecycle_case_with_termination(
            &root,
            "unexpected-destructive-return",
            "printf '%s\\n' '@@VMSA BEGIN protocol=1 target=host-self-check' \
             '@@VMSA RUN host.destructive'; exit 0",
            "host.destructive",
        );
        if !matches!(destructive_returned, Err(Failure::Malformed(ref detail)) if detail.contains("expected PASS or FAIL"))
        {
            return Err(format!(
                "destructive return without completion was not rejected exactly: {destructive_returned:?}"
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
            Err(Failure::TestTimeout { ref detail, ref counts })
                if detail.contains("test host.destructive watchdog expired")
                    && counts.failed == 1
        ) {
            return Err(format!(
                "unmarked destructive hang was not rejected exactly: {destructive_quiescent:?}"
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
            if name == "test-timeout" {
                if !matches!(
                    outcome,
                    Err(Failure::TestTimeout { ref detail, ref counts })
                        if detail.contains(expected) && counts.failed == 1
                ) {
                    return Err(format!(
                        "{name} self-check was not classified exactly: {outcome:?}"
                    ));
                }
                let results = std::fs::read_to_string(root.join(name).join("results.log"))
                    .map_err(|error| format!("cannot read timeout self-check results: {error}"))?;
                if !results.contains(
                    "@@VMSA FAIL host.timeout reason=test-watchdog-timeout expected=300 actual=",
                ) {
                    return Err(format!(
                        "test-timeout self-check did not record a FAIL completion: {results:?}"
                    ));
                }
            } else if !matches!(
                outcome,
                Err(Failure::Timeout(ref detail)) if detail.contains(expected)
            ) {
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
    run_with_limits(
        command,
        &container_name,
        "host-self-check",
        &directory,
        false,
        expected_termination,
        None,
        if expected_termination.is_some() {
            SupervisorLimits::doctor()
        } else {
            SupervisorLimits::production("host-self-check")
        },
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
        return Err(Failure::Malformed(format!(
            "expected PASS or FAIL during destructive test {expected}; active test was {:?} and process exited with {status}",
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
        Failure::Harness(detail) => Failure::Harness(format!("{detail}; {context}")),
        Failure::Malformed(detail) => Failure::Malformed(format!("{detail}; {context}")),
        Failure::Timeout(detail) => Failure::Timeout(format!("{detail}; {context}")),
        Failure::TestTimeout { detail, counts } => Failure::TestTimeout {
            detail: format!("{detail}; {context}"),
            counts,
        },
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
        || line.starts_with("@@VMSA INFRA")
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

fn protocol_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_bar_scales_and_clamps() {
        assert_eq!(progress_bar(0, 4, 8, false), "[--------]");
        assert_eq!(progress_bar(1, 4, 8, false), "[##------]");
        assert_eq!(progress_bar(4, 4, 8, false), "[########]");
        assert_eq!(progress_bar(5, 4, 8, false), "[########]");
    }

    #[test]
    fn parses_structured_build_steps() {
        assert_eq!(
            parse_build_step("VMSA-INFRA BUILD_STEP index=2 total=5 name=hafnium"),
            Some((2, 5, "hafnium"))
        );
        assert_eq!(
            parse_build_step("VMSA-INFRA BUILD_STEP index=0 total=5 name=hafnium"),
            None
        );
    }
}
