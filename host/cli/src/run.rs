use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::args::{Args, Command, Target};
use crate::podman;
use crate::process;
use crate::report::{self, TargetReport};

struct SuiteProgress {
    target: Target,
    completed: usize,
    total: usize,
    failed: u32,
    skipped: u32,
}

struct DashboardState {
    suites: Vec<SuiteProgress>,
    rendered: bool,
}

struct RuntimeDashboard {
    state: Mutex<DashboardState>,
    log: Mutex<File>,
    log_path: PathBuf,
}

impl RuntimeDashboard {
    fn create(repository: &Path, totals: &[(Target, usize)]) -> Result<Self, String> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_micros());
        let directory = repository
            .join("output/runs")
            .join(format!("session-{micros:020}-{}", std::process::id()));
        fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create session output directory: {error}"))?;
        let log_path = directory.join("results.log");
        let log = File::create(&log_path)
            .map_err(|error| format!("cannot create session results log: {error}"))?;
        Ok(Self {
            state: Mutex::new(DashboardState {
                suites: totals
                    .iter()
                    .map(|&(target, total)| SuiteProgress {
                        target,
                        completed: 0,
                        total,
                        failed: 0,
                        skipped: 0,
                    })
                    .collect(),
                rendered: false,
            }),
            log: Mutex::new(log),
            log_path,
        })
    }

    fn announce(&self) {
        eprintln!("detailed live results: {}", self.log_path.display());
        eprintln!(
            "inspect while running: tail -f '{}'",
            self.log_path.display()
        );
        self.render();
    }

    fn render(&self) {
        if !crate::terminal::stderr_is_terminal() {
            return;
        }
        use std::io::Write as _;

        let mut state = self.state.lock().expect("dashboard lock poisoned");
        let prefix = if state.rendered {
            format!("\x1b[{}A", state.suites.len())
        } else {
            String::new()
        };
        eprint!("{prefix}");
        let color = crate::terminal::stderr_has_color();
        for suite in &state.suites {
            let bar = runtime_progress_bar(suite.completed, suite.total, 24, color);
            let target = crate::terminal::paint(
                color,
                crate::terminal::Tone::Active,
                &format!("{:<14}", suite.target.as_str()),
            );
            let failures = crate::terminal::paint(
                color,
                if suite.failed == 0 {
                    crate::terminal::Tone::Muted
                } else {
                    crate::terminal::Tone::Failure
                },
                &format!("failed={}", suite.failed),
            );
            eprint!(
                "\r\x1b[2K{target} {bar} {}/{} {failures} skipped={}\n",
                suite.completed, suite.total, suite.skipped
            );
        }
        state.rendered = true;
        let _ = std::io::stderr().flush();
    }
}

impl process::RunObserver for RuntimeDashboard {
    fn event(&self, target: &str, event: &crate::protocol::Event, protocol_line: &str) {
        if let Ok(mut log) = self.log.lock() {
            let _ = writeln!(log, "[{target}] {protocol_line}");
            let _ = log.flush();
        }
        if !matches!(
            event,
            crate::protocol::Event::Pass { .. }
                | crate::protocol::Event::Fail { .. }
                | crate::protocol::Event::Skip { .. }
        ) {
            return;
        }
        {
            let mut state = self.state.lock().expect("dashboard lock poisoned");
            let Some(suite) = state
                .suites
                .iter_mut()
                .find(|suite| suite.target.as_str() == target)
            else {
                return;
            };
            suite.completed = suite.completed.saturating_add(1).min(suite.total);
            match event {
                crate::protocol::Event::Fail { .. } => {
                    suite.failed = suite.failed.saturating_add(1);
                }
                crate::protocol::Event::Skip { .. } => {
                    suite.skipped = suite.skipped.saturating_add(1);
                }
                _ => {}
            }
        }
        self.render();
    }
}

fn runtime_progress_bar(done: usize, total: usize, width: usize, color: bool) -> String {
    let filled = if total == 0 {
        0
    } else {
        done.saturating_mul(width) / total
    }
    .min(width);
    format!(
        "[{}{}]",
        crate::terminal::paint(color, crate::terminal::Tone::Success, &"#".repeat(filled)),
        crate::terminal::paint(
            color,
            crate::terminal::Tone::Muted,
            &"-".repeat(width - filled)
        )
    )
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExitCode {
    Success = 0,
    TestsFailed = 1,
    BuildFailed = 2,
    StartupFailed = 3,
    Malformed = 4,
    Timeout = 5,
    Capability = 6,
    InvalidSetup = 7,
    Cancelled = 130,
}

pub fn execute(args: Args) -> ExitCode {
    if let Err(error) = crate::cancellation::install() {
        return setup_error(error);
    }
    let repository = match locate_repository() {
        Ok(path) => path,
        Err(error) => return setup_error(error),
    };
    if matches!(args.command, Command::Clean) {
        return clean(&repository);
    }
    let Some(requested_crate) = args.crate_path.as_deref() else {
        return setup_error("--crate <path> is required for doctor and test".into());
    };
    let crate_path = match resolve_requested_crate(&repository, requested_crate) {
        Ok(path) => path,
        Err(error) => return setup_error(error),
    };
    match args.command {
        Command::Doctor => doctor(&repository, &crate_path),
        Command::Clean => clean(&repository),
        Command::Test(targets) => run_targets(
            &repository,
            &crate_path,
            &targets,
            args.filter.as_deref(),
            args.keep,
            args.max_concurrency,
            args.build_concurrency,
        ),
    }
}

fn doctor(repository: &Path, crate_path: &Path) -> ExitCode {
    let result = (|| {
        crate::catalog_plan::validate()?;
        crate::protocol::validate_parser()?;
        podman::validate_engine().map_err(|error| error.to_string())?;
        podman::ensure_image().map_err(|error| error.to_string())?;
        podman::ensure_cache_volume().map_err(|error| error.to_string())?;
        ensure_output_writable(repository)?;
        podman::validate_mounts(repository, crate_path).map_err(|error| error.to_string())?;
        podman::validate_fvp().map_err(|error| error.to_string())?;
        podman::validate_termination().map_err(|error| error.to_string())?;
        process::validate_lifecycle(&repository.join("output"))?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => {
            println!("doctor: host, Podman, mounts, image, cache, and FVP are ready");
            ExitCode::Success
        }
        Err(error) => setup_error(error),
    }
}

fn clean(repository: &Path) -> ExitCode {
    for path in [
        repository.join("output/runs"),
        repository.join("target/target"),
        repository.join("container/__pycache__"),
        repository.join("target/external/default-checkout"),
    ] {
        if let Err(error) = remove_if_present(&path) {
            return setup_error(format!("failed to clean {}: {error}", path.display()));
        }
    }
    let host_target = repository.join("host/target");
    if let Err(error) = remove_host_build_state(&host_target) {
        return setup_error(format!(
            "failed to clean {}: {error}",
            host_target.display()
        ));
    }
    let external = repository.join("target/external/aarch64-vmsa");
    if let Err(error) = remove_link_if_present(&external) {
        return setup_error(format!("failed to remove {}: {error}", external.display()));
    }
    println!("clean: generated output and local build state removed; cache volume preserved");
    ExitCode::Success
}

fn run_targets(
    repository: &Path,
    crate_path: &Path,
    targets: &[Target],
    filter: Option<&str>,
    keep: bool,
    max_concurrency: usize,
    build_concurrency: usize,
) -> ExitCode {
    if let Err(error) = podman::validate_engine()
        .and_then(|_| podman::ensure_image())
        .and_then(|_| podman::ensure_cache_volume())
    {
        eprintln!("vmsa-test: {error}");
        return ExitCode::StartupFailed;
    }
    if let Err(error) = podman::validate_mounts(repository, crate_path) {
        return setup_error(error.to_string());
    }
    #[derive(Clone)]
    struct PlannedRun {
        target: Target,
        filter: Option<String>,
        expects_termination: bool,
        test_count: usize,
    }

    let mut planned = Vec::new();
    let mut reports = Vec::with_capacity(targets.len());
    let mut final_code = ExitCode::Success;
    for &target in targets {
        let plans = match crate::catalog_plan::plan(target, filter) {
            Ok(plans) => plans,
            Err(error) => {
                final_code = final_code.max(ExitCode::InvalidSetup);
                reports.push(failure_report(target, "invalid", error));
                continue;
            }
        };
        if plans.is_empty() {
            final_code = final_code.max(ExitCode::InvalidSetup);
            reports.push(failure_report(
                target,
                "invalid",
                "the filter matched no registered adapter case".into(),
            ));
            continue;
        }
        for plan in plans {
            planned.push(PlannedRun {
                target,
                filter: plan.filter,
                expects_termination: plan.expects_termination,
                test_count: plan.test_count,
            });
        }
    }
    if final_code != ExitCode::Success {
        print!("{}", report::combined_for_terminal(&reports));
        return final_code;
    }

    let build_targets = targets
        .iter()
        .copied()
        .filter(|target| planned.iter().any(|run| run.target == *target))
        .collect::<Vec<_>>();
    let build_target_names = build_targets
        .iter()
        .map(|target| target.as_str())
        .collect::<Vec<_>>();
    process::begin_preparation_progress(&build_target_names);
    let build_worker_count = build_concurrency.min(build_targets.len()).max(1);
    let next_build = AtomicUsize::new(0);
    let build_results = Mutex::new(
        std::iter::repeat_with(|| None)
            .take(build_targets.len())
            .collect::<Vec<_>>(),
    );
    thread::scope(|scope| {
        for _ in 0..build_worker_count {
            scope.spawn(|| {
                loop {
                    let index = next_build.fetch_add(1, Ordering::Relaxed);
                    let Some(&target) = build_targets.get(index) else {
                        break;
                    };
                    let result = prepare_target(repository, crate_path, target);
                    build_results
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())[index] = Some(result);
                }
            });
        }
    });
    let build_results = build_results
        .into_inner()
        .unwrap_or_else(|error| error.into_inner());
    let mut firmware_cache_keys = Vec::with_capacity(build_targets.len());
    for (&target, result) in build_targets.iter().zip(build_results) {
        match result.expect("each firmware build must produce a result") {
            Ok(key) => firmware_cache_keys.push((target, key)),
            Err((error, directory)) => {
                eprintln!("preparation artifacts retained at {}", directory.display());
                let (outcome, code, detail) = classify_failure(error);
                reports.push(failure_report(target, outcome, detail));
                final_code = final_code.max(code);
            }
        }
    }
    if final_code != ExitCode::Success {
        print!("{}", report::combined_for_terminal(&reports));
        return final_code;
    }

    let fvp_version = match podman::fvp_version() {
        Ok(version) => version,
        Err(error) => {
            eprintln!("vmsa-test: {error}");
            return ExitCode::StartupFailed;
        }
    };

    let worker_count = max_concurrency.min(planned.len()).max(1);
    eprintln!(
        "vmsa-test: firmware preparation complete; running {} boot(s) with up to {worker_count} FVP instance(s)",
        planned.len()
    );
    let suite_totals = targets
        .iter()
        .copied()
        .filter_map(|target| {
            let total = planned
                .iter()
                .filter(|run| run.target == target)
                .map(|run| run.test_count)
                .sum::<usize>();
            (total != 0).then_some((target, total))
        })
        .collect::<Vec<_>>();
    let dashboard = match RuntimeDashboard::create(repository, &suite_totals) {
        Ok(dashboard) => Arc::new(dashboard),
        Err(error) => return setup_error(error),
    };
    dashboard.announce();
    let next = AtomicUsize::new(0);
    let completed = Mutex::new(
        std::iter::repeat_with(|| None)
            .take(planned.len())
            .collect::<Vec<_>>(),
    );
    thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(run) = planned.get(index) else {
                        break;
                    };
                    let result = if crate::cancellation::requested() {
                        (
                            failure_report(
                                run.target,
                                "cancelled",
                                "host cancellation requested before boot launch".into(),
                            ),
                            ExitCode::Cancelled,
                        )
                    } else {
                        let firmware_cache_key = firmware_cache_keys
                            .iter()
                            .find_map(|(target, key)| (*target == run.target).then_some(key.as_str()))
                            .expect("every planned target must have a firmware cache key");
                        run_target(
                            repository,
                            crate_path,
                            run.target,
                            run.filter.as_deref(),
                            run.expects_termination,
                            keep,
                            Some(dashboard.as_ref()),
                            &fvp_version,
                            firmware_cache_key,
                        )
                    };
                    completed.lock().expect("result lock poisoned")[index] = Some(result);
                }
            });
        }
    });
    for result in completed.into_inner().expect("result lock poisoned") {
        let (report, code) = result.expect("every planned run must produce a result");
        final_code = final_code.max(code);
        reports.push(report);
    }
    let summary = report::combined_for_terminal(&reports);
    print!("{summary}");
    final_code
}

fn prepare_target(
    repository: &Path,
    crate_path: &Path,
    target: Target,
) -> Result<String, (process::Failure, PathBuf)> {
    let run_id = format!("prepare-{}", run_id(target));
    let directory = repository.join("output/runs").join(&run_id);
    create_artifacts(&directory)
        .map_err(process::Failure::Io)
        .map_err(|error| (error, directory.clone()))?;
    let container_name = format!("vmsa-{run_id}");
    let command = podman::prepare_command(
        &container_name,
        repository,
        crate_path,
        &directory,
        target.as_str(),
    );
    let result = process::prepare(
        command,
        &container_name,
        &directory,
        process::PreparationProgress {
            target: target.as_str(),
        },
    );
    if result.is_ok() {
        if let Err(error) = fs::remove_dir_all(&directory) {
            eprintln!(
                "warning: could not remove successful preparation {}: {error}",
                directory.display()
            );
        }
    }
    result.map_err(|error| (error, directory))
}

fn run_target(
    repository: &Path,
    crate_path: &Path,
    target: Target,
    filter: Option<&str>,
    expects_termination: bool,
    keep: bool,
    observer: Option<&dyn process::RunObserver>,
    fvp_version: &str,
    firmware_cache_key: &str,
) -> (TargetReport, ExitCode) {
    let run_id = run_id(target);
    let directory = repository.join("output/runs").join(&run_id);
    if let Err(error) = create_artifacts(&directory) {
        return (
            failure_report(target, "invalid", error.clone()),
            setup_error(error),
        );
    }
    if let Err(error) = write_provenance(
        &directory,
        repository,
        crate_path,
        target,
        filter,
        fvp_version,
    ) {
        return (
            failure_report(target, "startup-error", error.clone()),
            setup_error(error),
        );
    }
    let mut host_log = match open_append(&directory.join("host.log")) {
        Ok(file) => file,
        Err(error) => {
            let detail = format!("cannot open host log: {error}");
            return (
                failure_report(target, "startup-error", detail),
                ExitCode::StartupFailed,
            );
        }
    };
    if let Err(error) = log(
        &mut host_log,
        &format!(
            "run={run_id} target={} crate={} expects_termination={expects_termination}",
            target.as_str(),
            crate_path.display()
        ),
    ) {
        let detail = format!("cannot write host log: {error}");
        return (
            failure_report(target, "startup-error", detail),
            ExitCode::StartupFailed,
        );
    }
    // The cache worktree key is inherited from the container name. A PID-only
    // name collides after normal Windows PID reuse when an interrupted run has
    // intentionally retained its disposable worktree for diagnosis.
    let container_name = format!("vmsa-{run_id}");
    let command = podman::run_command(
        &container_name,
        repository,
        crate_path,
        &directory,
        target.as_str(),
        filter,
        firmware_cache_key,
    );
    if let Err(error) = append_provenance(
        &directory,
        &format!(
            "podman_command={command:?}\ncommand_logs=firmware.log,container.stdout.log,container.stderr.log\n"
        ),
    ) {
        return (
            failure_report(target, "startup-error", error.clone()),
            setup_error(error),
        );
    }
    let mut command = Some(command);
    let completed = loop {
        let result = process::run(
            command
                .take()
                .expect("each Podman launch attempt must have a command"),
            &container_name,
            target.as_str(),
            &directory,
            observer.is_none(),
            expects_termination.then_some(filter.unwrap_or_default()),
            observer,
        );
        if !matches!(result, Err(process::Failure::Startup(_)))
            || !transient_podman_ssh_failure(&directory)
            || crate::cancellation::requested()
        {
            break result;
        }
        let _ = log(
            &mut host_log,
            "retrying Podman launch after transient SSH handshake failure",
        );
        command = Some(podman::run_command(
            &container_name,
            repository,
            crate_path,
            &directory,
            target.as_str(),
            filter,
            firmware_cache_key,
        ));
    };
    let (mut report, mut code) = match completed {
        Ok(completed)
            if completed.counts.passed == 0
                && completed.counts.failed == 0
                && completed.counts.skipped == 0 =>
        {
            (
                TargetReport {
                    target,
                    counts: Some(completed.counts),
                    outcome: "invalid",
                    detail: Some("the filter matched no applicable tests".into()),
                },
                ExitCode::InvalidSetup,
            )
        }
        Ok(completed)
            if completed.counts.passed == 0
                && completed.counts.failed == 0
                && completed.counts.skipped > 0 =>
        {
            (
                TargetReport {
                    target,
                    counts: Some(completed.counts),
                    outcome: "unsupported",
                    detail: Some("every selected test was skipped".into()),
                },
                ExitCode::Capability,
            )
        }
        Ok(completed) if completed.counts.failed == 0 => (
            TargetReport {
                target,
                counts: Some(completed.counts),
                outcome: "passed",
                detail: None,
            },
            ExitCode::Success,
        ),
        Ok(completed) => (
            TargetReport {
                target,
                counts: Some(completed.counts),
                outcome: "failed",
                detail: None,
            },
            ExitCode::TestsFailed,
        ),
        Err(process::Failure::TestTimeout { detail, counts }) => (
            TargetReport {
                target,
                counts: Some(counts),
                outcome: "timeout",
                detail: Some(detail),
            },
            ExitCode::Timeout,
        ),
        Err(error) => {
            let (outcome, code, detail) = classify_failure(error);
            (failure_report(target, outcome, detail), code)
        }
    };
    if let Err(error) = append_reported_capabilities(&directory) {
        let detail = format!("cannot complete provenance manifest: {error}");
        report = failure_report(target, "startup-error", detail);
        code = ExitCode::StartupFailed;
    }
    let log_message = match report.detail.as_deref() {
        Some(detail) => format!("outcome={} detail={detail}", report.outcome),
        None => format!("outcome={}", report.outcome),
    };
    if let Err(error) = log(&mut host_log, &log_message) {
        let detail = format!("cannot write host log: {error}");
        report = failure_report(target, "startup-error", detail);
        code = ExitCode::StartupFailed;
    }
    let summary = report::combined(std::slice::from_ref(&report));
    if let Err(error) = fs::write(directory.join("summary.txt"), summary) {
        let detail = format!("cannot write run summary: {error}");
        report = failure_report(target, "startup-error", detail);
        code = ExitCode::StartupFailed;
    }
    if code == ExitCode::Success && !keep {
        if let Err(error) = fs::remove_dir_all(&directory) {
            eprintln!(
                "warning: could not remove successful run {}: {error}",
                directory.display()
            );
        }
    } else if observer.is_none() {
        eprintln!("artifacts retained at {}", directory.display());
    }
    (report, code)
}

fn transient_podman_ssh_failure(directory: &Path) -> bool {
    fs::read_to_string(directory.join("container.stderr.log"))
        .is_ok_and(|stderr| stderr.contains("ssh: handshake failed: EOF"))
}

fn classify_failure(error: process::Failure) -> (&'static str, ExitCode, String) {
    match error {
        process::Failure::Build(detail) => ("build-error", ExitCode::BuildFailed, detail),
        process::Failure::Startup(detail) => ("startup-error", ExitCode::StartupFailed, detail),
        process::Failure::Capability(detail) => ("unsupported", ExitCode::Capability, detail),
        process::Failure::Harness(detail) => ("harness-error", ExitCode::Malformed, detail),
        process::Failure::Malformed(detail) => ("malformed", ExitCode::Malformed, detail),
        process::Failure::Timeout(detail) => ("timeout", ExitCode::Timeout, detail),
        process::Failure::TestTimeout { .. } => {
            unreachable!("test timeouts are classified with their observed counts")
        }
        process::Failure::Io(detail) => ("startup-error", ExitCode::StartupFailed, detail),
        process::Failure::Cancelled(detail) => ("cancelled", ExitCode::Cancelled, detail),
    }
}

fn failure_report(target: Target, outcome: &'static str, detail: String) -> TargetReport {
    TargetReport {
        target,
        counts: None,
        outcome,
        detail: Some(detail),
    }
}

fn locate_repository() -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current);
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.to_path_buf());
    }
    for candidate in candidates {
        for ancestor in candidate.ancestors() {
            if ancestor.join("host/Cargo.toml").is_file()
                && ancestor.join("container/run.py").is_file()
            {
                return ancestor
                    .canonicalize()
                    .map_err(|error| format!("cannot canonicalize repository root: {error}"));
            }
        }
    }
    Err("could not locate aarch64-vmsa-test repository root".into())
}

fn resolve_crate(path: &Path) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("invalid aarch64-vmsa path {}: {error}", path.display()))?;
    if !canonical.join("Cargo.toml").is_file() {
        return Err(format!(
            "{} does not contain Cargo.toml",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn resolve_requested_crate(repository: &Path, requested: &Path) -> Result<PathBuf, String> {
    if requested == Path::new("default") {
        podman::validate_engine().map_err(|error| error.to_string())?;
        podman::ensure_image().map_err(|error| error.to_string())?;
        podman::clone_default_crate(repository).map_err(|error| error.to_string())
    } else {
        resolve_crate(requested)
    }
}

fn ensure_output_writable(repository: &Path) -> Result<(), String> {
    let output = repository.join("output");
    fs::create_dir_all(&output)
        .map_err(|error| format!("cannot create {}: {error}", output.display()))?;
    let probe = output.join(format!(".write-probe-{}", std::process::id()));
    fs::write(&probe, b"probe")
        .map_err(|error| format!("output directory is not writable: {error}"))?;
    fs::remove_file(probe).map_err(|error| format!("cannot remove output probe: {error}"))
}

fn create_artifacts(directory: &Path) -> Result<(), String> {
    fs::create_dir_all(directory)
        .map_err(|error| format!("cannot create run directory: {error}"))?;
    for name in [
        "host.log",
        "container.stdout.log",
        "container.stderr.log",
        "firmware.log",
        "uart.log",
        "results.log",
        "summary.txt",
        "provenance.txt",
    ] {
        File::create(directory.join(name))
            .map_err(|error| format!("cannot create {name}: {error}"))?;
    }
    Ok(())
}

fn write_provenance(
    directory: &Path,
    repository: &Path,
    crate_path: &Path,
    target: Target,
    filter: Option<&str>,
    fvp_version: &str,
) -> Result<(), String> {
    let test_repository = git_provenance(repository);
    let vmsa_repository = git_provenance(crate_path);
    let test_fingerprint = repository_fingerprint(repository)?;
    let vmsa_fingerprint = repository_fingerprint(crate_path)?;
    let contents = format!(
        "test_repository_revision={}\n\
         test_repository_dirty={}\n\
         test_repository_content_fingerprint=fnv1a64:{}\n\
         vmsa_revision={}\n\
         vmsa_dirty={}\n\
         vmsa_content_fingerprint=fnv1a64:{}\n\
         container_image={}\n\
         tf_a_revision={}\n\
         tf_a_tests_revision={}\n\
         hafnium_revision={}\n\
         tf_rmm_revision={}\n\
         fvp_version={}\n\
         host_os={}\n\
         host_arch={}\n\
         boot_profile={}\n\
         filter={}\n\
         target_triple=aarch64-unknown-none-softfloat\n",
        test_repository.revision,
        test_repository.dirty,
        test_fingerprint,
        vmsa_repository.revision,
        vmsa_repository.dirty,
        vmsa_fingerprint,
        crate::settings::CONTAINER_IMAGE,
        crate::settings::TF_A_REVISION,
        crate::settings::TF_A_TESTS_REVISION,
        crate::settings::HAFNIUM_REVISION,
        crate::settings::TF_RMM_REVISION,
        fvp_version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        target.as_str(),
        filter.unwrap_or("<none>"),
    );
    fs::write(directory.join("provenance.txt"), contents)
        .map_err(|error| format!("cannot write provenance manifest: {error}"))
}

fn repository_fingerprint(repository: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_fingerprint_files(repository, repository, &mut files)?;
    files.sort();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for path in files {
        let relative = path
            .strip_prefix(repository)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        update_fnv1a(&mut hash, normalized.as_bytes());
        update_fnv1a(&mut hash, &[0]);
        let mut file = File::open(&path)
            .map_err(|error| format!("cannot fingerprint {}: {error}", path.display()))?;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| format!("cannot fingerprint {}: {error}", path.display()))?;
            if count == 0 {
                break;
            }
            update_fnv1a(&mut hash, &buffer[..count]);
        }
        update_fnv1a(&mut hash, &[0xff]);
    }
    Ok(format!("{hash:016x}"))
}

fn collect_fingerprint_files(
    repository: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot fingerprint {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read fingerprint entry in {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(repository)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
        let is_test_repository = repository.join("host/Cargo.toml").is_file()
            && repository.join("container/run.py").is_file();
        if fingerprint_path_excluded(relative, is_test_repository) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_fingerprint_files(repository, &path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn fingerprint_path_excluded(relative: &Path, is_test_repository: bool) -> bool {
    let normalized = relative.to_string_lossy().replace('\\', "/");
    normalized == ".git"
        || normalized.starts_with(".git/")
        || normalized == ".upstream-inspect"
        || normalized.starts_with(".upstream-inspect/")
        || normalized == "output"
        || normalized.starts_with("output/")
        || normalized == "host/target"
        || normalized.starts_with("host/target/")
        || normalized == "target/target"
        || normalized.starts_with("target/target/")
        || normalized == "target/external"
        || normalized.starts_with("target/external/")
        || normalized == "container/__pycache__"
        || normalized.starts_with("container/__pycache__/")
        || (!is_test_repository && (normalized == "target" || normalized.starts_with("target/")))
}

fn update_fnv1a(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

struct GitProvenance {
    revision: String,
    dirty: String,
}

fn git_provenance(repository: &Path) -> GitProvenance {
    let revision = ProcessCommand::new("git")
        .current_dir(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unavailable".into());
    let dirty = ProcessCommand::new("git")
        .current_dir(repository)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || "unknown".into(),
            |output| {
                if output.stdout.is_empty() {
                    "false".into()
                } else {
                    "true".into()
                }
            },
        );
    GitProvenance { revision, dirty }
}

fn append_provenance(directory: &Path, contents: &str) -> Result<(), String> {
    let mut manifest = open_append(&directory.join("provenance.txt"))
        .map_err(|error| format!("cannot open provenance manifest: {error}"))?;
    manifest
        .write_all(contents.as_bytes())
        .and_then(|_| manifest.flush())
        .map_err(|error| format!("cannot append provenance manifest: {error}"))
}

fn append_reported_capabilities(directory: &Path) -> Result<(), String> {
    let results = fs::read_to_string(directory.join("results.log"))
        .map_err(|error| format!("cannot read protocol results for provenance: {error}"))?;
    let mut capabilities = String::new();
    for line in results.lines() {
        if let Some(capability) = line.strip_prefix("@@VMSA CAP ") {
            capabilities.push_str("architecture_capability=");
            capabilities.push_str(capability);
            capabilities.push('\n');
        }
    }
    append_provenance(directory, &capabilities)
}

fn run_id(target: Target) -> String {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_micros());
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        "{}-{micros:020}-{}-{sequence:06}",
        target.as_str(),
        std::process::id()
    )
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn log(file: &mut File, message: &str) -> std::io::Result<()> {
    writeln!(file, "{message}")?;
    file.flush()
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_host_build_state(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let executable = std::env::current_exe()?.canonicalize()?;
    if !executable.starts_with(path) {
        return remove_if_present(path);
    }
    remove_tree_except(path, &executable)
}

fn remove_tree_except(path: &Path, preserved: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            remove_tree_except(&entry_path, preserved)?;
            match fs::remove_dir(&entry_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error),
            }
        } else if entry_path.canonicalize()? != preserved {
            fs::remove_file(entry_path)?;
        }
    }
    Ok(())
}

fn remove_link_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            remove_symlink(path, metadata.file_type())
        }
        Ok(metadata) if metadata.is_file() => fs::remove_file(removable_path(path)),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir(removable_path(path)),
        Ok(_) => fs::remove_file(removable_path(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn remove_symlink(path: &Path, _: fs::FileType) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[cfg(windows)]
fn remove_symlink(path: &Path, file_type: fs::FileType) -> std::io::Result<()> {
    use std::os::windows::fs::FileTypeExt;

    if file_type.is_symlink_dir() {
        fs::remove_dir(removable_path(path))
    } else {
        fs::remove_file(removable_path(path))
    }
}

#[cfg(not(windows))]
fn removable_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(windows)]
fn removable_path(path: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    const VERBATIM_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    if wide.starts_with(&VERBATIM_PREFIX) {
        wide.drain(..VERBATIM_PREFIX.len());
    }
    PathBuf::from(OsString::from_wide(&wide))
}

fn setup_error(error: String) -> ExitCode {
    eprintln!("vmsa-test: {error}");
    ExitCode::InvalidSetup
}
