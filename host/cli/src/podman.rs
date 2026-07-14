use std::ffi::OsString;
use std::fmt;
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use crate::settings::{CACHE_VOLUME, CONTAINER_IMAGE, DEFAULT_VMSA_URL, SHUTDOWN_TIMEOUT};

#[derive(Debug)]
pub struct PodmanError {
    message: String,
    machine_hint: bool,
}

impl PodmanError {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            machine_hint: cfg!(windows),
        }
    }

    fn command(action: &str, output: &Output) -> Self {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        Self::unavailable(format!("Podman {action} failed: {detail}"))
    }
}

impl fmt::Display for PodmanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)?;
        if self.machine_hint {
            write!(
                formatter,
                "\nOn Windows, initialize and start the Podman machine with:\n  podman machine init\n  podman machine start"
            )?;
        }
        Ok(())
    }
}

pub fn validate_engine() -> Result<(), PodmanError> {
    let version = command_output(["--version"])?;
    if !version.status.success() {
        return Err(PodmanError::command("version check", &version));
    }
    let mut info = command_output(["info", "--format", "{{.Host.OS}}"])?;
    if !info.status.success() {
        info = command_output(["info", "--format", "{{.Host.Os}}"])?;
        if !info.status.success() {
            return Err(PodmanError::command("info", &info));
        }
    }
    if String::from_utf8_lossy(&info.stdout).trim() != "linux" {
        return Err(PodmanError::unavailable(
            "Podman is not providing Linux containers",
        ));
    }
    Ok(())
}

pub fn ensure_image() -> Result<(), PodmanError> {
    let inspect = command_output(["image", "inspect", CONTAINER_IMAGE]);
    match inspect {
        Ok(output) if output.status.success() => {}
        _ => {
            let pull = command_output(["pull", CONTAINER_IMAGE])?;
            if !pull.status.success() {
                return Err(PodmanError::command("image pull", &pull));
            }
        }
    }
    let architecture = command_output([
        "image",
        "inspect",
        "--format",
        "{{.Architecture}}",
        CONTAINER_IMAGE,
    ])?;
    if !architecture.status.success() {
        return Err(PodmanError::command(
            "image architecture inspection",
            &architecture,
        ));
    }
    let expected = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => {
            return Err(PodmanError::unavailable(format!(
                "unsupported host architecture: {other}"
            )));
        }
    };
    if String::from_utf8_lossy(&architecture.stdout).trim() != expected {
        return Err(PodmanError::unavailable(format!(
            "the pinned image does not provide the current host architecture ({expected})"
        )));
    }
    Ok(())
}

pub fn ensure_cache_volume() -> Result<(), PodmanError> {
    let inspect = command_output(["volume", "inspect", CACHE_VOLUME])?;
    if inspect.status.success() {
        return Ok(());
    }
    let create = command_output(["volume", "create", CACHE_VOLUME])?;
    if !create.status.success() {
        return Err(PodmanError::command("cache volume creation", &create));
    }
    Ok(())
}

pub fn validate_mounts(repository: &Path, crate_path: &Path) -> Result<(), PodmanError> {
    for (path, container_path, read_only, access) in [
        (repository, "/workspace/tests", false, "-w"),
        (crate_path, "/workspace/aarch64-vmsa", true, "-r"),
    ] {
        let mount = mount_argument(path, container_path, read_only);
        let output = command_output_os([
            OsString::from("run"),
            OsString::from("--rm"),
            OsString::from("--mount"),
            mount,
            OsString::from("--entrypoint"),
            OsString::from("/usr/bin/test"),
            OsString::from(CONTAINER_IMAGE),
            OsString::from(access),
            OsString::from(container_path),
        ])?;
        if !output.status.success() {
            return Err(PodmanError::command("mount validation", &output));
        }
    }
    Ok(())
}

pub fn validate_fvp() -> Result<(), PodmanError> {
    fvp_version().map(|_| ())
}

pub fn fvp_version() -> Result<String, PodmanError> {
    let output = command_output([
        "run",
        "--rm",
        "--entrypoint",
        "FVP_Base_RevC-2xAEMvA",
        CONTAINER_IMAGE,
        "--version",
    ])?;
    if !output.status.success() {
        return Err(PodmanError::command("FVP startup check", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let version = if stdout.is_empty() { stderr } else { stdout };
    if version.is_empty() {
        return Err(PodmanError::unavailable(
            "FVP version command returned no version text",
        ));
    }
    Ok(version.replace(['\r', '\n'], " "))
}

pub fn clone_default_crate(repository: &Path) -> Result<std::path::PathBuf, PodmanError> {
    let checkout = repository.join("target/external/default-checkout");
    if checkout.join("Cargo.toml").is_file() {
        return checkout.canonicalize().map_err(|error| {
            PodmanError::unavailable(format!("cannot canonicalize default checkout: {error}"))
        });
    }
    if checkout.exists() {
        std::fs::remove_dir_all(&checkout).map_err(|error| {
            PodmanError::unavailable(format!(
                "cannot remove incomplete default checkout: {error}"
            ))
        })?;
    }
    let output = command_output_os([
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--mount"),
        mount_argument(repository, "/workspace/tests", false),
        OsString::from("--entrypoint"),
        OsString::from("git"),
        OsString::from(CONTAINER_IMAGE),
        OsString::from("clone"),
        OsString::from("--filter=blob:none"),
        OsString::from(DEFAULT_VMSA_URL),
        OsString::from("/workspace/tests/target/external/default-checkout"),
    ])?;
    if !output.status.success() {
        return Err(PodmanError::command("default aarch64-vmsa clone", &output));
    }
    if !checkout.join("Cargo.toml").is_file() {
        return Err(PodmanError::unavailable(
            "default aarch64-vmsa clone does not contain Cargo.toml",
        ));
    }
    checkout.canonicalize().map_err(|error| {
        PodmanError::unavailable(format!("cannot canonicalize default checkout: {error}"))
    })
}

pub fn validate_termination() -> Result<(), PodmanError> {
    let name = format!("vmsa-doctor-termination-{}", std::process::id());
    let started = command_output([
        "run",
        "--detach",
        "--rm",
        "--name",
        &name,
        "--entrypoint",
        "python3",
        CONTAINER_IMAGE,
        "-c",
        "import time; time.sleep(60)",
    ])?;
    if !started.status.success() {
        return Err(PodmanError::command(
            "termination self-check startup",
            &started,
        ));
    }
    stop_container(&name)?;
    let inspect = command_output(["container", "inspect", &name])?;
    if inspect.status.success() {
        let removed = command_output(["rm", "--force", &name])?;
        if !removed.status.success() {
            return Err(PodmanError::command(
                "termination self-check emergency removal",
                &removed,
            ));
        }
        return Err(PodmanError::unavailable(
            "Podman termination self-check left the container running",
        ));
    }
    Ok(())
}

pub fn run_command(
    name: &str,
    repository: &Path,
    crate_path: &Path,
    output: &Path,
    target: &str,
    filter: Option<&str>,
) -> Command {
    let mut command = Command::new("podman");
    command
        .arg("run")
        .arg("--rm")
        .arg("--name")
        .arg(name)
        .arg("--env")
        .arg(format!("VMSA_RUN_ID={name}"))
        .arg("--mount")
        .arg(mount_argument(repository, "/workspace/tests", false))
        .arg("--mount")
        .arg(mount_argument(crate_path, "/workspace/aarch64-vmsa", true))
        .arg("--mount")
        .arg(format!("type=volume,src={CACHE_VOLUME},dst=/cache"))
        .arg("--mount")
        .arg(mount_argument(output, "/output", false))
        .arg("--workdir")
        .arg("/workspace/tests")
        .arg("--entrypoint")
        .arg("python3")
        .arg(CONTAINER_IMAGE)
        .arg("-B")
        .arg("/workspace/tests/container/run.py")
        .arg(target);
    if let Some(value) = filter {
        command.arg("--filter").arg(value);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

pub fn stop_container(name: &str) -> Result<(), PodmanError> {
    let exists = command_output(["container", "exists", name])?;
    if !exists.status.success() {
        return Ok(());
    }

    let timeout = SHUTDOWN_TIMEOUT.as_secs().to_string();
    let stopped = Command::new("podman")
        .args(["stop", "--time", &timeout, name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| PodmanError::unavailable(format!("cannot start Podman stop: {error}")))?;
    if matches!(
        wait_bounded(stopped, SHUTDOWN_TIMEOUT + Duration::from_secs(1))?,
        Some(status) if status.success()
    ) {
        return Ok(());
    }

    let killed = Command::new("podman")
        .args(["kill", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| PodmanError::unavailable(format!("cannot start Podman kill: {error}")))?;
    match wait_bounded(killed, Duration::from_secs(2))? {
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(PodmanError::unavailable(format!(
            "Podman could not stop or kill container {name}: kill exited with {status}"
        ))),
        None => Err(PodmanError::unavailable(format!(
            "Podman could not stop or kill container {name} within the shutdown deadline"
        ))),
    }
}

fn wait_bounded(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, PodmanError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => std::thread::park_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25)),
            ),
            Ok(None) => {
                child.kill().map_err(|error| {
                    PodmanError::unavailable(format!(
                        "cannot kill timed-out Podman command: {error}"
                    ))
                })?;
                child.wait().map_err(|error| {
                    PodmanError::unavailable(format!(
                        "cannot reap timed-out Podman command: {error}"
                    ))
                })?;
                return Ok(None);
            }
            Err(error) => {
                return Err(PodmanError::unavailable(format!(
                    "cannot query Podman command status: {error}"
                )));
            }
        }
    }
}

fn mount_argument(path: &Path, destination: &str, read_only: bool) -> OsString {
    let mut value = OsString::from("type=bind,src=");
    value.push(path.as_os_str());
    value.push(",dst=");
    value.push(destination);
    if read_only {
        value.push(",ro=true");
    }
    value
}

fn command_output<const N: usize>(arguments: [&str; N]) -> Result<Output, PodmanError> {
    command_output_os(arguments.map(OsString::from))
}

fn command_output_os<I, S>(arguments: I) -> Result<Output, PodmanError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new("podman")
        .args(arguments)
        .output()
        .map_err(|error| {
            PodmanError::unavailable(format!("Podman executable is unavailable: {error}"))
        })
}
