#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os
import shutil
import subprocess
import urllib.request

import prepare

TESTS = Path("/workspace/tests")
OUTPUT = Path("/output")
SOURCE_TARGET_WORKSPACE = TESTS / "target"
TARGET_WORKSPACE = OUTPUT / "target-workspace"
CRATE_UNDER_TEST = Path("/workspace/aarch64-vmsa")
TARGET_TRIPLE = "aarch64-unknown-none-softfloat"
RUST_TOOLCHAIN = "nightly-2026-04-07"
RUSTUP_VERSION = "1.28.2"
RUSTUP_SHA256_X86_64 = "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c"
RUSTUP_SHA256_AARCH64 = "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c"
FIRMWARE_CACHE = Path("/cache/firmware-artifacts")


@dataclass(frozen=True)
class FirmwareImages:
    bl1: Path
    fip: Path


def _hash_tree(digest: "hashlib._Hash", root: Path, excluded: set[str]) -> None:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts) or not path.is_file():
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)


def firmware_cache_key(target: str, filter_value: str | None) -> str:
    digest = hashlib.sha256()
    digest.update(target.encode("utf-8"))
    digest.update(b"\0")
    digest.update((filter_value or "").encode("utf-8"))
    digest.update(b"\0")
    for revision in (
        prepare.TF_A_REVISION,
        prepare.TF_A_TESTS_REVISION,
        prepare.HAFNIUM_REVISION,
        prepare.TF_RMM_REVISION,
        RUST_TOOLCHAIN,
        TARGET_TRIPLE,
    ):
        digest.update(revision.encode("ascii"))
        digest.update(b"\0")
    _hash_tree(digest, SOURCE_TARGET_WORKSPACE, {"target", "external"})
    _hash_tree(digest, TESTS / "integration", {".git", "__pycache__"})
    _hash_tree(digest, CRATE_UNDER_TEST, {".git", "target", "__pycache__"})
    for source in (TESTS / "container" / "build.py", TESTS / "container" / "prepare.py"):
        digest.update(source.name.encode("ascii"))
        digest.update(source.read_bytes())
    return digest.hexdigest()


def restore_cached_build(target: str, filter_value: str | None) -> FirmwareImages | None:
    key = firmware_cache_key(target, filter_value)
    cached = FIRMWARE_CACHE / f"{target}-{key}"
    bl1 = cached / "bl1.bin"
    fip = cached / "fip.bin"
    if not bl1.is_file() or not fip.is_file() or bl1.stat().st_size == 0 or fip.stat().st_size == 0:
        return None
    artifacts = OUTPUT / "artifacts"
    shutil.copytree(cached, artifacts, dirs_exist_ok=True)
    os.utime(cached)
    print(f"VMSA-INFRA PHASE firmware-cache-hit key={key[:16]}", flush=True)
    return FirmwareImages(artifacts / "bl1.bin", artifacts / "fip.bin")


def cache_build(target: str, filter_value: str | None, images: FirmwareImages) -> None:
    key = firmware_cache_key(target, filter_value)
    FIRMWARE_CACHE.mkdir(parents=True, exist_ok=True)
    destination = FIRMWARE_CACHE / f"{target}-{key}"
    temporary = FIRMWARE_CACHE / f".{target}-{key}-{os.getpid()}"
    if temporary.exists():
        shutil.rmtree(temporary)
    shutil.copytree(OUTPUT / "artifacts", temporary)
    if destination.exists():
        shutil.rmtree(temporary)
    else:
        temporary.rename(destination)
    entries = sorted(
        FIRMWARE_CACHE.glob(f"{target}-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for stale in entries[8:]:
        shutil.rmtree(stale)
    require_file(images.bl1)
    require_file(images.fip)


def prepare_target_workspace() -> None:
    if TARGET_WORKSPACE.exists():
        shutil.rmtree(TARGET_WORKSPACE)

    def ignore(path: str, names: list[str]) -> set[str]:
        relative = Path(path).relative_to(SOURCE_TARGET_WORKSPACE)
        ignored = {"target"} if not relative.parts else set()
        if relative == Path("external"):
            ignored.add("aarch64-vmsa")
        return ignored.intersection(names)

    shutil.copytree(SOURCE_TARGET_WORKSPACE, TARGET_WORKSPACE, ignore=ignore)
    external = TARGET_WORKSPACE / "external"
    external.mkdir(parents=True, exist_ok=True)
    (external / "aarch64-vmsa").symlink_to(CRATE_UNDER_TEST, target_is_directory=True)


def checked(command: list[str], cwd: Path, log: Path, environment: dict[str, str] | None = None) -> None:
    with log.open("ab") as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if process.stdout is None:
            process.kill()
            process.wait()
            raise RuntimeError(f"failed to capture output for {command[0]}")
        for chunk in iter(process.stdout.readline, b""):
            output.write(chunk)
            output.flush()
        status = process.wait()
    if status != 0:
        raise subprocess.CalledProcessError(status, command)


def rust_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = "/cache/cargo"
    environment["RUSTUP_HOME"] = "/cache/rustup"
    environment["PATH"] = f"/cache/cargo/bin:{environment.get('PATH', '')}"
    return environment


def ensure_rust(log: Path) -> None:
    machine = os.uname().machine
    if machine == "x86_64":
        triple = "x86_64-unknown-linux-gnu"
        expected = RUSTUP_SHA256_X86_64
    elif machine in {"aarch64", "arm64"}:
        triple = "aarch64-unknown-linux-gnu"
        expected = RUSTUP_SHA256_AARCH64
    else:
        raise RuntimeError(f"unsupported container architecture {machine}")
    cargo = Path("/cache/cargo/bin/cargo")
    rustup = Path("/cache/cargo/bin/rustup")
    environment = rust_environment()
    if not rustup.is_file():
        installer = Path("/cache/rustup-init")
        url = f"https://static.rust-lang.org/rustup/archive/{RUSTUP_VERSION}/{triple}/rustup-init"
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"rustup-init checksum mismatch: expected {expected}, got {actual}")
        installer.write_bytes(data)
        installer.chmod(0o755)
        checked(
            [str(installer), "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "none"],
            TESTS,
            log,
            environment,
        )
    checked(
        [
            str(rustup), "toolchain", "install", RUST_TOOLCHAIN,
            "--profile", "minimal", "--target", TARGET_TRIPLE,
            "--component", "rust-src",
        ],
        TESTS,
        log,
        environment,
    )
    if not cargo.is_file():
        raise RuntimeError("pinned Rust installation did not provide cargo")


def build_rust(package: str, log: Path) -> Path:
    checked(
        [
            "/cache/cargo/bin/cargo", f"+{RUST_TOOLCHAIN}", "build",
            "-Z", "build-std=core", "--release", "--locked", "-p", package,
        ],
        TARGET_WORKSPACE,
        log,
        rust_environment(),
    )
    archive = TARGET_WORKSPACE / "target" / TARGET_TRIPLE / "release" / f"lib{package.replace('-', '_')}.a"
    if not archive.is_file():
        raise RuntimeError(f"Rust build did not produce {archive}")
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive, artifacts / archive.name)
    return archive


def write_filter_header(worktree: Path, filter_value: str | None) -> None:
    encoded = json.dumps(filter_value or "")
    header = worktree / "vmsa_filter.h"
    header.write_text(
        "#ifndef VMSA_FILTER_H\n#define VMSA_FILTER_H\n"
        f"#define VMSA_FILTER {encoded}\n"
        "#define VMSA_FILTER_LENGTH (sizeof(VMSA_FILTER) - 1U)\n#endif\n",
        encoding="utf-8",
    )


def build_tftf(
    worktree: Path,
    test_archive: Path | None,
    filter_value: str | None,
    log: Path,
    test_suite: str | None = None,
    build_realm_payload: bool = False,
    realm_payload_archive: Path | None = None,
) -> Path:
    write_filter_header(worktree, filter_value)
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PLAT=fvp", "DEBUG=1",
        "CROSS_COMPILE=aarch64-none-elf-",
        f"TESTS={test_suite or ('vmsa' if test_archive else 'psci')}",
    ]
    if test_archive:
        command.append(f"VMSA_TEST_LIB={test_archive}")
    if build_realm_payload:
        command.append("ENABLE_REALM_PAYLOAD_TESTS=1")
    if realm_payload_archive:
        command.append(f"VMSA_REALM_LIB={realm_payload_archive}")
    checked(command, worktree, log)
    image = worktree / "build" / "fvp" / "debug" / "tftf.bin"
    require_file(image)
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    for name in ("tftf.elf", "tftf.map"):
        source = image.parent / "tftf" / name
        if source.is_file():
            shutil.copy2(source, artifacts / name)
    return image


def build_tf_a(worktree: Path, log: Path, extra: list[str]) -> FirmwareImages:
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PLAT=fvp", "DEBUG=1",
        "CROSS_COMPILE=aarch64-none-elf-", "ENABLE_ASSERTIONS=1", *extra, "all", "fip",
    ]
    checked(command, worktree, log)
    directory = worktree / "build" / "fvp" / "debug"
    images = FirmwareImages(directory / "bl1.bin", directory / "fip.bin")
    require_file(images.bl1)
    require_file(images.fip)
    return images


def build_ns_el2(repositories: dict[str, Path], filter_value: str | None, log: Path) -> FirmwareImages:
    payload = build_rust("vmsa-test-ns-el2", log)
    tftf = build_tftf(repositories["tf-a-tests"], payload, filter_value, log)
    return build_tf_a(
        repositories["tf-a"],
        log,
        ["CTX_INCLUDE_AARCH32_REGS=0", f"BL33={tftf}"],
    )


def build_root_el3(repositories: dict[str, Path], filter_value: str | None, log: Path) -> FirmwareImages:
    payload = build_rust("vmsa-test-root-el3", log)
    tftf = build_tftf(repositories["tf-a-tests"], None, None, log)
    write_filter_header(repositories["tf-a"], filter_value)
    return build_tf_a(
        repositories["tf-a"], log,
        [
            "CTX_INCLUDE_AARCH32_REGS=0",
            "FVP_TRUSTED_SRAM_SIZE=512",
            "ENABLE_RME=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=2",
            f"BL33={tftf}",
            f"VMSA_ROOT_LIB={payload}",
            f"VMSA_TEST_INCLUDE={repositories['tf-a']}",
        ],
    )


def build_realm_el2(repositories: dict[str, Path], filter_value: str | None, log: Path) -> FirmwareImages:
    payload = build_rust("vmsa-test-realm-el2", log)
    tftf = build_tftf(repositories["tf-a-tests"], None, None, log)
    write_filter_header(repositories["tf-a"], filter_value)
    return build_tf_a(
        repositories["tf-a"], log,
        ["ENABLE_RME=1", f"BL33={tftf}", f"VMSA_REALM_LIB={payload}", f"VMSA_TEST_INCLUDE={repositories['tf-a']}"],
    )


def build_hafnium(worktree: Path, payload: Path, log: Path) -> Path:
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PROJECT=reference",
        "PLATFORM=secure_aem_v8a_fvp_vhe",
        f"GN_ARGS_EXTRA=vmsa_test_lib=\"{payload}\"",
    ]
    checked(command, worktree, log)
    candidates = list((worktree / "out" / "reference").rglob("hafnium.bin"))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Hafnium image, found {candidates}")
    elf_candidates = list((worktree / "out" / "reference").rglob("hafnium.elf"))
    if len(elf_candidates) != 1:
        raise RuntimeError(f"expected one Hafnium ELF, found {elf_candidates}")
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(elf_candidates[0], artifacts / "secure-el2-hafnium.elf")
    return candidates[0]


def stage_secure_partitions(tf_a_tests: Path, tftf: Path) -> Path:
    staging = OUTPUT / "secure-partitions"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    layout = TESTS / "integration" / "hafnium" / "files" / "sp_layout.json"
    shutil.copy2(layout, staging / layout.name)
    build_directory = tftf.parent
    for name in ["cactus.bin", "ivy.bin"]:
        source = build_directory / name
        require_file(source)
        shutil.copy2(source, staging / name)
    manifests = tf_a_tests / "spm" / "cactus" / "plat" / "arm" / "fvp" / "fdts"
    for name in ["cactus.dts", "cactus-secondary.dts", "cactus-tertiary.dts"]:
        source = manifests / name
        require_file(source)
        shutil.copy2(source, staging / name)
    ivy = tf_a_tests / "spm" / "ivy" / "app" / "plat" / "arm" / "fvp" / "fdts" / "ivy-sel1.dts"
    require_file(ivy)
    shutil.copy2(ivy, staging / ivy.name)
    return staging / layout.name


def build_secure_el2(repositories: dict[str, Path], filter_value: str | None, log: Path) -> FirmwareImages:
    payload = build_rust("vmsa-test-secure-el2", log)
    write_filter_header(repositories["hafnium"], filter_value)
    hafnium = build_hafnium(repositories["hafnium"], payload, log)
    tftf = build_tftf(repositories["tf-a-tests"], None, None, log)
    layout = stage_secure_partitions(repositories["tf-a-tests"], tftf)
    return build_tf_a(
        repositories["tf-a"], log,
        [
            "SPD=spmd",
            "SPMD_SPM_AT_SEL2=1",
            "ARM_ARCH_MINOR=5",
            "BRANCH_PROTECTION=1",
            "CTX_INCLUDE_PAUTH_REGS=1",
            "ENABLE_FEAT_MTE2=1",
            f"BL32={hafnium}",
            f"BL33={tftf}",
            f"SP_LAYOUT_FILE={layout}",
        ],
    )


def build_tf_rmm(worktree: Path, log: Path) -> Path:
    build = worktree / "build-vmsa"
    environment = os.environ.copy()
    environment["CROSS_COMPILE"] = "aarch64-none-elf-"
    checked([
        "cmake", "-G", "Ninja", "-S", str(worktree), "-B", str(build),
        "-DRMM_CONFIG=fvp_defcfg", "-DRMM_TOOLCHAIN=llvm", "-DCMAKE_BUILD_TYPE=Debug",
    ], worktree, log, environment)
    checked(["cmake", "--build", str(build)], worktree, log, environment)
    candidates = list(build.rglob("rmm.img"))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one TF-RMM image, found {candidates}")
    return candidates[0]


def build_realm_stage2(repositories: dict[str, Path], filter_value: str | None, log: Path) -> FirmwareImages:
    payload = build_rust("vmsa-test-realm-stage2", log)
    rmm = build_tf_rmm(repositories["tf-rmm"], log)
    tftf = build_tftf(
        repositories["tf-a-tests"],
        None,
        filter_value,
        log,
        test_suite="vmsa-realm",
        build_realm_payload=True,
        realm_payload_archive=payload,
    )
    return build_tf_a(
        repositories["tf-a"],
        log,
        [
            "ENABLE_RME=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=2",
            f"RMM={rmm}",
            f"BL33={tftf}",
        ],
    )


def build(target: str, repositories: dict[str, Path], filter_value: str | None) -> FirmwareImages:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    log = OUTPUT / "firmware.log"
    prepare_target_workspace()
    ensure_rust(log)
    if target == "ns-el2":
        images = build_ns_el2(repositories, filter_value, log)
    elif target == "secure-el2":
        images = build_secure_el2(repositories, filter_value, log)
    elif target == "realm-el2":
        images = build_realm_el2(repositories, filter_value, log)
    elif target == "realm-stage2":
        images = build_realm_stage2(repositories, filter_value, log)
    elif target == "root-el3":
        images = build_root_el3(repositories, filter_value, log)
    else:
        raise ValueError(f"unsupported target {target}")
    preserved = preserve_artifacts(target, repositories, images)
    cache_build(target, filter_value, preserved)
    return preserved


def preserve_artifacts(
    target: str,
    repositories: dict[str, Path],
    images: FirmwareImages,
) -> FirmwareImages:
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(images.bl1, artifacts / "bl1.bin")
    shutil.copy2(images.fip, artifacts / "fip.bin")
    tf_a_build = repositories["tf-a"] / "build" / "fvp" / "debug"
    for relative in (
        Path("bl1/bl1.elf"),
        Path("bl1/bl1.map"),
        Path("bl2/bl2.elf"),
        Path("bl2/bl2.map"),
        Path("bl31/bl31.elf"),
        Path("bl31/bl31.map"),
        Path("rmm/rmm.elf"),
        Path("rmm/rmm.map"),
    ):
        source = tf_a_build / relative
        if source.is_file():
            shutil.copy2(source, artifacts / f"{target}-{source.name}")
    if target == "realm-stage2":
        rmm_build = repositories["tf-rmm"] / "build-vmsa"
        for name in ("rmm.elf",):
            matches = list(rmm_build.rglob(name))
            if len(matches) != 1:
                raise RuntimeError(f"expected one TF-RMM {name}, found {matches}")
            shutil.copy2(matches[0], artifacts / f"{target}-{name}")
    return FirmwareImages(artifacts / "bl1.bin", artifacts / "fip.bin")


def require_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"required build artifact is missing: {path}")


if __name__ == "__main__":
    raise SystemExit("build.py is invoked by run.py")
