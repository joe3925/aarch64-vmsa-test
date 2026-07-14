#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

CACHE = Path("/cache")
TESTS = Path("/workspace/tests")
LOG = Path("/output/firmware.log")

TF_A_URL = "https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git"
TF_A_REVISION = "1d5aa939bc8d3d892e2ed9945fa50e36a1a924cc"
TF_A_TESTS_URL = "https://git.trustedfirmware.org/TF-A/tf-a-tests.git"
TF_A_TESTS_REVISION = "3b3d800133081b48482b1205a32671b82bc2b640"
HAFNIUM_URL = "https://git.trustedfirmware.org/hafnium/hafnium.git"
HAFNIUM_REVISION = "ce12c6e53838f1cf07d50b616b72db57a81539a4"
TF_RMM_URL = "https://github.com/TF-RMM/tf-rmm.git"
TF_RMM_REVISION = "13a82ef5f3bbe4181c8c73a898b6ccdd61e12dae"
LIBEVENTLOG_URL = "https://review.trustedfirmware.org/shared/libEventLog"
LIBTL_URL = "https://review.trustedfirmware.org/shared/transfer-list-library"
MBEDTLS_URL = "https://github.com/Mbed-TLS/mbedtls.git"
MBEDTLS_FRAMEWORK_URL = "https://github.com/Mbed-TLS/mbedtls-framework"
HAFNIUM_PREBUILTS_URL = "https://git.trustedfirmware.org/hafnium/prebuilts"
HAFNIUM_REFERENCE_URL = "https://git.trustedfirmware.org/hafnium/project/reference"
HAFNIUM_DTC_URL = "https://git.trustedfirmware.org/hafnium/third_party/dtc"
HAFNIUM_GOOGLETEST_URL = "https://git.trustedfirmware.org/hafnium/third_party/googletest"
HAFNIUM_SHRINKWRAP_URL = "https://git.gitlab.arm.com/tooling/shrinkwrap.git"
QCBOR_URL = "https://github.com/laurencelundblade/QCBOR.git"
T_COSE_URL = "https://github.com/laurencelundblade/t_cose.git"
CPPUTEST_URL = "https://github.com/cpputest/cpputest.git"
LIBSPDM_URL = "https://github.com/DMTF/libspdm.git"
SPDM_EMU_URL = "https://github.com/DMTF/spdm-emu.git"


def checked(command: list[str], cwd: Path | None = None) -> None:
    with LOG.open("a", encoding="utf-8") as output:
        output.write(f"+ {' '.join(command)}\n")
        output.flush()
        subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, check=True)


def checked_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    with LOG.open("a", encoding="utf-8") as output:
        output.write(f"+ {' '.join(command)}\n")
        output.write(result.stdout)
        output.write(result.stderr)
    return result.stdout.strip()


def has_commit(mirror: Path, revision: str) -> bool:
    result = subprocess.run(
        ["git", "--git-dir", str(mirror), "cat-file", "-e", f"{revision}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def valid_mirror(mirror: Path) -> bool:
    result = subprocess.run(
        ["git", "--git-dir", str(mirror), "rev-parse", "--is-bare-repository"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def prepare_repository(name: str, url: str, revision: str, run_root: Path) -> Path:
    mirrors = CACHE / "git"
    mirrors.mkdir(parents=True, exist_ok=True)
    mirror = mirrors / f"{name}.git"
    if mirror.exists() and not valid_mirror(mirror):
        shutil.rmtree(mirror)
    if not mirror.exists():
        incomplete = mirrors / f"{name}.git.incomplete"
        if incomplete.exists():
            shutil.rmtree(incomplete)
        try:
            checked(["git", "clone", "--mirror", url, str(incomplete)])
            incomplete.replace(mirror)
        except BaseException:
            if incomplete.exists():
                shutil.rmtree(incomplete)
            raise
    if not has_commit(mirror, revision):
        checked(["git", "--git-dir", str(mirror), "fetch", "--no-tags", url, revision])
    if not has_commit(mirror, revision):
        raise RuntimeError(f"pinned commit {revision} is unavailable for {name}")

    worktree = run_root / name
    checked(["git", "--git-dir", str(mirror), "worktree", "prune"])
    checked(["git", "--git-dir", str(mirror), "worktree", "add", "--detach", str(worktree), revision])
    try:
        checked(["git", "reset", "--hard", revision], cwd=worktree)
        checked(["git", "clean", "-ffdqx"], cwd=worktree)
        prepare_submodules(name, worktree)
    except BaseException as error:
        try:
            checked([
                "git", "--git-dir", str(mirror), "worktree", "remove", "--force", str(worktree)
            ])
        except (OSError, subprocess.CalledProcessError) as cleanup_error:
            raise RuntimeError(
                f"failed to remove incomplete {name} worktree: {cleanup_error}"
            ) from error
        raise
    return worktree


def prepare_cached_submodule(
    worktree: Path,
    module_name: str,
    module_path: str,
    url: str,
    cache_name: str,
) -> None:
    revision = checked_output(["git", "rev-parse", f"HEAD:{module_path}"], worktree)
    mirror = CACHE / "git" / "submodules" / f"{cache_name}.git"
    mirror.parent.mkdir(parents=True, exist_ok=True)
    if not mirror.exists():
        checked(["git", "clone", "--mirror", url, str(mirror)])
    if not has_commit(mirror, revision):
        checked(["git", "--git-dir", str(mirror), "fetch", "--no-tags", url, revision])
    if not has_commit(mirror, revision):
        raise RuntimeError(f"pinned submodule commit {revision} is unavailable for {module_path}")
    checked(["git", "config", f"submodule.{module_name}.url", str(mirror)], cwd=worktree)
    checked(["git", "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--", module_path], cwd=worktree)


def prepare_submodules(repository_name: str, worktree: Path) -> None:
    if repository_name == "tf-a":
        prepare_cached_submodule(
            worktree, "libeventlog", "contrib/libeventlog", LIBEVENTLOG_URL, "libeventlog"
        )
        prepare_cached_submodule(worktree, "libtl", "contrib/libtl", LIBTL_URL, "tf-a-libtl")
    elif repository_name == "tf-a-tests":
        prepare_cached_submodule(
            worktree, "contrib/libeventlog", "contrib/libeventlog", LIBEVENTLOG_URL,
            "libeventlog",
        )
        prepare_cached_submodule(
            worktree, "libtl", "contrib/libtl", LIBTL_URL, "tf-a-tests-libtl"
        )
        prepare_cached_submodule(
            worktree, "ext/mbedtls", "contrib/mbedtls", MBEDTLS_URL, "mbedtls"
        )
        prepare_cached_submodule(
            worktree / "contrib/mbedtls", "framework", "framework", MBEDTLS_FRAMEWORK_URL,
            "mbedtls-framework",
        )
    elif repository_name == "hafnium":
        for module_name, module_path, url, cache_name in (
            ("prebuilts", "prebuilts", HAFNIUM_PREBUILTS_URL, "hafnium-prebuilts"),
            (
                "project/reference", "project/reference", HAFNIUM_REFERENCE_URL,
                "hafnium-reference",
            ),
            ("third_party/dtc", "third_party/dtc", HAFNIUM_DTC_URL, "hafnium-dtc"),
            (
                "third_party/googletest", "third_party/googletest",
                HAFNIUM_GOOGLETEST_URL, "hafnium-googletest",
            ),
            (
                "third_party/shrinkwrap", "third_party/shrinkwrap",
                HAFNIUM_SHRINKWRAP_URL, "hafnium-shrinkwrap",
            ),
        ):
            prepare_cached_submodule(worktree, module_name, module_path, url, cache_name)
    elif repository_name == "tf-rmm":
        for module_name, module_path, url, cache_name in (
            ("mbedtls", "ext/mbedtls", MBEDTLS_URL, "tf-rmm-mbedtls"),
            ("ext/qcbor", "ext/qcbor", QCBOR_URL, "tf-rmm-qcbor"),
            ("ext/t_cose", "ext/t_cose", T_COSE_URL, "tf-rmm-t-cose"),
            ("ext/cpputest", "ext/cpputest", CPPUTEST_URL, "tf-rmm-cpputest"),
            ("ext/libspdm", "ext/libspdm", LIBSPDM_URL, "tf-rmm-libspdm"),
            ("ext/spdm-emu", "ext/spdm-emu", SPDM_EMU_URL, "tf-rmm-spdm-emu"),
        ):
            prepare_cached_submodule(worktree, module_name, module_path, url, cache_name)
    else:
        return


def apply_integration(worktree: Path, integration_name: str) -> None:
    integration = TESTS / "integration" / integration_name
    patches = integration / "patches"
    if patches.is_dir():
        for patch in sorted(patches.glob("*.patch")):
            checked(["git", "apply", "--check", str(patch)], cwd=worktree)
            checked(["git", "apply", str(patch)], cwd=worktree)
    files = integration / "files"
    if files.is_dir():
        for source in sorted(files.rglob("*")):
            if source.is_file():
                destination = worktree / source.relative_to(files)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)


def cleanup(repositories: dict[str, Path]) -> None:
    run_roots = {path.parent for path in repositories.values()}
    failures: list[str] = []
    for name, worktree in repositories.items():
        mirror = CACHE / "git" / f"{name}.git"
        if mirror.is_dir() and worktree.exists():
            try:
                checked([
                    "git", "--git-dir", str(mirror), "worktree", "remove", "--force", str(worktree)
                ])
            except (OSError, subprocess.CalledProcessError) as error:
                failures.append(f"{name}: {error}")
    for run_root in run_roots:
        if not run_root.exists():
            continue
        resolved = run_root.resolve()
        expected = (CACHE / "worktrees").resolve()
        if expected not in resolved.parents:
            raise RuntimeError(f"refusing to remove unexpected worktree path {resolved}")
        shutil.rmtree(run_root)
    if failures:
        raise RuntimeError("; ".join(failures))


def prepare(target: str) -> dict[str, Path]:
    run_id = os.environ.get("VMSA_RUN_ID")
    safe_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if not run_id or any(character not in safe_characters for character in run_id):
        raise RuntimeError("VMSA_RUN_ID is missing or contains unsafe characters")
    run_root = CACHE / "worktrees" / run_id
    if run_root.exists():
        resolved = run_root.resolve()
        expected = (CACHE / "worktrees").resolve()
        if expected not in resolved.parents:
            raise RuntimeError(f"refusing to remove unexpected worktree path {resolved}")
        raise RuntimeError(f"disposable worktree root already exists: {resolved}")
    run_root.mkdir(parents=True)

    repositories: dict[str, Path] = {}
    try:
        repositories["tf-a"] = prepare_repository("tf-a", TF_A_URL, TF_A_REVISION, run_root)
        repositories["tf-a-tests"] = prepare_repository(
            "tf-a-tests", TF_A_TESTS_URL, TF_A_TESTS_REVISION, run_root
        )
        apply_integration(repositories["tf-a"], "tf_a")
        apply_integration(repositories["tf-a-tests"], "tf_a_tests")

        if target == "realm-el2":
            apply_integration(repositories["tf-a"], "trp")
        elif target == "secure-el2":
            repositories["hafnium"] = prepare_repository(
                "hafnium", HAFNIUM_URL, HAFNIUM_REVISION, run_root
            )
            apply_integration(repositories["hafnium"], "hafnium")
        elif target == "realm-stage2":
            repositories["tf-rmm"] = prepare_repository(
                "tf-rmm", TF_RMM_URL, TF_RMM_REVISION, run_root
            )
            apply_integration(repositories["tf-rmm"], "tf_rmm")
        elif target not in {"ns-el2", "root-el3"}:
            raise ValueError(f"unsupported target {target}")
    except BaseException:
        cleanup(repositories)
        if run_root.exists():
            shutil.rmtree(run_root)
        raise
    return repositories


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare.py <target>")
    for key, value in prepare(sys.argv[1]).items():
        print(f"{key}={value}")
