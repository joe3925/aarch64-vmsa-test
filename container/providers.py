#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform as host_platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

import prepare


CACHE = Path("/cache/platforms")


@dataclass(frozen=True)
class Package:
    url: str
    sha256: str
    archive_name: str
    executable: str


@dataclass(frozen=True)
class Provider:
    identifier: str
    version: str
    system_executable: str | None
    packages: dict[str, Package]


PROVIDERS = {
    "fvp-revc": Provider(
        identifier="fvp-revc",
        version="image",
        system_executable="FVP_Base_RevC-2xAEMvA",
        packages={},
    ),
    "fvp-rdn2": Provider(
        identifier="fvp-rdn2",
        version="11.25.23",
        system_executable=None,
        packages={
            "aarch64": Package(
                url="https://developer.arm.com/-/cdn-downloads/permalink/FVPs-Neoverse-Infrastructure/RD-N2/FVP_RD_N2_11.25_23_Linux64_armv8l.tgz",
                sha256="ae3a3e85ae307dffcc1221d0f30efbb6bc22b61fd508305b984f294407659bdd",
                archive_name="FVP_RD_N2_11.25_23_Linux64_armv8l.tgz",
                executable="models/Linux64_armv8l_GCC-9.3/FVP_RD_N2",
            ),
            "x86_64": Package(
                url="https://developer.arm.com/-/cdn-downloads/permalink/FVPs-Neoverse-Infrastructure/RD-N2/FVP_RD_N2_11.25_23_Linux64.tgz",
                sha256="89c6d5a784d0b76168fb187e366de35f7de5aa7583a148b206b2aee2bc486da2",
                archive_name="FVP_RD_N2_11.25_23_Linux64.tgz",
                executable="models/Linux64_GCC-9.3/FVP_RD_N2",
            ),
        },
    ),
}

RD_N2_MODEL_SCRIPTS_REVISION = "5536958105dcde35a564d352b8d11db6fa5c27a1"
RD_N2_ASSETS = {
    "example_pcie_hierarchy_2.json": "99667c0204d8e609cda18dca7ae4a0bb7456c172102740d168f35a892b1aa60b",
    "example_pcie_hierarchy_3.json": "ee206a29da9379823f630922b14fde4131ef491a23e3dfb8988638b1fb752c54",
    "example_pcie_hierarchy_4.json": "e71ffde1a2bfc2483ff59fd6fdda31a53d16d7f42edb0fadd2fe0f59f5ee60cf",
}


def _version(executable: str | Path) -> str:
    result = subprocess.run(
        [str(executable), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    version = (result.stdout or result.stderr).strip().replace("\r", " ").replace("\n", " ")
    if not version:
        raise RuntimeError(f"{executable} returned no version text")
    return version


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _install(provider: Provider, package: Package, destination: Path) -> None:
    partial = destination.with_name(f".{destination.name}.partial-{os.getpid()}")
    if partial.exists():
        shutil.rmtree(partial)
    partial.mkdir(parents=True)
    archive = partial / package.archive_name
    unpacked = partial / "package"
    installed = partial / "installed"
    try:
        print(f"VMSA-INFRA PLATFORM_DOWNLOAD platform={provider.identifier}", flush=True)
        urllib.request.urlretrieve(package.url, archive)
        actual = _digest(archive)
        if actual != package.sha256:
            raise RuntimeError(
                f"{provider.identifier} package digest mismatch: expected {package.sha256}, got {actual}"
            )
        unpacked.mkdir()
        with tarfile.open(archive, "r:gz") as source:
            for member in source.getmembers():
                target = (unpacked / member.name).resolve()
                if unpacked.resolve() not in target.parents and target != unpacked.resolve():
                    raise RuntimeError(f"unsafe path in {package.archive_name}: {member.name}")
            source.extractall(unpacked)
        installers = list(unpacked.rglob("FVP_RD_N2.sh"))
        if len(installers) != 1:
            raise RuntimeError(f"expected one RD-N2 installer, found {len(installers)}")
        subprocess.run(
            [
                "bash", str(installers[0]),
                "--i-agree-to-the-contained-eula",
                "--no-interactive",
                "--force",
                "--destination", str(installed),
            ],
            check=True,
        )
        executable = installed / package.executable
        version = _version(executable)
        if provider.version not in version:
            raise RuntimeError(
                f"installed {provider.identifier} version does not contain {provider.version}: {version}"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        installed.replace(destination)
    finally:
        if partial.exists():
            shutil.rmtree(partial)


def ensure(identifier: str) -> Path:
    try:
        provider = PROVIDERS[identifier]
    except KeyError as error:
        raise ValueError(f"unsupported platform {identifier}") from error
    if provider.system_executable is not None:
        executable = shutil.which(provider.system_executable)
        if executable is None:
            raise RuntimeError(f"container image does not provide {provider.system_executable}")
        _version(executable)
        return Path(executable)

    architecture = host_platform.machine()
    try:
        package = provider.packages[architecture]
    except KeyError as error:
        raise RuntimeError(
            f"{identifier} has no pinned package for container architecture {architecture}"
        ) from error
    destination = CACHE / provider.identifier / provider.version
    executable = destination / package.executable
    with prepare.cache_lock(f"platform-{provider.identifier}-{provider.version}"):
        try:
            version = _version(executable)
        except (OSError, subprocess.CalledProcessError, RuntimeError):
            if destination.exists():
                shutil.rmtree(destination)
            _install(provider, package, destination)
            version = _version(executable)
        if provider.version not in version:
            raise RuntimeError(
                f"cached {identifier} version does not contain {provider.version}: {version}"
            )
        if identifier == "fvp-rdn2":
            assets = destination / "vmsa-assets"
            assets.mkdir(exist_ok=True)
            base = (
                "https://git.gitlab.arm.com/infra-solutions/reference-design/"
                f"scripts/model-scripts/-/raw/{RD_N2_MODEL_SCRIPTS_REVISION}/"
                "rdinfra/platforms/rdn2"
            )
            for name, expected in RD_N2_ASSETS.items():
                path = assets / name
                if path.is_file() and _digest(path) == expected:
                    continue
                partial = assets / f".{name}.partial-{os.getpid()}"
                try:
                    urllib.request.urlretrieve(f"{base}/{name}", partial)
                    actual = _digest(partial)
                    if actual != expected:
                        raise RuntimeError(
                            f"RD-N2 model asset digest mismatch for {name}: "
                            f"expected {expected}, got {actual}"
                        )
                    partial.replace(path)
                finally:
                    if partial.exists():
                        partial.unlink()
    return executable


def asset(identifier: str, name: str) -> Path:
    executable = ensure(identifier)
    path = executable.parents[2] / "vmsa-assets" / name
    if not path.is_file():
        raise RuntimeError(f"platform asset is missing after provisioning: {path}")
    return path


def version(identifier: str) -> str:
    return _version(ensure(identifier))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "version":
        raise SystemExit("usage: providers.py version <platform>")
    print(version(sys.argv[2]))
