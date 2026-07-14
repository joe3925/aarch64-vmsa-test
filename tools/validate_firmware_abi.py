#!/usr/bin/env python3
"""Fail closed when the checked-in Rust and firmware ABI definitions drift."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOT_HEADERS = (
    ROOT / "integration/tf_a/files/vmsa_test_abi.h",
    ROOT / "integration/hafnium/files/src/vmsa_test_abi.h",
    ROOT / "integration/tf_a_tests/files/tftf/tests/vmsa/vmsa_test_abi.h",
)
REALM_HEADER = ROOT / "integration/tf_a_tests/files/vmsa_realm_rec_abi.h"
COMMON_RUST = ROOT / "target/payloads/common/mod.rs"
ABI_RUST = ROOT / "target/abi/src/lib.rs"
TARGET_REPORT = ROOT / "target/harness/src/report.rs"
HOST_SETTINGS = ROOT / "host/cli/src/settings.rs"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require(pattern: str, text: str, source: Path) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise ValueError(f"{source}: required ABI pattern not found: {pattern}")
    return match


def rust_constant(path: Path, name: str) -> int:
    match = require(rf"pub const {name}: [^=]+ = (\d+);", read(path), path)
    return int(match.group(1))


def c_constant(path: Path, name: str) -> int:
    match = require(rf"#define {name} UINT(?:32|64)_C\((\d+)\)", read(path), path)
    return int(match.group(1))


def rust_fields(path: Path, name: str) -> tuple[str, ...]:
    body = require(rf"pub struct {name}\s*\{{(.*?)\n\}}", read(path), path).group(1)
    return tuple(re.findall(r"^\s*pub\s+(\w+)\s*:", body, re.MULTILINE))


def c_fields(path: Path, tag: str) -> tuple[str, ...]:
    body = require(rf"typedef struct {tag}\s*\{{(.*?)\n\}}", read(path), path).group(1)
    fields: list[str] = []
    for declaration in body.split(";"):
        declaration = declaration.strip()
        if not declaration:
            continue
        match = re.search(r"(\w+)(?:\[[^]]+\])?$", declaration)
        if match is None:
            raise ValueError(f"{path}: cannot parse C ABI field: {declaration!r}")
        fields.append(match.group(1))
    return tuple(fields)


def rust_layout(path: Path, name: str) -> tuple[int, int]:
    text = read(path)
    size = int(
        require(rf"size_of::<{name}>\(\) == (\d+)", text, path).group(1)
    )
    align = int(
        require(rf"align_of::<{name}>\(\) == (\d+)", text, path).group(1)
    )
    return size, align


def c_layout(path: Path, typedef: str) -> tuple[int, int]:
    text = read(path)
    size = int(
        require(rf"sizeof\({typedef}\) == (\d+)U", text, path).group(1)
    )
    align = int(
        require(rf"_Alignof\({typedef}\) == (\d+)U", text, path).group(1)
    )
    return size, align


def equal(label: str, values: list[object]) -> None:
    if any(value != values[0] for value in values[1:]):
        raise ValueError(f"{label} mismatch: {values!r}")


def main() -> int:
    equal(
        "boot ABI version",
        [rust_constant(COMMON_RUST, "BOOT_CONTEXT_ABI_VERSION")]
        + [c_constant(path, "VMSA_BOOT_CONTEXT_ABI_VERSION") for path in BOOT_HEADERS],
    )
    equal(
        "boot ABI fields",
        [rust_fields(COMMON_RUST, "BootContext")]
        + [c_fields(path, "vmsa_boot_context") for path in BOOT_HEADERS],
    )
    equal(
        "boot ABI layout",
        [rust_layout(COMMON_RUST, "BootContext")]
        + [c_layout(path, "vmsa_boot_context_t") for path in BOOT_HEADERS],
    )

    equal(
        "Realm REC ABI version",
        [
            rust_constant(ABI_RUST, "REALM_REC_ABI_VERSION"),
            c_constant(REALM_HEADER, "VMSA_REALM_REC_ABI_VERSION"),
        ],
    )
    equal(
        "Realm REC ABI fields",
        [
            rust_fields(ABI_RUST, "RealmRecRecord"),
            c_fields(REALM_HEADER, "vmsa_realm_rec_record"),
        ],
    )
    equal(
        "Realm REC ABI layout",
        [
            rust_layout(ABI_RUST, "RealmRecRecord"),
            c_layout(REALM_HEADER, "vmsa_realm_rec_record_t"),
        ],
    )

    equal(
        "report protocol version",
        [
            int(
                require(
                    r"const PROTOCOL_VERSION: u32 = (\d+);",
                    read(TARGET_REPORT),
                    TARGET_REPORT,
                ).group(1)
            ),
            rust_constant(HOST_SETTINGS, "PROTOCOL_VERSION"),
        ],
    )
    print("firmware ABI validation: passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"firmware ABI validation: {error}", file=sys.stderr)
        raise SystemExit(1) from error
