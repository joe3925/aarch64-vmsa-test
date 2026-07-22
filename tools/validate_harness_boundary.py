#!/usr/bin/env python3
"""Reject harness implementation details used as crate-test oracles."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TRANSLATION = ROOT / "target/harness/src/translation.rs"
HARNESS_LIB = ROOT / "target/harness/src/lib.rs"
PAYLOADS = ROOT / "target/payloads/common"
HARNESS_ONLY_ASSERTION_FILES = {"infrastructure.rs", "recovery.rs"}


def fail(message: str) -> None:
    print(f"harness-boundary: {message}", file=sys.stderr)
    raise SystemExit(1)


translation = TRANSLATION.read_text()
harness_lib = HARNESS_LIB.read_text()

for forbidden in ("fn encode_memory_attributes", "pub const fn stage1_start_level"):
    if forbidden in translation:
        fail(f"forbidden duplicated/public oracle found: {forbidden}")

if re.search(r"\bstage1_start_level\b", harness_lib):
    fail("the stage-1 safety interlock is reexported to payload tests")

oracle_pattern = re.compile(
    r"(?:expected\s*:|expected\s*=|assert_eq!\s*\([^,]+,)[^;\n]*"
    r"(?:TranslationControls|Stage1MemoryControls|_stage[12]_controls|with_raw_attribute)"
)
for path in PAYLOADS.rglob("*.rs"):
    source = path.read_text()
    match = oracle_pattern.search(source)
    if match:
        line = source.count("\n", 0, match.start()) + 1
        fail(f"register-setup helper used as an expected oracle at {path.relative_to(ROOT)}:{line}")
    if (
        path.name not in HARNESS_ONLY_ASSERTION_FILES
        and re.search(r"HarnessError::InvalidState\.into\(\)", source)
    ):
        fail(
            "crate-facing assertion is reported as harness-invalid-state at "
            + str(path.relative_to(ROOT))
        )

for path in (ROOT / "target/harness/src/context.rs", TRANSLATION):
    source = path.read_text()
    if re.search(r"SemanticMapperError::Mapper\(_\)\s*=>\s*HarnessError::InvalidState", source):
        fail(f"semantic mapper error loses crate ownership at {path.relative_to(ROOT)}")

print("harness-boundary: validated crate evidence boundary")
