#!/usr/bin/env python3
"""Validate branch-area audit source coverage and catalog references."""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRATE = Path("/Users/boden/Documents/aarch64-vmsa")
AUDIT = ROOT / "docs" / "BRANCH_AREA_AUDIT.md"
REGISTRY = ROOT / "target" / "harness" / "src" / "registry.rs"
SOURCE_INVENTORY = ROOT / "docs" / "branch-area-source-inventory.csv"


def fail(message: str) -> None:
    print(f"branch-area audit error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    audit = AUDIT.read_text()
    registry = REGISTRY.read_text()
    names = set(re.findall(r'"([a-z0-9][a-z0-9_.-]+)"', registry))

    exact = set(re.findall(r"`case:([a-z0-9][a-z0-9_-]*\.[a-z0-9_.-]+)`", audit))
    prefixes = set(re.findall(r"`prefix:([a-z0-9][a-z0-9_-]*\.[a-z0-9_.-]+)`", audit))
    missing = sorted(exact - names)
    if missing:
        fail(f"unknown exact catalog identities: {', '.join(missing)}")
    empty_prefixes = sorted(prefix for prefix in prefixes if not any(name.startswith(prefix) for name in names))
    if empty_prefixes:
        fail(f"catalog prefixes match nothing: {', '.join(empty_prefixes)}")

    source_paths = sorted(CRATE.rglob("*.rs"))
    source_files = [path.relative_to(CRATE).as_posix() for path in source_paths]
    if len(source_files) != 51:
        fail(f"expected 51 crate Rust files, found {len(source_files)}")
    source_lines = sum(len(path.read_text().splitlines()) for path in CRATE.rglob("*.rs"))
    if source_lines != 10_196:
        fail(f"expected 10,196 crate Rust lines, found {source_lines}")
    if len(names) != 543:
        fail(f"expected 543 catalog identities, found {len(names)}")

    with SOURCE_INVENTORY.open(newline="") as source:
        inventory = list(csv.DictReader(source))
    inventory_files = [row["source_file"] for row in inventory]
    if inventory_files != source_files:
        fail("source inventory does not exactly match the crate Rust file set")
    for path, row in zip(source_paths, inventory):
        text = path.read_text()
        lines = len(text.splitlines())
        decisions = len(
            re.findall(
                r"\b(?:if|match|while|for)\b|\?\s*(?:[;,.)}]|$)|#\[cfg\(",
                text,
            )
        )
        if int(row["lines"]) != lines or int(row["decision_sites"]) != decisions:
            fail(
                f"stale source inventory for {row['source_file']}: "
                f"expected lines/decisions {lines}/{decisions}, "
                f"recorded {row['lines']}/{row['decision_sites']}"
            )
    decision_sites = sum(int(row["decision_sites"]) for row in inventory)
    if decision_sites != 671:
        fail(f"expected 671 inventoried decision sites, found {decision_sites}")

    boxes = re.findall(r"^- \[([ x])\] \*\*(BA-[A-Z0-9-]+)", audit, re.MULTILINE)
    if not boxes:
        fail("no branch-area checkboxes found")
    identifiers = [identifier for _, identifier in boxes]
    duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicates:
        fail(f"duplicate branch-area identifiers: {', '.join(duplicates)}")

    checked = sum(state == "x" for state, _ in boxes)
    unchecked = len(boxes) - checked
    print(
        f"branch-area audit valid: {len(boxes)} areas, {checked} checked, "
        f"{unchecked} unchecked; {len(exact)} exact routes, "
        f"{len(prefixes)} route prefixes; {len(source_files)} crate files"
        f", {decision_sites} decision sites"
    )


if __name__ == "__main__":
    main()
