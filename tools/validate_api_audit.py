#!/usr/bin/env python3
"""Validate completeness and vocabulary of the public API audit CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


CLASSIFICATIONS = {
    "directly-exercisable-through-harness",
    "exercisable-through-typed-descriptor-inspection",
    "exercisable-through-isolated-malformed-input",
    "pure-compile-time-or-type-system",
    "architecturally-unobservable",
    "architecturally-constrained-or-unpredictable",
    "unsupported-by-selected-fvp",
}
EVIDENCE_STATES = {"classified", "evidence-incomplete", "evidence-complete"}
FIELDS = {
    "revision",
    "rustdoc_item_id",
    "public_path",
    "kind",
    "classification",
    "harness_route",
    "evidence_state",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("audit", type=Path)
    parser.add_argument("--expected-items", type=int, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="reject any architecturally observable item whose evidence is incomplete",
    )
    args = parser.parse_args()

    with args.audit.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if set(reader.fieldnames or ()) != FIELDS:
            raise SystemExit("API audit columns do not match the required schema")
        rows = list(reader)

    if len(rows) != args.expected_items:
        raise SystemExit(
            f"API audit contains {len(rows)} items; expected {args.expected_items}"
        )
    item_ids = {row["rustdoc_item_id"] for row in rows}
    if len(item_ids) != len(rows):
        raise SystemExit("API audit contains duplicate rustdoc item IDs")
    for row in rows:
        if any(not row[field] for field in FIELDS):
            raise SystemExit(f"API audit item {row['rustdoc_item_id']} has a blank field")
        if row["revision"] != args.revision:
            raise SystemExit(f"API audit item {row['rustdoc_item_id']} has the wrong revision")
        if row["classification"] not in CLASSIFICATIONS:
            raise SystemExit(
                f"API audit item {row['rustdoc_item_id']} has an unknown classification"
            )
        if row["evidence_state"] not in EVIDENCE_STATES:
            raise SystemExit(
                f"API audit item {row['rustdoc_item_id']} has an unknown evidence state"
            )
        if (
            args.require_complete
            and row["classification"]
            not in {
                "pure-compile-time-or-type-system",
                "architecturally-unobservable",
                "architecturally-constrained-or-unpredictable",
                "unsupported-by-selected-fvp",
            }
            and row["evidence_state"] != "evidence-complete"
        ):
            raise SystemExit(
                "API audit item "
                f"{row['rustdoc_item_id']} ({row['public_path']}) has incomplete evidence"
            )

    print(f"validated {len(rows)} unique classified public API items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
