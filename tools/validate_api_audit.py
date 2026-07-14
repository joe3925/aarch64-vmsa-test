#!/usr/bin/env python3
"""Validate completeness and vocabulary of the public API audit CSV."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


CLASSIFICATIONS = {
    "type-only",
    "value-only",
    "typed-inspection",
    "direct-fvp-execution",
    "isolated-malformed-input",
    "genuinely-fvp-unsupported",
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
    parser.add_argument(
        "--catalog-registry",
        type=Path,
        help="require every observable route to name a registered catalog identity",
    )
    args = parser.parse_args()
    catalog_identities: set[str] = set()
    if args.catalog_registry is not None:
        catalog_identities = set(
            re.findall(
                r'"([a-z0-9][a-z0-9.-]+)"',
                args.catalog_registry.read_text(encoding="utf-8"),
            )
        )
        if not catalog_identities:
            raise SystemExit("catalog registry contains no test identities")

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
                "type-only",
                "value-only",
                "genuinely-fvp-unsupported",
            }
            and row["evidence_state"] != "evidence-complete"
        ):
            raise SystemExit(
                "API audit item "
                f"{row['rustdoc_item_id']} ({row['public_path']}) has incomplete evidence"
            )
        if (
            catalog_identities
            and row["classification"]
            in {"typed-inspection", "direct-fvp-execution", "isolated-malformed-input"}
            and not any(identity in row["harness_route"] for identity in catalog_identities)
        ):
            raise SystemExit(
                "API audit item "
                f"{row['rustdoc_item_id']} ({row['public_path']}) has no catalog identity"
            )

    print(f"validated {len(rows)} unique classified public API items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
