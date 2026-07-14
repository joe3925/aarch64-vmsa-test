#!/usr/bin/env python3
"""Generate the item-level aarch64-vmsa public API coverage inventory."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path, PurePosixPath


def classify(path: list[str], kind: str) -> tuple[str, str, str]:
    relative = path[1:]
    lowered = [part.lower() for part in relative]
    module = lowered[0] if lowered else "crate"
    joined = "::".join(lowered)

    if kind in {"use", "module"}:
        return (
            "pure-compile-time-or-type-system",
            "public namespace and reexport surface",
            "classified",
        )
    if "error" in joined or kind == "variant" and any("error" in part for part in lowered):
        return (
            "exercisable-through-isolated-malformed-input",
            "typed errors, failure injection, or isolated malformed descriptors",
            "evidence-incomplete",
        )
    if module == "regime" or kind in {"trait", "type_alias"}:
        return (
            "pure-compile-time-or-type-system",
            "typed catalog bounds and compile-time regime/format selection",
            "classified",
        )
    if module == "arch":
        return (
            "pure-compile-time-or-type-system",
            "typed feature input and adapter capability validation",
            "classified",
        )
    if module == "address":
        return (
            "architecturally-unobservable",
            "typed address/geometry construction and mapper boundary validation",
            "evidence-incomplete",
        )
    if module in {"attrs", "descriptor", "translation"}:
        return (
            "exercisable-through-typed-descriptor-inspection",
            "semantic codec, descriptor inspection, and typed walk inspection",
            "evidence-incomplete",
        )
    if module in {"mapper", "table"}:
        return (
            "directly-exercisable-through-harness",
            "offline/live mapper, installed translation, mutation, and restoration",
            "evidence-incomplete",
        )
    return (
        "architecturally-unobservable",
        "crate/module/type surface with no independent architectural observation",
        "classified",
    )


def ownership_map(index: dict[str, dict[str, object]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    ownership_keys = {"items", "fields", "impls", "variants", "implementations"}
    for owner_id, item in index.items():
        inner = item.get("inner", {})
        for payload in inner.values():
            if not isinstance(payload, dict):
                continue
            for key, value in payload.items():
                if key not in ownership_keys or not isinstance(value, list):
                    continue
                for child_id in value:
                    if isinstance(child_id, int):
                        owners.setdefault(str(child_id), owner_id)
    return owners


def item_path(
    item_id: str,
    item: dict[str, object],
    paths: dict[str, dict[str, object]],
    owners: dict[str, str],
) -> list[str]:
    if item_id in paths:
        return list(paths[item_id]["path"])

    owner_id = owners.get(item_id)
    visited = {item_id}
    while owner_id is not None and owner_id not in visited:
        visited.add(owner_id)
        if owner_id in paths:
            path = list(paths[owner_id]["path"])
            name = item.get("name")
            if isinstance(name, str) and (not path or path[-1] != name):
                path.append(name)
            return path
        owner_id = owners.get(owner_id)

    span = item.get("span")
    filename = span.get("filename", "unknown") if isinstance(span, dict) else "unknown"
    components = PurePosixPath(filename.replace("\\", "/")).with_suffix("").parts
    if components and components[-1] in {"lib", "mod"}:
        components = components[:-1]
    name = item.get("name")
    leaf = name if isinstance(name, str) else f"item_{item_id}"
    return ["aarch64_vmsa", *components, leaf]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rustdoc_json", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()

    with args.rustdoc_json.open(encoding="utf-8") as source:
        document = json.load(source)

    rows: list[dict[str, str]] = []
    index = document["index"]
    paths = document["paths"]
    owners = ownership_map(index)
    for item_id, item in index.items():
        if item["crate_id"] != 0 or item["visibility"] != "public":
            continue
        kind = next(iter(item["inner"]))
        path = item_path(item_id, item, paths, owners)
        classification, route, evidence = classify(path, kind)
        rows.append(
            {
                "revision": args.revision,
                "rustdoc_item_id": item_id,
                "public_path": "::".join(path),
                "kind": kind,
                "classification": classification,
                "harness_route": route,
                "evidence_state": evidence,
            }
        )

    rows.sort(key=lambda row: (row["public_path"], row["kind"], row["rustdoc_item_id"]))
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} crate-owned public API items to {args.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
