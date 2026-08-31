#!/usr/bin/env python3
"""Compile the public SMMU stage-1 semantic-codec contract against a crate checkout."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/probes/smmu_stage1_semantics.rs"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", required=True, type=pathlib.Path)
    args = parser.parse_args()
    crate_path = args.crate.resolve()
    if not (crate_path / "Cargo.toml").is_file():
        parser.error(f"not a Rust crate: {crate_path}")

    with tempfile.TemporaryDirectory(prefix="aarch64-vmsa-smmu-stage1-probe.") as temporary:
        probe = pathlib.Path(temporary)
        (probe / "src").mkdir()
        shutil.copyfile(SOURCE, probe / "src/main.rs")
        (probe / "Cargo.toml").write_text(
            "[package]\n"
            'name = "smmu-stage1-public-api-probe"\n'
            'version = "0.0.0"\n'
            'edition = "2024"\n\n'
            "[dependencies]\n"
            f'aarch64-vmsa = {{ path = "{crate_path}" }}\n\n'
            "[workspace]\n"
        )
        completed = subprocess.run(
            ["cargo", "check", "--offline", "--manifest-path", str(probe / "Cargo.toml")],
            check=False,
        )
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
