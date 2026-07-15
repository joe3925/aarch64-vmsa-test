# aarch64-vmsa-test

Portable, Podman-only FVP integration tests for an arbitrary local checkout of
[`aarch64-vmsa`](../aarch64-vmsa). The checkout under test is mounted read-only;
upstream mirrors and Rust downloads live in a persistent Podman cache, while
disposable firmware worktrees and run artifacts are isolated per invocation.

## Prerequisites

- Podman with Linux containers
- A local `aarch64-vmsa` checkout

On Windows, initialize and start the Podman machine if necessary:

```text
podman machine init
podman machine start
```

Build the native CLI from the host workspace:

```text
cargo build --manifest-path host/Cargo.toml --release
host/target/release/vmsa-test doctor --crate ../aarch64-vmsa
host/target/release/vmsa-test test all --crate ../aarch64-vmsa
```

`--crate <path>` is required for `doctor` and `test`; there is no implicit local
path. Pass `--crate default` to explicitly clone
`https://github.com/joe3925/aarch64-vmsa` through Podman into disposable local
state. Explicit local checkouts, including uncommitted changes, are always
mounted read-only. The CLI accepts only `--crate <path>`, `--filter
<substring>`, and `--keep`.
Failed and incomplete runs are retained under `output/runs`; successful runs are
removed unless `--keep` is supplied.

When attached to a terminal, live results use color to distinguish passes,
failures, skips, and the currently running case. Redirected output and retained
protocol/artifact files remain plain text. Set the standard `NO_COLOR`
environment variable to disable terminal color explicitly.

Pressing Ctrl-C requests bounded cleanup rather than abandoning the model or
container. The CLI stops the scoped Podman process tree, retains the interrupted
run directory, records a `cancelled` summary, and exits with status 130.

The Arm Shrinkwrap container, firmware revisions, and Rust toolchain are pinned.
No root Cargo workspace exists: native host code and freestanding AArch64 code
are deliberately separate workspaces.

The typed test-author acceptance contract and current FVP evidence are tracked
in [`docs/CAPABILITY_MODEL.md`](docs/CAPABILITY_MODEL.md). Completion progress is
recorded item by item in [`IMPLEMENTATION_TODO.md`](IMPLEMENTATION_TODO.md).
