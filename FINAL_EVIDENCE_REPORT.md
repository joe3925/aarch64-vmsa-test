# Production harness final evidence

Final verification was performed on 2026-07-13 against the required read-only checkout at `C:\Users\Boden\Documents\temp\aarch64-vmsa`.

## Result

The final exact all-target run completed in 143.9 seconds with 68 passed, 0 failed, and 1 skipped case. There were no harness failures, unexpected exceptions, hangs, cleanup failures, restoration failures, adapter gaps, or crate-attributable failures.

| Boot | Passed | Failed | Skipped | Retained artifact |
|---|---:|---:|---:|---|
| NS-EL2 sequential | 35 | 0 | 0 | `output/runs/ns-el2-00001784008716222028-25628` |
| NS-EL2 isolated malformed recovery | 1 | 0 | 0 | `output/runs/ns-el2-00001784008748647367-25628` |
| Secure EL2 | 8 | 0 | 1 | `output/runs/secure-el2-00001784008782538283-25628` |
| Realm EL2 | 8 | 0 | 0 | `output/runs/realm-el2-00001784008790050248-25628` |
| Realm REC stage 2 | 8 | 0 | 0 | `output/runs/realm-stage2-00001784008797266118-25628` |
| Root EL3 | 8 | 0 | 0 | `output/runs/root-el3-00001784008850726311-25628` |

The single skip is `smoke.lpa2-descriptor` in Secure EL2, whose reported profile capabilities contain `lpa2=0`. It is a meaningful but unavailable selected-FVP/profile feature, not an adapter omission.

## Capability and smoke coverage

The code-represented acceptance matrix and its construction/inspection/cleanup routes are in `docs/CAPABILITY_MODEL.md`. The stable test-author surface and registration examples are in `docs/TEST_AUTHOR_API.md`. Together with the final runs above, they cover:

- Normal, Secure, Realm, REC-owned Realm, and Root security environments.
- Current stage 1, lower-EL stage 1, EL2 stage 2, combined stage 1+2, REC-owned Realm stage 2, and Root stage 1 ownership.
- Current EL, EL1, EL0 under EL1, EL2&0, R-EL1 REC, and secondary-PE execution.
- VMSA64, active LPA2, active D128, and active 4/16/64-KiB translations.
- Page/block/range construction, intermediate growth, live install/mutation/BBM/unmap, walks/descriptors, hardware AF/dirty updates, semantic attributes, and automatic restoration.
- Scalar, pair, ordered, atomic, generated instruction, execute, and AT/PAR access paths.
- ASID/VMID isolation, typed TLBI scopes/operands, cache and table visibility, and multi-PE visibility.
- Exact normalized instruction/data, read/write/execute, translation/permission/address-size/access-flag, stage/level/FAR/IPA fault observations.
- Deterministic PAS-aware memory, exhaustion/contiguous boundaries, secondary lifecycle, Realm/RTT/REC lifecycle, failure injection, cleanup, and isolation.

Representative mechanism evidence is the 35-case NS sequence for generic stage-1/stage-2 behavior, the separately booted malformed-descriptor recovery case, the three other security adapters, and the eight-case REC lifecycle. Equivalent generic behavior is intentionally not duplicated in every payload.

## Public API audit

`tools/validate_api_audit.py` accepts all 773 unique public API items for VMSA revision `ada32824cd813c16ab6ea30322ee396aad3aaa75`. `docs/api-coverage.csv` classifies every item as directly exercisable, inspectable, isolated malformed input, compile-time-only, architecturally unobservable/constrained, or unavailable on the selected FVP. No architecturally observable item requires another harness abstraction.

## Build, ABI, portability, and cleanup gates

- Host formatting and `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Target formatting and `cargo clippy -Z build-std=core,alloc,compiler_builtins --workspace --all-targets -- -D warnings`: passed. Cargo's note about future compatibility of the nightly-rebuilt `core` is toolchain informational output, not a project warning.
- Python syntax/static validators: passed.
- Firmware ABI validator: passed for boot context v3, lower-EL mailbox v2, secondary command v2, Realm REC record v2, and report protocol v1.
- Assembly/AAPCS64 and C/Rust layout review: passed as recorded in the checklist.
- Host portability checks: passed for installed Windows/Linux x86-64 and AArch64 targets.
- Strict `doctor`: passed in 21.3 seconds, covering phase-specific build/package/startup/suite/test deadlines, expected destructive termination, concurrent capture, process-tree termination, and scratch/container cleanup.
- Secondary firmware polling is bounded by the architectural counter; an unrecoverable live PE resets the boot instead of contaminating later tests.
- Cancellation, partial-build/package failure, failed-artifact retention, unique disposable worktrees, cache retention, and independent-boot continuation are validated by the retained evidence referenced in `IMPLEMENTATION_CHECKLIST.md`.

## Integrity and prohibited-pattern confirmation

The final run provenance records VMSA revision `ada32824cd813c16ab6ea30322ee396aad3aaa75`, its pre-existing dirty state, unchanged content fingerprint `fnv1a64:efe950d65438f158`, and `ro=true` mounting. The harness did not modify the checkout.

The final repository audit found no project-owned Rust unit tests or `cfg(test)` modules, TODO/placeholders, `todo!`, `unimplemented!`, warning suppressions, Tarmac markers, temporary diagnostic breadcrumbs, or ignored fake-success paths. UART remains only as the versioned firmware report/panic transport; test logic performs no UART formatting or raw firmware interaction.

Future comprehensive coverage requires only test logic, typed matrix requirements, and one explicit row in `target/harness/src/registry.rs`. It does not require a new harness API, firmware path, exception/EL transition, raw register access, memory ownership mechanism, cleanup path, FVP knowledge, Podman knowledge, or host-specific logic.
