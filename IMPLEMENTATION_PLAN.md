# `aarch64-vmsa` remaining branch-gap implementation plan

## Objective

Close every currently unchecked area in
`docs/BRANCH_AREA_AUDIT.md` against the exact read-only crate checkout at
`/Users/boden/Documents/aarch64-vmsa`. The starting scope is 34 areas. A gap is
closed only by an independently named test route with the evidence tier
required by the audit, or by a rigorously demonstrated platform limitation
whose assertion remains enabled and isolated.

This plan intentionally excludes:

- non-AArch64/custom-target and alternate atomic-code-generation builds;
- concurrent writer/walker stress and no-tearing races, which are accepted for
  static review;
- inspection or mutation of TF-RMM-owned Realm stage-2 descriptors, because it
  does not exercise unique crate branches.

Do not reopen completed audit areas unless a regression is discovered while
implementing the remaining scope.

## Non-negotiable boundaries

1. Never modify `/Users/boden/Documents/aarch64-vmsa`. Do not format it,
   patch it, create tests in it, update its lockfile, or write build output into
   it. Build it only through the harness's read-only mount.
2. Tests must exercise public `aarch64-vmsa` behavior. The harness may supply
   memory, register installation, EL transitions, guarded accesses, faults,
   and cleanup, but it must not reproduce VMSA encoding, decoding, walking, or
   mapper logic as an oracle.
3. Expected values must come from an architectural constant, simple test
   arithmetic, an exact public crate error, or an independent FVP access,
   fault, AT/PAR, walk, or cross-PE observation. Encoder/decoder round trips
   alone are insufficient live evidence.
4. Use stable typed harness APIs. If an observation cannot be expressed
   because the harness is missing or incorrect, fix the general harness
   facility and test its restoration. Do not reach through adapter internals
   or add a case-specific bypass.
5. Keep cases isolated. One assertion failure must not prevent unrelated
   catalog identities from running. If later checks do not require the failed
   result, split them into separate tests. Destructive/model-terminating cases
   must run in separate boots.
6. Never add a special code path that accepts, skips, or changes behavior for
   one failing assertion. Never weaken an expectation to make a run pass.
7. Add coherent batches of tests before building and running them. Compile
   time dominates, so do not repeatedly compile and boot for one newly added
   case when the rest of the batch can be added first.
8. `crate_report.md` is only for confirmed crate failures. It must never
   contain progress, harness defects, FVP limitations, plans, or passing-test
   summaries.

## Failure disposition rules

Every failure must remain visible and be classified using these rules.

### Harness failure

A harness failure includes an absent handler for an applicable case, incorrect
capability routing, an invalid test oracle, firmware ABI/setup defects,
register or memory restoration defects, timeouts, isolation failures, and
profile configuration that hides a feature the selected FVP can expose.

Fix every harness failure in this repository. Add a regression assertion, then
rerun the failing batch and every affected profile. Do not record a harness
failure in `crate_report.md`.

### Crate failure

A crate failure is a disagreement in public `aarch64-vmsa` behavior supported
by an independent expectation or architectural observation. Never modify the
crate checkout. Keep the independently named test registered, enabled,
isolated, and failing. Append a complete entry to `crate_report.md` with the
case, profile, command, checkout fingerprint, public APIs/source area,
expected and actual behavior, minimal reproduction, control comparisons, and
retained evidence paths. Never overwrite prior entries.

### FVP or firmware limitation

If the crate-produced state is independently correct but the model terminates,
faults inconsistently, or cannot expose an architectural observation, retain
the assertion and artifacts. Record the limitation in run/audit evidence, not
`crate_report.md`. Do not add an exception branch or convert the case to a
pass/skip.

### Unsupported capability

`Unsupported` is valid only when live architectural ID registers report the
feature absent after all required model and firmware profile configuration has
been supplied. A missing launcher switch, TF-A option, adapter handler, or
firmware conduit is a harness failure, not unsupported hardware.

An untriaged failure, incomplete boot, timeout, suppressed later case, or
unrestored state is never an acceptable final result.

## Workstream 1: feature decoder value branches

Add synthetic `IdRegisterSnapshot` tables for `BA-FEAT-010`, `BA-FEAT-011`,
and `BA-FEAT-012`. Drive every implemented, absent, reserved, and unknown arm
of binary features, EL2/EL3, RME, VARange, PARange, LPA2 primary/secondary
granule fields, and derived-state merging. Expected raw field selections must
be explicit test inputs rather than a second decoder implementation.

These are value/inspection cases. Keep them independently named even though
they can run in one compiled Normal payload batch.

## Workstream 2: enable real profile capabilities

Make feature-dependent profile setup general before adding semantic cases.

- Enable the already-proven Realm LPA2 model parameters and 52-bit PA/VA
  configuration for Realm EL2 and Realm REC.
- Enable Realm D128 model parameters and the required TF-A
  `ENABLE_FEAT_D128=2` path for REC exposure.
- Replace hard-coded "extended formats unsupported" profile assertions with a
  generic comparison between crate format validation and the live decoded
  feature set.
- Probe Secure LPA2/D128 and Root LPA2 with the selected FVP and pinned
  firmware. Exhaust viable model/firmware configuration before classifying a
  combination unavailable.
- Require `features.live-snapshot-agreement` and
  `features.regime-format-validation` to pass for every enabled profile before
  relying on that profile's semantic tests.

Feature enablement is infrastructure. Tests must still construct and inspect
descriptors through the crate.

## Workstream 3: PAS and D128 permission behavior

Close `BA-PAS-012` through `BA-PAS-014` with live Secure/Realm D128 and LPA2
semantic mappings, exact output PAS selection, hardware access/fault evidence,
typed inspection, and full restoration.

Close `BA-PERM-015` through `BA-PERM-018` by expanding the existing D128
permission matrices into independently named live cases. Cover stage-1 and
stage-2 base/overlay selection, bypass, duplicate/missing/conflicting inputs,
Root, Realm, and Secure regimes. Offline exhaustive matrices may supply the
case inventory but cannot replace live representative evidence for each
material branch.

Do not create one monolithic permission test whose first mismatch suppresses
the remaining combinations.

## Workstream 4: semantic codec regime matrix

Close the remaining codec areas with crate semantic construction, raw
descriptor inspection, a live access/fault/AT observation, semantic decode,
and restoration:

- Normal: `BA-CODEC-006`, `BA-CODEC-007`, and isolated current-EL2 D128
  `BA-CODEC-008`.
- Secure: `BA-CODEC-010` through `BA-CODEC-014`.
- Realm: `BA-CODEC-016`, `BA-CODEC-017`, and `BA-CODEC-019` through
  `BA-CODEC-021`.
- Root: `BA-CODEC-024` and `BA-CODEC-025`.

Cover all applicable granules, legal leaf/table levels, direct and XNX stage-2
permission models, PAS alternatives, memory modes, and descriptor controls.
Reuse generic builders in `target/payloads/common`; payload crates should
provide only regime aliases and genuinely environment-specific semantic
values.

The known Normal current-EL2 D128 model fault must be an isolated enabled case.
Its failure cannot suppress lower-EL D128 or any following codec identity.

## Workstream 5: live planner, SKL, and completed BBM

Close `BA-DESC-013`, `BA-MAP-013`, and `BA-ORDER-012`.

- Install every feasible D128 skipped-level transition live for all granules
  and both stages where supported.
- Install step-by-step, bounded-SKL, and maximum-SKL planner results for every
  format/granule/stage family without attempting unsafe impractical
  allocations.
- Add one end-to-end break-before-make case that observes the crate callback
  sequence, descriptor invalidation/replacement, required barrier/TLBI events,
  the final hardware result, and restoration in one completed non-concurrent
  mutation.

Keep the known `MaxSklTablePlan` crate failure enabled and reported; do not
special-case it to reach later planner cases. Give independent planner
families independent identities.

## Workstream 6: completed-mutation cross-PE visibility

Close `BA-ORDER-015`, `BA-ORDER-016`, `BA-ORDER-018`, and `BA-ORDER-019`.
These tests observe a secondary PE only after the primary has completed
publication/invalidation; they do not require concurrent writer/walker races.

- Generalize the current Normal 4 KiB VMSA64 case to VMSA64 16/64 KiB and
  LPA2 4/16/64 KiB.
- Add Normal stage-2 direct/XNX completed-mutation visibility.
- Supply general secondary-PE conduits and per-PE translation setup/restoration
  for Secure, Realm EL2, Realm REC, and Root where their firmware ownership
  permits it.
- Treat absent secondary callbacks, wrong per-PE registers, and cleanup
  failures as harness failures. Each profile/case must be independently
  runnable.

Do not extend this work into simultaneous mutation races or RMM table
introspection.

## Workstream 7: malformed bits and exact fault matrix

Close `BA-FAULT-009` and `BA-FAULT-010`.

- Inject every architecturally RES0/RES1 bit independently for every real
  descriptor layout. Generate independent catalog identities so an accepted
  malformed bit cannot suppress later bits.
- Repeat exact address-size, translation, permission, access-flag, execute,
  alignment, malformed-table, PAS/GPC, and applicable stage-2 fault classes
  across every supported format, granule, and regime.
- Assert normalized status, access kind, stage, level, FAR, and IPA whenever
  architecturally supplied.
- Use destructive boots for model-terminating inputs and verify independent
  later boots still run.

Accepted malformed encodings are crate/FVP observations, not reasons to alter
the harness expectation.

## Batch execution and validation

For each workstream, add the complete coherent case batch before compiling.
Then run formatting/static validation once, compile once, and execute the
largest useful filter/profile batch. After harness fixes, rerun the affected
batch rather than one assertion at a time.

Required validation includes:

```text
python3 tools/verify_branch_area_audit.py
python3 tools/validate_harness_boundary.py
python3 tools/validate_api_audit.py
cargo build --manifest-path host/Cargo.toml --release
host/target/release/vmsa-test doctor --crate /Users/boden/Documents/aarch64-vmsa
host/target/release/vmsa-test test all --crate /Users/boden/Documents/aarch64-vmsa
```

Run the complete suite a second time in a fresh invocation to expose test-order
or retained-state dependencies. Preserve failed/destructive evidence and
confirm the crate checkout fingerprint is unchanged.

## Completion gate

The implementation is complete only when:

- all 34 starting unchecked audit areas have concrete executed routes and no
  area remains unchecked;
- every harness-caused failure is fixed and regression-tested;
- every crate-caused failure remains enabled and is fully recorded only in
  `crate_report.md`;
- every FVP/firmware discrepancy remains enabled, isolated, and retained
  outside `crate_report.md`;
- no applicable case is skipped because of a profile or adapter gap;
- no failure prevents unrelated later identities from running;
- all validators, doctor, two complete all-profile runs, restoration, cleanup,
  provenance, and read-only-checkout checks pass subject only to the retained
  crate/FVP assertions above.
