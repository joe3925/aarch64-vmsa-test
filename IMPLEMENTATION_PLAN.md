# `aarch64-vmsa` FVP Coverage Implementation Plan

## Objective and authority

Build an exhaustive integration-test suite for the current contents of the
read-only `aarch64-vmsa` checkout at
`/Users/boden/Documents/aarch64-vmsa`. The suite must exercise every
architecturally observable public behavior supported by the selected Arm FVP,
using the FVP's hardware behavior as the final oracle.

This is not a source-line-coverage or conventional unit-test project. Pure
marker types, aliases, reexports, compile-time bounds, and value-only helpers
with no independent architectural observation are covered by an explicit API
audit classification. Every behavior which can affect a translation, table
walk, access, fault, invalidation, or restoration must have FVP evidence.

The only accepted observational exception is cache state itself. Cache and
shareability encodings, coherency sequences, and data integrity must still be
tested, but a test need not prove the FVP's internal cache occupancy or
replacement behavior.


## Non-negotiable boundaries

1. Never modify the checkout under test. Do not format it, patch it, create
   tests in it, update its lockfile, or run a command that writes build output
   into it. Build it only through the harness's read-only crate mount.
2. Harness, payload, firmware integration, host runner, test documentation,
   `crate_report.md`, and test artifacts may be changed in this repository.
3. Test logic must use the stable API reexported from `vmsa_test_harness`.
   Tests must not use the rustdoc-hidden adapter API, raw firmware callbacks,
   direct system-register manipulation, exception records, UART, arbitrary
   table pointers, or frame-provider internals.
4. The only malformed-descriptor escape hatch is the affine
   `IsolatedMalformedTable` plus `TransitionSandbox` API. It must be used before
   installation and must be followed by exact restoration checks.
5. If a required architectural observation cannot be expressed through the
   stable harness, first demonstrate that the missing or incorrect behavior is
   a harness defect. Add the narrowest typed harness operation needed and test
   its cleanup. Do not work around it with adapter internals.
6. Keep code idiomatic, typed, small, and domain-oriented. Reuse useful setup
   from the current smoke tests, but do not preserve monolithic smoke cases or
   duplicate format/regime setup.
7. Never weaken an expectation to make a run pass. Do not convert a failure to
   a skip, expected failure, warning, or ignored test.

## Definition of 100% coverage

Coverage is complete only when all of the following are true:

- A freshly generated rustdoc/API inventory covers every public crate-owned
  item in the exact checkout contents used by the run. Every item is assigned
  one of these routes: compile-time/type-only, architecturally unobservable
  value behavior, typed descriptor inspection, direct FVP execution, isolated
  malformed input, or FVP-unsupported capability.
- Every item with an architectural effect maps to at least one named catalog
  test and retained run evidence. No observable item remains
  `evidence-incomplete`.
- Each applicable row of the matrix below has positive behavior, exact
  negative behavior, state restoration, resource cleanup, and a following-test
  isolation observation.
- A supported applicable case without an adapter handler is a harness failure,
  never a skip. `unsupported` is valid only when the FVP's ID registers or
  capability probe say the feature is absent.
- Every required test has been added and executed. A crate-caused failure may
  remain failing only under the reporting procedure below; the test itself
  must remain registered and unchanged.
- There are no files, modules, catalog names, functions, or documentation
  references presented as smoke tests.

The generated API audit is a guard against omissions, not a substitute for
hardware evidence. An encoder/decoder round trip alone is also insufficient:
both halves may share the same bug.

## Required platform and ownership matrix

Run every test on every applicable profile. Share payload-independent logic in
`target/payloads/common`; payload crates should normally contain only regime
aliases, platform-specific semantic values, and thin handlers.

| FVP profile | Required crate regimes and observations |
|---|---|
| Normal-world EL2 | `NonSecureEl2Stage1`, `NonSecureEl1Stage1`, `NonSecureEl2HostStage1`, `NonSecureEl2Stage2<Stage2Permissions>`, and `NonSecureEl2Stage2<Stage2XnxPermissions>`; current EL2, EL1, EL0/EL1, EL2&0, stage 2, combined stage 1+2, ASID, VMID, and secondary-PE observations |
| Secure EL2 | `SecureEl2Stage1`, `SecureEl1Stage1`, `SecureEl2HostStage1`, `SecureEl2SecureIpaStage2`, and `SecureEl2NonSecureIpaStage2`, with both stage-2 permission models where supported; Secure and Non-secure output PAS behavior |
| Realm EL2 / TRP | `RealmEl2Stage1`, `RealmEl1Stage1`, `RealmEl2HostStage1`, and `RealmEl2Stage2`, with both stage-2 permission models where supported; Realm and Non-secure output PAS behavior |
| Realm REC stage 2 | RMM-owned Realm stage-2 map, protect, unprotect, unmap, remap, AT/PAR, exact stage-2 faults, lifecycle reuse, and cleanup through the bounded Realm session API; never access RMM's live `VTTBR_EL2` directly |
| Root EL3 | `RootEl3Stage1`; Secure, Non-secure, Root, and Realm output PAS encodings and hardware effects; every supported format and granule |

The marker/regime constants must also be compared with the actual feature
snapshot in their owning profile. Equivalent implementations are not a reason
to omit a profile: security state, privilege, PAS, and register ownership are
hardware-visible differences.

## Required format, granule, level, and address matrix

For both stage 1 and stage 2 wherever the format is supported, generate cases
for every legal leaf level and verify the exact walk kind, level, indexes,
covered range, output base, output including a nonzero offset, and hardware
translation result.

| Format | Granule | Required legal leaf levels |
|---|---:|---|
| VMSA64 | 4 KiB | L1 block, L2 block, L3 page |
| VMSA64 | 16 KiB | L2 block, L3 page |
| VMSA64 | 64 KiB | L2 block, L3 page |
| VMSA64 LPA2 | 4 KiB | L0, L1, and L2 blocks; L3 page |
| VMSA64 LPA2 | 16 KiB | L1 and L2 blocks; L3 page |
| VMSA64 LPA2 | 64 KiB | L1 and L2 blocks; L3 page |
| D128 | 4 KiB | L0, L1, and L2 blocks; L3 page |
| D128 | 16 KiB | L1 and L2 blocks; L3 page |
| D128 | 64 KiB | L1 and L2 blocks; L3 page |

Also cover:

- all valid root/start levels down to VMSA64 `NEG1`, LPA2 `NEG1`, and D128
  `NEG2`, plus exact rejection immediately outside each range;
- step-by-one tables and every feasible D128 skipped-level transition using
  `BoundedSklTablePlan` and `MaxSklTablePlan`, including the allocation bound
  and no-valid-plan path;
- 32, 36, 40, 42, 44, 48, 52, and 56-bit output-width acceptance where the
  selected format permits it, with exact rejection where it does not;
- minimum, maximum, and one-past-maximum input/output addresses; arithmetic
  overflow; high PA bits in LPA2 and D128; page and block boundary crossings;
- aligned and misaligned roots, inputs, outputs, lengths, and table bases;
- table-growth boundaries that allocate a new terminal table, and reclaim of a
  last leaf versus a leaf whose siblings remain.

An impractically large D128 skipped-level table must be tested through bounded
planning and exact rejection rather than attempting an unsafe allocation.

## Test-family design

Split common test code by behavior rather than payload. A suitable structure is
`target/payloads/common/tests/{features,address_geometry,attributes,descriptors,
mapper,invalidation,platforms,failures}.rs`, with a small shared builder module.
The exact filenames may differ, but each catalog test must have one clear
claim, deterministic inputs, and an independently useful failure identity.

### 1. Feature discovery and regime validation

- Read the live ID-register snapshot through `VmsaFeatures::current` and
  `IdRegisterSnapshot::current`; require `decode_features(snapshot)` and the
  harness capabilities to agree with successfully exercised features.
- Validate every applicable regime and every format/granule combination with
  `validate_regime` and `validate_regime_format` in its owning profile.
- Correlate EL2, EL3, EL2&0, SEL2, RME, stage 2, XNX, LPA2, D128, D128 stage 2,
  extended input/output addressing, and security-state claims with a real
  positive operation. An ID claim that cannot perform its advertised behavior
  is not silently unsupported.
- Exercise requirement unions and security-state membership as assertions
  attached to the live cases; synthetic unknown ID encodings remain explicitly
  classified as value-only because no FVP hardware observation exists for
  them.

### 2. Address, granule, table geometry, and walk paths

- Use active mappings to corroborate every `GranuleKind`, `TranslationGranule`,
  `Level`, `TableGeometry`, `TableShape`, `TableTransition`, `TableWalkPath`,
  cursor, and location calculation against the walk and AT/PAR result.
- Verify exact root/table alignment, entry count, stride count, allocation
  layout, level shift, indexes, offsets, path length, terminal level, and
  transition step.
- Cover `OffsetTableAccess` through normal offline/live mappers and
  `RecursiveTableAccess` through a live recursive mapping, including exact
  negative recursive base/index/level/path errors through the stable harness.
- Verify `TranslationTable` reads and `TranslationTableMut` effects only
  through owned safe harness wrappers; tests must not construct arbitrary
  pointers.

### 3. Descriptor formats and walkers

- Exercise the bounded constructors/accessors reexported through
  `low_level::raw` at their minimum, maximum, and first-invalid values inside
  the descriptor cases. These checks are value-only and cannot claim hardware
  evidence by themselves; every raw field that can enter a descriptor must
  also be covered by typed inspection of a viable or isolated-malformed
  hardware table.
- For every matrix row, inspect invalid, table, block, and page outcomes as
  applicable. Compare normalized descriptor kind, raw width, table target,
  leaf output, decoded fields, and every bounded path step with the live
  hardware result.
- Exercise VMSA64 and LPA2 step-by-one tables, LPA2 DS/non-DS address placement,
  and D128 SKL table/leaf address alignment and next-level behavior.
- Verify offline `Walker`/mapper inspection and installed inspection agree,
  including block offsets and invalid/unmapped outcomes.
- Exercise exact `DescriptorError` paths: invalid leaf levels, invalid table
  transitions, reserved fields, D128 NT/BBM-at-final-level, and reserved-bit
  state. Hardware-facing malformed candidates must run in separate boots or a
  destructive sandbox as required by the matrix.
- Malformed type encodings, bad next-table addresses, illegal SKL, reserved
  RES0/RES1 state, and final-level table descriptors must fault or be rejected
  exactly, restore all translation/vector/stack state, and permit a clean
  mapping immediately afterward.

### 4. Semantic memory attributes

- Exhaust every encodable MAIR device and normal-memory value, including both
  cache policies, both transience values, all allocation hints, Non-cacheable,
  duplicate MAIR-slot selection, MAIR2 slots 8-15, and all exact unencodable or
  missing-slot errors.
- Exhaust stage-2 combined memory attributes and every FWB encoding, both FWB
  modes, MTE-permission gating, wrong-mode errors, and invalid encodings.
- Test VMSA64, LPA2, and D128 semantic construction and inspection at stage 1
  and stage 2. Require the semantic value, raw descriptor inspection, active
  access, and restored MAIR/MAIR2/control state to agree.
- Test every shareability value, invalid raw shareability, and LPA2 DS
  effective-shareability agreement/mismatch. Confirm that 64 KiB LPA2 retains
  its descriptor-carried shareability behavior rather than inheriting the DS
  rule.
- For cacheability/shareability, require correct encode/decode, active data
  integrity, generated-code coherency, and multi-PE publication where
  applicable. Do not claim to observe internal FVP cache residency.

### 5. Permissions, controls, and hardware-updated fields

- Exhaust single-privilege and two-privilege stage-1 AP leaf/table values,
  execute combinations, table limits, and every unencodable combination.
- Exhaust direct stage-2 AP/XN values. Without XNX, test both valid common
  execute states and exact rejection of mixed privilege states. With XNX, test
  all data and privileged/unprivileged execute combinations.
- Exhaust D128 stage-1 PI/PO base and overlay entries, reserved entries, WXN,
  optional unprivileged registers, GCS gating, duplicate matches, unavailable
  indirection, and missing combinations. Exercise all hardware-distinguishable
  effective data/execute permissions at the appropriate EL and EL0 context.
- Exhaust D128 stage-2 `Stage2Permission` values, all 16 base entries, all 16
  overlay entries, MostlyReadOnly qualifiers, WriteOnly, execute combinations,
  reserved-as-no-access behavior, unavailable overlay, and missing
  combinations. Use hardware accesses/faults for every distinguishable result.
- Cover AF and dirty updates with HA/HD disabled and enabled for VMSA64 and
  D128, stage 1 and stage 2 wherever the architecture exposes the update.
- Cover global/non-global aliases, Root NSE aliasing, D128 alias mode,
  contiguous, guarded, protected/assured-only, force-no-execute, BBM/NT,
  table-NT, DISCH, table access flag, and the entire 4-bit/10-bit software
  metadata range. Architecturally ignored hint fields require exact typed
  inspection plus a viable active mapping, not a fabricated behavioral claim.
- Every permission denial must assert exact class, access kind, stage, level,
  FAR, and IPA when architecturally supplied. Read, write, privileged execute,
  and unprivileged execute must be distinguished.

### 6. Physical address spaces

- Exercise fixed Non-secure, fixed Realm IPA, Secure-selectable, Realm-or-
  Non-secure, and Root-extended PAS models through semantic leaves and tables.
- In Secure EL2 cover Secure and Non-secure stage-1 outputs, Secure-IPA and
  Non-secure-IPA stage-2 contexts, configured output PAS equality, and mismatch
  rejection.
- In Realm EL2 cover Realm and Non-secure output selections at both stages.
- In Root EL3 cover Secure, Non-secure, Root, and Realm encodings and access or
  the exact architectural protection fault.
- Require PAS-appropriate owned memory, cleanup/delegation reversal, table PAS
  inheritance, malformed NSE/NS rejection, and exact normalized GPC faults.
  If the stable harness lacks an owned pool required for an applicable PAS,
  treat that as a harness gap and add a typed scoped allocator; never borrow a
  firmware address directly.

### 7. Mapper operations and transactional behavior

- Cover offline and live construction, all public accessors/`into_parts`, page
  and block mapping, mapping with each table planner, range mapping, semantic
  mapping, software translation, exact mapping metadata, unmap, and recursive
  reclaim.
- Verify zero-length ranges, multi-table ranges, already-mapped collisions,
  unmapped translation/unmap/reclaim, non-leaf-base unmap, sibling preservation,
  root-empty reporting, exact allocation/free counts, and retry after failure.
- For every operation failure, observe the documented or name-implied
  postcondition. In particular, determine whether `map_range`, remap, protect,
  and table growth are atomic at their advertised boundary. If hardware and
  retained table inspection show behavior inconsistent with the public name or
  contract, classify it as a crate failure rather than teaching the test that
  surprising behavior is acceptable.
- Exercise every reachable `MapperError`, `AccessError`, `TableError`,
  `TableAddressError`, `WalkCursorError`, and `WalkError` variant with exact
  fields. Use scoped access/frame/failure injection for generic provider
  errors. Classify truly unreachable generic states explicitly in the API
  audit; do not silently omit them.

### 8. Live invalidation, identity, and combined translations

- Verify live mapper invalidation ordering for leaf/table insertion and
  removal, synchronization, and frame reclaim through hardware-visible stale
  versus current translations and the harness's typed invalidation API.
- Exercise protect, remap, break-before-make, failed replacement rollback,
  unmap, reclaim, and following access/fault. Verify the original mapping is
  retained after a failed mutation.
- Exercise local and inner-shareable TLBI for VA, IPA, VA range, IPA range,
  ASID, VMID, and all entries. Assert wrong-stage, wrong-identifier, invalid
  range, and unsupported-scope rejection.
- Verify ASID and VMID separation with independently owned roots and values.
- Exercise mixed format/granule/width combined stage 1+2 translation, each
  stage's independent inspection and mutation, stage-specific faults, combined
  TLBI order, and reverse-order restoration.
- Verify primary/secondary PE visibility where invalidation scope matters.

### 9. Failure, recovery, and isolation

- Inject every harness-supported allocation, table access, mapping, install,
  mutation, invalidation, lower-entry, secondary-PE, REC/RMM, cleanup, and
  restoration failure point at the earliest and latest meaningful boundary.
- After each non-destructive failure, inspect roots/resources, retry the same
  operation, restore, and run a sentinel translation in the same boot.
- Use separate boots for malformed or potentially corrupting transitions and
  destructive boots for expected model termination. Confirm the host reports
  the exact expected termination and continues with the next independent boot.
- Verify emergency restoration independently of the test's explicit cleanup,
  including translation controls, roots, MAIR/MAIR2, vectors, stack, exception
  state, memory scope, secondary PE, Realm lifecycle, and delegated pages.
- No test may depend on catalog order for correctness. A following sentinel is
  evidence of isolation, not a hidden cleanup mechanism.
- Match every reachable `AttrError` variant exactly at the stable semantic
  boundary. If a variant is proven unreachable through all public codecs,
  record that proof and its value/type-only classification in the API audit.

## Test construction pattern

Every positive hardware test should, where applicable:

1. Check typed requirements and allocate PAS-correct scoped memory.
2. Seed distinct values in the original and replacement outputs.
3. Build with the crate through an offline harness mapper.
4. Inspect the complete offline walk and semantic value.
5. Install through an owned `LiveTranslation` or `CombinedTranslation` guard.
6. Compare crate translation, hardware AT/PAR, and actual read/write/execute.
7. Mutate one property and verify both the allowed operation and exact denied
   operation/fault.
8. Unmap or restore explicitly, verify the expected fault or original mapping,
   then drop all owned resources.
9. Run or leave a catalog-adjacent isolation sentinel that proves the platform
   can install and restore a fresh mapping.

Use different input/output values and nonzero offsets so swapped stages,
truncated addresses, stale TLB entries, and accidental identity mappings cannot
pass.

## Failure triage and `crate_report.md`

On any failing test, stop broad implementation work on that test long enough
to classify the failure. Preserve the original failure artifacts.

### Harness failure

A failure is a harness failure when the crate was not given the requested
state, the wrong platform/context ran, setup or normalization is incorrect, a
stable API violates its ownership contract, or cleanup/dispatch/reporting is
wrong. Prove this with the smallest control case and retained observations.
Fix the harness, add a regression assertion, rerun the failing test, rerun its
isolation sentinel, then rerun every affected profile. Harness failures must be
fixed before the corresponding TODO can close.

### Crate failure

A failure is a crate failure when the crate-created state disagrees with FVP
hardware behavior or any public crate behavior is wrong, including:

- incorrect mapping, descriptor, walk, attribute, permission, PAS,
  invalidation, reclamation, or error result;
- failure to reject an invalid input or rejection of a valid input;
- incorrect state after an error;
- behavior inconsistent with the function/type name or apparent public
  contract, even if it is a small naming/semantic mismatch.

Do not modify the tested checkout. Do not remove, disable, rename away, relax,
or mark the failing test as expected. Keep it registered and failing so it can
be debugged after the test project is returned.

Append, never overwrite, a section in root-level `crate_report.md` containing:

- a stable issue ID and UTC timestamp;
- exact catalog case identity, profile, advertised capabilities, and command;
- public crate items and source area under test;
- expected hardware-visible behavior;
- actual result, normalized fault/error, and retained artifact paths;
- the minimal reproduction and control comparison;
- why setup, harness, firmware, and cleanup were ruled out;
- why the result is considered a crate failure, including any name/contract
  mismatch;
- confirmation that the tested checkout was not changed and the test remains
  enabled.

One report section may group identical manifestations only when the retained
case identities are all listed. A later rerun may append status; prior evidence
must remain intact.

### Unsupported FVP feature or model limitation

Use `unsupported` only when the FVP reports a required feature absent before
the case runs. If the FVP advertises a feature but a crate-generated mapping
fails, use a known-good harness-owned control and another applicable context to
separate a model limitation from crate output. Record a genuine model
limitation in run evidence and the API audit, not `crate_report.md`, but never
use it to hide an independently reproducible crate failure. Cache residency is
the sole pre-approved unobservable behavior.

## Smoke-test migration

The current `target/payloads/common/smoke.rs` and
`target/payloads/common/translation_smoke.rs` are implementation material, not
the final organization.

- Move reusable builders and useful assertions into domain modules.
- Split each multi-purpose smoke function into narrow catalog cases with names
  such as `features.*`, `geometry.*`, `descriptor.*`, `attributes.*`,
  `mapper.*`, `invalidation.*`, `pas.*`, and `recovery.*`.
- Remove harness-only demonstrations that do not contribute to crate coverage;
  keep required harness controls as shared helpers or explicit preconditions,
  not as smoke cases counted toward crate coverage.
- Delete both smoke source files, their module declarations, all `smoke.*`
  registry names, and stale documentation references after every useful path
  has either migrated or been deliberately removed.
- Do not close migration based only on renamed functions. The new cases must be
  independently filterable and must identify the exact behavior they prove.

## Execution and evidence workflow

1. Before edits, record both repositories' status and the tested checkout's
   provenance. Keep unrelated user changes intact.
2. Regenerate the API inventory for the exact checkout without writing to it.
   Update audit routes as tests are added; never lower the expected item count
   to conceal a missing item.
3. Add test families incrementally. Use filtered profile runs during
   development and retain artifacts for failures.
4. After a family is complete, run it in every applicable profile and run the
   adjacent isolation sentinel.
5. Run the complete suite with the explicit read-only crate path:
   `vmsa-test test all --crate /Users/boden/Documents/aarch64-vmsa`.
6. Rerun the complete suite once from a clean new invocation to detect order,
   retained-state, and boot-grouping dependencies.
7. Validate that the API audit has zero unclassified items and zero incomplete
   observable routes. Validate catalog uniqueness and firmware ABI before the
   final run.
8. Review all failures. No untriaged result, harness-caused failure, missing
   adapter, accidental skip, boot corruption, leaked resource, or missing
   artifact may remain.
9. Check an item in `IMPLMENTATION_TODO.md` only after its code, catalog row,
   applicable runs, cleanup evidence, and failure disposition satisfy that
   item's gate.

## Completion and return rule

The implementing agent may return only when every checkbox in
`IMPLMENTATION_TODO.md` is checked. A test checkbox may be checked when the test
passes everywhere applicable, or when it remains enabled and its crate-caused
failure is fully appended to `crate_report.md`. It may not be checked for an
unfixed harness failure, untriaged result, missing run, missing adapter, or
unjustified skip.

The final handoff must state the tested crate fingerprint, profiles run, pass /
crate-failure / unsupported totals, retained evidence locations, harness files
changed, confirmation that smoke tests are gone, confirmation that the tested
checkout was not modified, and the location of `crate_report.md` if it exists.
