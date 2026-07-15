# Public `aarch64-vmsa` API coverage audit

Audit source:

- Checkout: `/Users/boden/Documents/aarch64-vmsa`
- Revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- Checkout state: dirty before harness work; mounted and inspected read-only
- Rustdoc JSON: `output/api-audit-target/doc/aarch64_vmsa.json`
- Item inventory: [`api-coverage.csv`](api-coverage.csv)
- Generator: [`../tools/generate_api_audit.py`](../tools/generate_api_audit.py)

The inventory contains all 774 crate-owned items whose rustdoc visibility is
`public`: 279 functions, 192 fields, 131 structs, 59 reexports, 39 enums, 31
traits, 17 associated constants, 17 modules, and 9 type aliases. Methods and
fields absent from rustdoc's exported `paths` table are recovered through their
owning impl/type relationship; they are not silently omitted.

## Scope exclusions

Completion means that every architecturally observable public behavior exposed
by the crate and supported by the selected FVP can be constructed, executed,
inspected, and restored through the harness. It does not claim source-line or
branch coverage for private unreachable implementation details, pure
compile-time/type-system invariants, architecturally constrained or
unpredictable behavior, implementation-defined observations, or architectural
features absent from the selected FVP. Those categories remain explicit audit
classifications rather than being counted as executed coverage.

## Classification totals

| Classification | Items | Meaning |
|---|---:|---|
| Type-only | 213 | Marker regimes, traits, aliases, namespace/reexport surface, and associated type constraints with no independent run-time observation |
| Value-only | 71 | Pure value/address/raw-field behavior asserted by bounded catalog tests |
| Isolated malformed input | 9 | Typed error paths whose observation requires malformed descriptors, invalid geometry, allocation failure, or scoped injection |
| Typed inspection | 285 | Attribute codecs, descriptor fields/layouts, walk state, and semantic/effective values |
| Direct FVP execution | 196 | Table and mapper construction, live mutation, translation, reclamation, and invalidation behavior |
| Genuinely FVP-unsupported | 0 | No public item is globally absent from the selected FVP; environment-specific absences remain capability-backed matrix `SKIP` outcomes |

## Current audit status

The inventory, item classification, and route fields are complete. A machine
check on 2026-07-14 found 774 unique item IDs, zero blank classifications, zero
blank harness routes, and zero incomplete evidence states. Items marked
`classified` are type-only or value-only surfaces without an independent FVP
observation; observable items name their catalog route and retained evidence.

Known capability gaps discovered by this audit and the FVP runs are:

- The selected Fast Model accepts D128 table queries at current EL2 but raises
  an instruction translation fault on enable despite a complete inspected walk;
  retained Iris state is in
  `output/runs/ns-el2-00001783986518058654-11640/artifacts/iris-current-el2-d128.txt`.
  The independent 52-bit lower-EL D128 hardware walk passes, so current-EL D128
  is tracked as an environment-specific FVP limitation rather than a global
  public-item classification.

- Descriptor/walk inspection still exposes too little semantic/path detail;
  the isolated malformed-input surface and invariant recovery sandbox remain
  incomplete.
- Typed TLBI now covers stage-checked VA/IPA/ranges, EL1 ASID, active VMID,
  local/inner-shareable scope, and combined routing. Complete adapter/regime
  breadth and cache-maintenance breadth remain incomplete.
- D128 stage 1 and stage 2 now have active walks, typed permission mutation,
  normalized faults, targeted TLBI, and exact restoration. Stage-1 AF/dirty
  hardware updates are active; remaining breadth is tracked by the adapter and
  control aggregate items rather than a missing fundamental D128 path.
- Malformed/reserved/invalid-geometry recovery does not yet cover the complete
  invariant transition sandbox.
- PAS delegation and firmware/Realm failure-injection breadth remain
  incomplete. Secondary-PE sessions and the adapter state machine are typed,
  including explicit `Uninitialized`, but timeout/model-termination recovery
  evidence remains incomplete.
- REC-owned Realm stage 2 now executes inside a real R-EL1 REC and provides
  typed protected access, normalized faults, and owned unprotected
  map/unmap/remap/protect through TF-RMM plus exact R-EL1 AT/PAR semantics.
  Descriptor inspection and failure-injection breadth remain incomplete. No
  test mutates RMM's active `VTTBR_EL2`.

Remaining breadth tracked outside the public-item audit maps directly to
[`CAPABILITY_MODEL.md`](CAPABILITY_MODEL.md) and the unchecked entries in
[`../IMPLEMENTATION_TODO.md`](../IMPLEMENTATION_TODO.md).

The stricter post-plan audit is
[`BRANCH_AREA_AUDIT.md`](BRANCH_AREA_AUDIT.md). It expands generic API routes
into regime/format/stage combinations and deliberately leaves ordering,
non-representative live branches
unchecked until they have direct evidence. Its unchecked boxes supersede the
older sentence above as the current beyond-plan work queue.
