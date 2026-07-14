# `aarch64-vmsa` crate failure report

## AVMSA-ATTR-001 — MAIR encode/decode disagreement for non-allocating cacheable memory

- First confirmed: 2026-07-14T07:47:33Z
- Catalog case: `attributes.mair-normal-matrix`
- Profile: Normal EL2 (`ns-el2`)
- Command: `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa`
- Tested checkout: HEAD `ada32824cd813c16ab6ea30322ee396aad3aaa75`, dirty content fingerprint `fnv1a64:efe950d65438f158`
- Advertised capabilities: EL2, EL3, EL2&0, SEL2, stage 2, XNX, LPA2, D128, D128 stage 2, extended input and output addresses, 4/16/64 KiB granules, 52-bit VA and PA; RME absent
- Public items under test: `Cacheability`, `CachePolicy`, `MemoryTransience`, `AllocationHints`, `MemoryAttributes`, `AttributeCodec::{resolve_leaf,decode_leaf}`, and `VmsaAttributeCodec`
- Source area: `attrs/resolve/memory.rs`, specifically MAIR cacheability encode/decode

Expected behavior: every semantic memory attribute accepted by `resolve_leaf` must decode from the resulting raw leaf and unchanged configuration to the same semantic value. In particular, the encoder accepts cacheable `NonTransient` memory with `AllocationHints::None`, producing nibble `0x8` for write-through and `0xc` for write-back.

Actual behavior: the corresponding decoder rejects those nibbles as `AttrError::UnencodableMemoryAttribute`. The exhaustive 15-by-15 inner/outer matrix completed all 225 combinations and reported 56 round-trip failures. The independent device-MAIR, MAIR-error, stage-2 combined-memory, and stage-2 FWB catalog cases all passed in the same boot.

Minimal reproduction:

1. Construct `MemoryAttributes::Normal` with either inner or outer cacheability set to `Cacheability::Cacheable { policy: WriteThrough or WriteBack, transience: NonTransient, allocation: None }`.
2. Put its public MAIR encoding in a `LiveVmsaConfig` slot.
3. Call `VmsaAttributeCodec::resolve_leaf` for VMSA64, `NonSecureEl2Stage1`, 4 KiB, L3; it succeeds.
4. Pass the returned raw leaf and unchanged configuration to `decode_leaf`; it returns `UnencodableMemoryAttribute`.

The control comparison covers all four device types and the remaining normal-memory combinations, plus independent stage-2 codec families. No live translation installation or platform register setup participates in this offline round trip. The target completed cleanup and all following cases, including live mappings, permissions, invalidation, and malformed-case isolation. This rules out FVP state, firmware setup, test ordering, and cleanup as causes.

The result is classified as a crate failure because two directions of the same public codec disagree on a value accepted by the encoder. The tested checkout was mounted read-only and was not changed. `attributes.mair-normal-matrix` remains registered, exhaustive, and failing.

Retained evidence:

- `output/runs/ns-el2-00001784015558764988-93455/`
- `output/runs/ns-el2-00001784015558764988-93455/results.log`
- `output/runs/ns-el2-00001784015558764988-93455/uart.log`
- `output/runs/ns-el2-00001784015558764988-93455/provenance.txt`

## AVMSA-MAPPER-001 — `MaxSklTablePlan` does not search past an unencodable initial stride

- First confirmed: 2026-07-14T08:05:00Z
- Catalog case: `mapper.max-skl-extended-root`
- Profile: Normal EL2 (`ns-el2`)
- Command: `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa`
- Tested checkout: HEAD `ada32824cd813c16ab6ea30322ee396aad3aaa75`, dirty content fingerprint `fnv1a64:efe950d65438f158`
- Advertised capabilities: D128 and the full capability set recorded in the retained provenance
- Public items under test: `MaxSklTablePlan`, `TablePlanProvider::plan_table`, `TablePlanContext`, `TablePlan`, `TableShape`, and `TableStrideCount`
- Source area: `mapper/plan.rs`, `choose_table_plan`

Expected behavior: from a D128 4 KiB root at level NEG2 toward an L3 leaf, `MaxSklTablePlan` should choose the largest supported progress. The path distance is five levels, while the public table-stride encoding permits at most four; the maximum feasible first child is therefore L2 with stride count four, followed by the final step to L3.

Actual behavior: `plan_table` returns `AccessError::InvalidTableStrideCount { stride_count: 5 }` before considering stride four. `choose_table_plan` contains a descending search loop, but `TableShape::new(child_level, step)?` exits the function on the first unencodable candidate instead of continuing the search.

Minimal reproduction:

1. Construct `TablePlanContext::<Vmsa128, Granule4KiB>` with parent `TableShape::root(Level::NEG2)` and target leaf `Level::L3`.
2. Construct `MaxSklTablePlan` with valid VMSA128 stage-1 table fields.
3. Invoke its `TablePlanProvider<Vmsa128, NonSecureEl2Stage1, Granule4KiB>::plan_table` implementation.
4. Observe `InvalidTableStrideCount { stride_count: 5 }` rather than a plan whose child is L2 and whose stride count is four.

Control comparisons in five independent catalog identities pass: `mapper.step-by-one-plan`, `mapper.bounded-skl-plan`, `mapper.maximum-skl-plan`, `mapper.bounded-skl-no-plan`, and `mapper.d128-skl-transition-matrix`. They cover step-by-one planning, every feasible D128 transition for all three granules, every fitting bounded stride, maximum supported strides, and exact no-plan errors for undersized allocation bounds. Table-path and walk-cursor cases also pass. No FVP translation installation is involved, and all following tests plus cleanup complete, ruling out platform state, ordering, and harness corruption.

This is classified as a crate failure because the public `MaxSklTablePlan` name and the implementation’s descending-search structure both require selecting the maximum feasible plan, while an invalid first candidate aborts that search. The tested checkout was mounted read-only and was not changed. `mapper.max-skl-extended-root` remains registered and failing.

Retained evidence:

- `output/runs/ns-el2-00001784028215467667-37237/` (expanded `mapper.` batch: 56 passes and only this retained crate failure)
- `output/runs/ns-el2-00001784027967550655-36350/` (complete `mapper.` batch: 54 passes and only this retained crate failure)
- `output/runs/ns-el2-00001784015872278629-94291/`
- `output/runs/ns-el2-00001784015872278629-94291/results.log`
- `output/runs/ns-el2-00001784015872278629-94291/uart.log`
- `output/runs/ns-el2-00001784015872278629-94291/provenance.txt`
- `output/runs/ns-el2-00001784023651969988-21068/`

## AVMSA-FVP-001 — D128 stage-1 and stage-2 AT/PAR omit the mapped output address while access succeeds

- First confirmed: 2026-07-14T10:39:18Z
- Catalog cases: the ten stage-1 `formats.d128-{4k,16k,64k}-*-at` identities and the ten stage-2 `formats.stage2-d128-{4k,16k,64k}-*-at` identities
- Independent control cases: the corresponding `*-block-access` cases
- Profile: Normal EL2 with a lower-EL1 D128 stage-1 translation
- Tested checkout: HEAD `ada32824cd813c16ab6ea30322ee396aad3aaa75`, dirty content fingerprint `fnv1a64:efe950d65438f158`

Expected behavior: stage-1 AT and combined stage1+stage2 AT through each installed D128 block or page should report the same physical address used by a real load through that mapping.

Actual behavior: the typed offline and installed walks report the expected nonzero-offset physical address and the independent real-access cases read the expected value. AT/PAR reports physical address `0x8` at every legal tested leaf level for 4 KiB, 16 KiB, and 64 KiB D128 translations in both stage 1 and stage 2. For example, the expected addresses in the retained large-granule stage-2 run were `0x88b91008` and `0x88b99008`; the raw PAR value was `0x8`, so the PAR decoder is not discarding address bits—the model supplied none.

The access and AT observations are separate catalog identities, and each identity executes only its owned observation. An AT failure therefore cannot suppress the real-access result at the same level or any other level. All ten high-input-address real-access cases pass at each stage.

This is recorded as an FVP/architectural-observation discrepancy rather than a codec exception or a reason to skip the cases. The crate-produced descriptors drive correct real accesses, but the model's AT/PAR result disagrees with those accesses. No special-case acceptance branch is present; all twenty AT assertions remain enabled and failing.

Retained evidence:

- `output/runs/ns-el2-00001784028236447132-37484/` (complete active-geometry-correlated `formats.` batch: 94 passes, 20 independently reported AT discrepancies, no timeout or suppressed later case)
- `output/runs/ns-el2-00001784029236954897-40402/` (complete `walk.` batch: 11 passes covering isolated invalid/block/table/page agreement and every exact walker error)
- `output/runs/ns-el2-00001784029386286290-40707/` (complete `tables.` batch: 8 passes covering live recursive access, safe table mediation, and isolated recursive rejection paths)
- `output/runs/ns-el2-00001784029739593312-41993/` (three end-to-end `map_leaf_with_plan` planner identities passed with exact outcomes and walk paths)
- `output/runs/ns-el2-00001784029957099365-42828/` (18 isolated offline mapper construction/accessor/`into_parts` identities passed across both stages, all formats, and all granules)
- `output/runs/ns-el2-00001784030080465290-43112/` (18 isolated live mapper construction/accessor/invalidation/`into_parts` identities passed across both stages, all formats, and all granules)
- `output/runs/ns-el2-00001784030247132311-43532/` (D128 descriptor batch passed both stages' final BBM/NT and table-NT/SKL=0 exact errors plus the live descriptor sentinel)
- `output/runs/ns-el2-00001784030370158827-43923/` (seven isolated allocator identities passed: arena exhaustion, page/contiguous/root injection, and all three 4 KiB table-growth failure boundaries with retry)
- `output/runs/ns-el2-00001784030459584657-44241/` (all three partial table-growth boundaries passed exact pre/post allocation counts, no-leaf inspection, retry, full reclaim, and root-empty cleanup)
- `output/runs/ns-el2-00001784030539295379-44517/` (`map_range` failure postcondition: a successfully mapped prefix remains visible when a later frame allocation fails; resuming at the first unmapped page completes the range, and reverse reclaim restores the allocation baseline. This matches the source-visible non-transactional loop.)
- `output/runs/ns-el2-00001784030714098443-45129/` (six isolated live mapper injection identities passed for map, range, remap, protect, unmap, and reclaim; every case verified preserved pre-failure state, retry, and the appropriate access/fault result)
- `output/runs/ns-el2-00001784027991967310-36598/` (complete strengthened `formats.` batch: 94 passes, 20 independently reported AT discrepancies, no timeout or suppressed later case)
- `output/runs/ns-el2-00001784027753751944-35737/` (complete `formats.` batch: 94 passes, 20 independently reported AT discrepancies, no timeout or suppressed later case)
- `output/runs/ns-el2-00001784027732021019-35473/` (stage 1, all granules, after 64 KiB runtime-layout isolation hardening)
- `output/runs/ns-el2-00001784027169499995-33916/` (stage 1, all granules)
- `output/runs/ns-el2-00001784027367029885-34264/` (stage 2, all granules)

## AVMSA-DESC-001 — VMSA64 stage-1 leaf RES0 bit 48 is accepted by the typed walk and hardware

- Reference crate revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- Catalog case: `descriptors.malformed-vmsa64-res0`
- Classification: crate/platform descriptor-validation discrepancy; assertion remains enabled

The VMSA64 stage-1 leaf layout classifies bit 48 as RES0. The isolated malformed-table case first
creates a valid typed page mapping, then changes only bit 48 through the explicit negative-test
surface and installs that caller-owned table. A read should return an exact stage-1 translation
fault. Instead, the typed walk continues to classify the descriptor as a leaf and FVP completes the
load with the mapped value. The neighboring reserved-type and cleared-RES1 identities return the
expected translation fault, so installation, exception capture, and fault matching are active.

All three identities restore their installation, invoke emergency restoration, and execute a fresh
successful mapping before returning their observation. In
`output/runs/ns-el2-00001784033337735088-55920`, reserved-type and RES1 passed, RES0 reported the
missing fault, and the later RES1 identity still ran. The RES0 case took twice the execution time
of the neighboring cases because it completed restoration, emergency restoration, and its fresh
mapping sentinel before returning the retained missing-fault result.

The reserved-type mutation is applied to the terminal L3 descriptor, exercising the malformed
final-level block/type encoding. VMSA64 uses the same `0b11` encoding for a page at the final level
and a table at non-final levels, so a distinct raw "final table" encoding does not exist; the typed
table-transition constructor's final-level rejection is covered separately by the exact descriptor
error cases.

- `output/runs/ns-el2-00001784022358626675-16850/`
- `output/runs/ns-el2-00001784022358626675-16850/results.log`
- `output/runs/ns-el2-00001784022358626675-16850/uart.log`
- `output/runs/ns-el2-00001784022358626675-16850/provenance.txt`
- `output/runs/ns-el2-00001784023411212722-20153/`
- `output/runs/ns-el2-00001784023411212722-20153/results.log`
- `output/runs/ns-el2-00001784023411212722-20153/uart.log`
- `output/runs/ns-el2-00001784023411212722-20153/provenance.txt`
- `output/runs/ns-el2-00001784024306696943-22170/`
- `output/runs/ns-el2-00001784024306696943-22170/results.log`
- `output/runs/ns-el2-00001784024306696943-22170/uart.log`
- `output/runs/ns-el2-00001784024306696943-22170/provenance.txt`
- `output/runs/ns-el2-00001784024392736885-22482/`
- `output/runs/ns-el2-00001784025762264141-29035/`
- `output/runs/ns-el2-00001784025762264141-29035/results.log`
- `output/runs/ns-el2-00001784025762264141-29035/uart.log`
- `output/runs/ns-el2-00001784025762264141-29035/provenance.txt`
- `output/runs/ns-el2-00001784025982274751-29332/`
- `output/runs/ns-el2-00001784025982274751-29332/results.log`
- `output/runs/ns-el2-00001784025982274751-29332/uart.log`
- `output/runs/ns-el2-00001784025982274751-29332/provenance.txt`
Independent installation recovery coverage is registered as `recovery.install-current`,
`recovery.install-lower`, and `recovery.install-combined-partial`. Each identity verifies the
exact injected failure, performs a clean retry and explicit restoration, and then installs a
fresh current translation to complete a mapped-access sentinel. The three-case FVP run passed in
`output/runs/ns-el2-00001784030934709486-45720`.

Lower-context recovery is split into `recovery.lower-entry`, `recovery.lower-action`, and
`recovery.lower-return`; all three passed with retry and a fresh mapping sentinel in
`output/runs/ns-el2-00001784031046523440-46091`. Secondary-PE recovery is independently covered
by `recovery.secondary-start`, `recovery.secondary-rendezvous`, `recovery.secondary-action`,
`recovery.secondary-timeout`, and `recovery.secondary-stop`. The five-case batch passed in
`output/runs/ns-el2-00001784031217718576-46964`, including rendezvous rollback and Drop-mediated
stop cleanup.

Invalidation, barrier, and explicit TLBI failure boundaries are registered separately as
`recovery.invalidation`, `recovery.barrier`, and `recovery.tlbi`. The invalidation and TLBI cases
confirm the old live mapping remains usable before retry; every case restores and completes a
fresh mapping sentinel. They passed together with all 24 earlier recovery identities in
`output/runs/ns-el2-00001784031296326099-47234` (27 passed, 0 failed).

Restoration ownership paths are isolated as `recovery.restore-explicit`,
`recovery.restore-drop`, and `recovery.restore-emergency`. The explicit case injects a restore
failure and verifies the consumed guard's Drop fallback; the emergency case deliberately forgets
the guard, invokes the same last-resort environment restoration used by the runner, and proves a
new translation can be installed in the same test. All three passed in
`output/runs/ns-el2-00001784031377717343-47534`.

Realm lifecycle recovery uses ten isolated `realm-rec.recovery-*` identities for delegation,
Realm creation, REC creation and entry, mapping, read-only and read-write mutation, unmapping,
destruction, and undelegation. Phase-specific harness injection replaced the former generic
firmware/cleanup ambiguity, and every identity retries through a fresh Realm session. The Realm
REC FVP batch passed 10/10 in
`output/runs/realm-stage2-00001784031509410995-47840`.

All recoverable failure identities now inspect the relevant post-failure state, retry, explicitly
restore or reclaim ownership, and install a fresh mapping (or fresh Realm session) before passing.
The full Normal recovery batch continued through an intentionally observed assertion failure and
ran every later identity in `output/runs/ns-el2-00001784031605461631-48147`; after tightening the
remaining cases, the sole scope-terminal arena exhaustion boundary passed independently in
`output/runs/ns-el2-00001784031640240012-48411`. Whole-arena exhaustion is not a recoverable
in-scope injection: it deliberately consumes the bump arena and is restored by the runner's
mandatory scope reset. Its page, contiguous, root, and table failure counterparts are recoverable
and do pass fresh mappings in the same test.

The Normal invalidation batch passed 7/7 in
`output/runs/ns-el2-00001784032187492066-52283`. It covers live leaf and table insertion,
removal/reclaim synchronization, local and inner-shareable invalidation observed across primary
and secondary PEs, and independent ASID roots with value switching and transactional reuse.
`recovery.mapper-remap` independently proves an injected failed remap preserves the old output and
a retry selects a distinct new output.

TLBI coverage now includes VA, IPA, VA-range, IPA-range, ASID, VMID, and all-entry operations.
Stage-2 wrong-stage operations, zero-page and unaligned ranges, plus wrong ASID/VMID identifiers
return exact `HarnessError::InvalidState`; the expanded stage-2 case passed in
`output/runs/ns-el2-00001784032264824822-52564`. `TlbiScope` is a closed two-variant typed API
(`Local` and `InnerShareable`), so an invalid scope cannot be constructed through the public
harness interface; both representable scopes are exercised.

`invalidation.vmid-isolation` now populates two independent stage-2 roots at the same IPA with
distinct outputs, installs and inspects them under VMIDs `0x15` and `0x2a`, restores both, and
reinstalls the first root/VMID pair to prove transactional reuse. It passed in
`output/runs/ns-el2-00001784032348976292-52845`.

`formats.d128-stage2-active` combines a 52-bit LPA2 stage-1 translation using 16 KiB tables with
a 52-bit D128 stage-2 translation using 4 KiB tables. It corroborates combined access, raw walk,
and semantic inspection before stage-2 protect/remap/unmap/fault/TLBI and reverse restoration; the
case passed in `output/runs/ns-el2-00001784032408400162-53129`.

Every active format leaf matrix now compares the complete typed offline `WalkInspection` and
semantic leaf decode with inspection of the installed tables before performing its access or AT
observation. These equalities include the descriptor raw value and width, normalized kind,
level/index path, next-table target, offset-adjusted output, and every decoded semantic field. The
bulk run retained at `output/runs/ns-el2-00001784033001474335-54749` passed all 94 access-backed
VMSA64, LPA2, and D128 stage-1/stage-2 cases. The 20 D128 AT identities independently reported the
already documented `AVMSA-FVP-001` discrepancy, and later identities continued to execute.

Repository quality checks pass: host and target `cargo fmt --check`, host clippy with
`-D warnings`, and the complete target workspace clippy with `-D warnings` inside the pinned Linux
build image. The target lint mounted `/Users/boden/Documents/aarch64-vmsa` read-only; no dependency
path remains in `target/external`. The 774-item API audit validator and `git diff --check` also pass.
