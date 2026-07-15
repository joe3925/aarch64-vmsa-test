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
- `output/runs/ns-el2-00001784075534013536-69381/` (latest full Normal run; all twenty D128 AT assertions failed independently with physical address `0x8`)

## AVMSA-DESC-001 — VMSA64, LPA2, and D128 malformed leaf fields are accepted

- Reference crate revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- Catalog cases: `descriptors.malformed-vmsa64-res0`, `descriptors.malformed-lpa2-ds-res0`, and `descriptors.malformed-lpa2-64k-res0`
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

The LPA2 DS case independently sets stage-1 leaf RES0 bit 59, while the 64 KiB non-DS case sets
RES0 bit 48. Both loads likewise complete with the mapped value. Their reserved-type and
cleared-RES1 neighbors fault and recover exactly. The DS batch is retained at
`output/runs/ns-el2-00001784033606763186-56747`; the corrected 64 KiB batch is retained at
`output/runs/ns-el2-00001784073901891888-63693`.

D128 independently shows the same validation gap. Clearing the valid/RES1 bit and setting illegal
terminal SKL are rejected exactly, while setting configured-output address bit 52 or RES0 bit 1 is
accepted by the crate mapper. All four cases then restore the exact original descriptor, invoke
emergency restoration, install the restored lower-EL translation, and read the expected value
before returning their observation. The batch is retained at
`output/runs/ns-el2-00001784074608364376-65655` (2 passes, 2 missing-rejection failures).

The reserved-type mutation is applied to the terminal L3 descriptor, exercising the malformed
final-level block/type encoding. VMSA64 uses the same `0b11` encoding for a page at the final level
and a table at non-final levels, so a distinct raw "final table" encoding does not exist; the typed
table-transition constructor's final-level rejection is covered separately by the exact descriptor
error cases.

## AVMSA-FVP-002 — LPA2 high output-address probes terminate FVP before an architectural fault

- Reference crate revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- Catalog cases: `descriptors.malformed-lpa2-ds-address` and `descriptors.malformed-lpa2-64k-address`
- Classification: destructive FVP/platform boundary; assertions remain enabled in separate boots

Each address identity starts from a viable 52-bit LPA2 leaf and changes only an encoded high output
address bit so the access targets an unavailable physical region. Instead of reporting a guarded
Data Abort, FVP exits with status 1 before the protocol can emit `END`. The DS evidence is retained
at `output/runs/ns-el2-00001784058930721911-59699`; the corrected 64 KiB evidence is retained at
`output/runs/ns-el2-00001784073930329001-63966`. These two identities are marked destructive and
run in separate boots, so this platform-wide termination cannot suppress any other malformed case.
All non-address LPA2 malformed identities perform explicit restoration, emergency restoration,
and a valid sibling mapping in the same test before returning their observation.

For the two destructive LPA2 address probes, FVP terminates before target code can execute any
post-fault assertion. Their separate-boot isolation is therefore the platform-enforced emergency
recovery boundary; every following boot begins from restored architectural state and all remaining
malformed identities execute. No test treats the missing cleanup callback as a pass.
