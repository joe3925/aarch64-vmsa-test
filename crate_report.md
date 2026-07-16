# `aarch64-vmsa` crate failure report

## AVMSA-ATTR-001 — MAIR encode/decode disagreement for non-allocating cacheable memory

- First confirmed: 2026-07-14T07:47:33Z
- Catalog case: `attributes.mair-normal-matrix`
- Profile: Normal EL2 (`ns-el2`)
- Command: `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa --filter attributes.mair-normal-matrix --keep`
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

The control comparison covers all four device types and the remaining normal-memory combinations. No live translation installation, platform register setup, or cleanup path participates in this offline round trip.

The result is classified as a crate failure because two directions of the same public codec disagree on a value accepted by the encoder. The tested checkout was mounted read-only and was not changed. `attributes.mair-normal-matrix` remains registered, exhaustive, and failing.

Retained evidence:

- `output/runs/ns-el2-00001784190368690663-85891/` (current isolated reproduction: expected zero failures, actual 56)

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

No FVP translation installation, platform register setup, or cleanup path is involved. The expected stride follows directly from the public four-stride encoding limit and the five-level NEG2-to-L3 distance; the returned error is produced before any harness-owned live state exists.

This is classified as a crate failure because the public `MaxSklTablePlan` name and the implementation’s descending-search structure both require selecting the maximum feasible plan, while an invalid first candidate aborts that search. The tested checkout was mounted read-only and was not changed. `mapper.max-skl-extended-root` remains registered and failing.

Retained evidence:

- `output/runs/ns-el2-00001784190399878456-86151/` (current isolated reproduction: expected stride four, actual error path encoded as zero)

## AVMSA-DESC-001 — VMSA64, LPA2, and D128 malformed leaf fields are accepted

- Reference crate revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- Tested content fingerprint: `fnv1a64:efe950d65438f158`
- Profile: Normal EL2 (`ns-el2`)
- Command: `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa --filter descriptors.malformed --keep`
- Catalog cases: `descriptors.malformed-vmsa64-res0`, `descriptors.malformed-lpa2-ds-res0`, `descriptors.malformed-lpa2-64k-res0`, `descriptors.malformed-d128-address`, and `descriptors.malformed-d128-res0`
- Public APIs/source area: `Mapper`, `TranslationWalk`, `DescriptorLayout::{kind,decode_leaf_fields}`, and the VMSA64/LPA2/D128 implementations under `descriptor/format/`
- Classification: confirmed crate descriptor-validation failure; every assertion remains enabled

The VMSA64 stage-1 leaf layout classifies bit 48 as RES0. The isolated malformed-table case first
creates a valid typed page mapping, changes only bit 48 through the explicit negative-test surface,
and installs that caller-owned table. The crate walk continues to classify the descriptor as a
leaf, and the independent hardware oracle completes the load with the mapped value instead of
returning a stage-1 translation fault. The neighboring reserved-type and cleared-RES1 cases do
return the expected translation fault, proving that installation, exception capture, and fault
matching are active.

Minimal reproduction: create a valid typed L3 mapping through the public mapper, mutate only the
layout-declared RES0 bit through the harness's explicit malformed-input surface, then invoke the
public typed walk and an independent guarded FVP load. The walk still returns a leaf and the load
completes instead of rejecting the descriptor.

The LPA2 DS case independently sets stage-1 leaf RES0 bit 59, while the 64 KiB non-DS case sets
RES0 bit 48. Both loads likewise complete with the mapped value. Their reserved-type and
cleared-RES1 neighbors fault and recover exactly.

D128 exposes the same crate-owned raw-validation gap through an offline oracle, not through an
installed malformed D128 table. With a root configured for 52 output-address bits, the public
mapper rejects newly requested outputs at or above bit 52, and the D128 layout declares bit 1
RES0. However, after mutating an existing raw leaf, `translate` accepts output-address bit 52 and
`inspect_walk` accepts RES0 bit 1. These are contradictions between the crate's own public
construction/root-width validation and its public raw walk. The control cases clear the required
valid bit or set illegal terminal SKL and are rejected. Every case restores the descriptor and a
fresh valid D128 installation succeeds afterward. Because malformed D128 hardware installation is
not used as the oracle, this entry does not claim an FVP observation for those two D128 failures.

The current full family run is
`output/runs/ns-el2-00001784190427877626-86399/`: eight cases pass and the five cases named above
fail. The three VMSA64/LPA2 failures contain independent hardware observations; the two D128
failures are independent contradictions between crate validation surfaces. The two destructive
LPA2 high-address control cases also terminated in their expected isolated boots at
`output/runs/ns-el2-00001784190451388919-86399/` and
`output/runs/ns-el2-00001784190474790436-86399/`.

The reserved-type mutation is applied to the terminal L3 descriptor, exercising the malformed
final-level block/type encoding. VMSA64 uses the same `0b11` encoding for a page at the final level
and a table at non-final levels, so a distinct raw "final table" encoding does not exist; the typed
table-transition constructor's final-level rejection is covered separately by the exact descriptor
error cases.
