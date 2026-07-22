# `aarch64-vmsa` crate failure report

This file contains only failures for which the observed disagreement is attributable to a public
`aarch64-vmsa` API. Untriaged failures are not recorded here.

## Current confirmation context

- Latest multi-profile campaign command:
  `cargo run --manifest-path host/Cargo.toml -- test all --crate /Users/boden/Documents/aarch64-vmsa`
- Latest NS-EL2 result: `passed=428 failed=4 skipped=0`
- Reference crate checkout used by this campaign:
  - HEAD: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
  - Dirty content fingerprint: `fnv1a64:efe950d65438f158`
- Advertised NS-EL2 capabilities: EL2, EL3, EL2&0, SEL2, stage 2, XNX, LPA2,
  D128, D128 stage 2, extended input and output addresses, 4/16/64 KiB granules,
  52-bit VA and PA; RME absent.
- The tested crate checkout is mounted read-only by the harness.
- That all-profile invocation executed NS EL2, Secure EL2, Realm EL2, and Realm stage 2 before
  exposing an unrelated Root EL3 payload compile error. After removing the stale unused Root
  declaration, a fresh Root EL3 invocation passed `26/26`.

The four latest NS-EL2 failures are exactly the four confirmed crate-failure cases documented
below. No unresolved failures remain from that campaign.

## AVMSA-ATTR-001 — MAIR encode/decode disagreement for non-allocating cacheable memory

- First confirmed: 2026-07-14T07:47:33Z
- Catalog case: `attributes.mair-normal-matrix`
- Profile: Normal EL2 (`ns-el2`)
- Isolated command:
  `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa --filter attributes.mair-normal-matrix --keep`
- Latest full-run result: `reason=wrong-value expected=0 actual=56`
- Public items under test: `Cacheability`, `CachePolicy`, `MemoryTransience`,
  `AllocationHints`, `MemoryAttributes`, `AttributeCodec::{resolve_leaf,decode_leaf}`,
  and `VmsaAttributeCodec`
- Source area: `attrs/resolve/memory.rs`, specifically normal-memory MAIR
  cacheability encoding and decoding
- Classification: confirmed crate failure

### Expected behavior

Every semantic memory attribute accepted by `resolve_leaf` must decode from the resulting raw
leaf and unchanged configuration to the same semantic value.

In particular, the encoder accepts cacheable `NonTransient` memory with
`AllocationHints::None`, producing nibble `0x8` for write-through and nibble `0xc` for
write-back.

### Actual behavior

The corresponding decoder rejects those encodings as
`AttrError::UnencodableMemoryAttribute`.

The exhaustive 15-by-15 inner/outer matrix executes 225 combinations and reports 56 round-trip
failures. The independent device-MAIR, MAIR-error, stage-2 combined-memory, stage-2 FWB,
D128 MAIR2, and LPA2 shareability cases pass in the same full run.

### Minimal reproduction

1. Construct `MemoryAttributes::Normal` with either inner or outer cacheability set to
   `Cacheability::Cacheable` using:
   - `CachePolicy::WriteThrough` or `CachePolicy::WriteBack`;
   - `MemoryTransience::NonTransient`;
   - `AllocationHints::None`.
2. Put the corresponding public MAIR encoding in a `LiveVmsaConfig` slot.
3. Call `VmsaAttributeCodec::resolve_leaf` for VMSA64,
   `NonSecureEl2Stage1`, 4 KiB, L3. It succeeds.
4. Pass the returned raw leaf and unchanged configuration to `decode_leaf`.
5. Observe `Err(AttrError::UnencodableMemoryAttribute)` instead of the original semantic value.

No live translation installation, platform register setup, exception handling, or cleanup path
participates in this offline round trip.

### Evidence

- 2026-07-21 full-profile confirmation:
  `attributes.mair-normal-matrix` failed with
  `reason=wrong-value expected=0 actual=56`.

The catalog case remains registered, exhaustive, and failing.

## AVMSA-MAPPER-001 — `MaxSklTablePlan` aborts before the maximum feasible stride

- First confirmed: 2026-07-14T08:05:00Z
- Catalog case: `mapper.max-skl-extended-root`
- Profile: Normal EL2 (`ns-el2`)
- Historical full command:
  `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa`
- Latest full-run result: `reason=wrong-value expected=4 actual=0`
- Public items under test: `MaxSklTablePlan`, `TablePlanProvider::plan_table`,
  `TablePlanContext`, `TablePlan`, `TableShape`, and `TableStrideCount`
- Source area: `mapper/plan.rs`, specifically the maximum-SKL candidate search
- Classification: confirmed crate failure

### Expected behavior

For a D128 4 KiB root at level NEG2 with an L3 target leaf, the planner must select the maximum
feasible encodable first transition.

The path distance is five levels. The public table-stride encoding permits at most four levels,
so the maximum feasible first child is L2 with stride count four, followed by the final step to
L3.

### Actual behavior

`plan_table` returns `AccessError::InvalidTableStrideCount { stride_count: 5 }` while evaluating
the initial five-level candidate and does not continue to the valid stride-four candidate.

The planner contains a descending candidate search, but construction of the first unencodable
`TableShape` propagates its error out of the function instead of rejecting that candidate and
continuing the search.

The catalog case collapses every unexpected result, including the stride-five error, to
`actual=0`; `actual=0` is not the raw error payload.

### Minimal reproduction

1. Construct `TablePlanContext::<Vmsa128, Granule4KiB>` with:
   - parent `TableShape::root(Level::NEG2)`;
   - target leaf `Level::L3`.
2. Construct `MaxSklTablePlan` with valid VMSA128 stage-1 table fields.
3. Invoke
   `TablePlanProvider<Vmsa128, NonSecureEl2Stage1, Granule4KiB>::plan_table`.
4. Observe `InvalidTableStrideCount { stride_count: 5 }`.
5. The expected result is a plan whose child level is L2 and whose stride count is four.

No live translation installation, FVP register programming, exception handling, or cleanup path
is involved.

### Evidence

- 2026-07-21 full-profile confirmation:
  `mapper.max-skl-extended-root` failed with
  `reason=wrong-value expected=4 actual=0`.

The catalog case remains registered and failing. Neighboring step-by-one, bounded-SKL, ordinary
maximum-SKL, D128 transition-matrix, and mapper execution cases pass.

## AVMSA-DESC-001 — D128 raw walk accepts an out-of-range output address and a RES0 bit

- First confirmed: 2026-07-14 test campaign
- Catalog cases:
  - `descriptors.malformed-d128-address`
  - `descriptors.malformed-d128-res0`
- Equivalent coverage aliases that reproduce the same public-API defect:
  - `coverage.faults.secure-d128-address`
  - `coverage.faults.secure-d128-res0`
  - `coverage.faults.realm-d128-address`
  - `coverage.faults.realm-d128-res0`
- Profiles: Normal EL2 (`ns-el2`), Secure EL2 (`secure-el2`), and Realm EL2 (`realm-el2`)
- Reproduction command:
  `host/target/release/vmsa-test test ns-el2 --crate /Users/boden/Documents/aarch64-vmsa --filter descriptors.malformed --keep`
- Latest full-run results:
  - `descriptors.malformed-d128-address`: `reason=missing-fault expected=1 actual=0`
  - `descriptors.malformed-d128-res0`: `reason=missing-fault expected=1 actual=0`
- Public APIs under test: `Mapper::translate`, typed walk inspection exposed through
  `Mapper::inspect_walk`, and the VMSA128 descriptor layout/decoder
- Source area: D128 descriptor classification, output-address decoding, and raw walk validation
  under `descriptor/format/`
- Classification: confirmed crate failure

### Expected behavior

A public raw walk must reject a terminal D128 descriptor that contradicts the same geometry and
layout constraints enforced during typed construction.

For a root configured with 52 output-address bits:

- a terminal descriptor with output-address bit 52 set is outside the configured output width and
  must not be returned as a valid translation;
- a terminal descriptor with layout-declared RES0 bit 1 set must be classified as invalid.

### Actual behavior

The harness first creates a valid D128 L3 mapping through the public mapper and obtains the
terminal raw descriptor through public typed inspection. It then uses the harness's explicitly
isolated malformed-input surface to mutate only the terminal descriptor.

For `descriptors.malformed-d128-address`, it sets low-word bit 52. A subsequent public
`mapper.translate(ADDRESS)` does not return the expected invalid-state rejection.

For `descriptors.malformed-d128-res0`, it sets low-word bit 1. A subsequent public
`mapper.inspect_walk(ADDRESS)` does not classify the terminal L3 step as invalid.

After each observation, the harness restores the original descriptor, verifies that public typed
inspection again returns a valid leaf, installs the restored table, and successfully reads the
mapped sentinel value.

### Minimal reproduction

1. Create a D128 4 KiB stage-1 root with 52-bit input and output widths, starting at NEG1.
2. Map an L3 page through the public mapper.
3. Inspect the terminal descriptor through the public walk and retain its raw value.
4. Mutate only one field through an isolated malformed-table escape hatch:
   - address case: set low-word bit 52;
   - RES0 case: set low-word bit 1.
5. Invoke the public crate observation:
   - address case: `mapper.translate(ADDRESS)`;
   - RES0 case: `mapper.inspect_walk(ADDRESS)`.
6. Observe acceptance instead of rejection.
7. Restore the original raw descriptor and verify a fresh live D128 access succeeds.

These two cases do not install the malformed D128 descriptor as their oracle and do not claim an
FVP observation of malformed D128 behavior. The failure is the contradiction between public
crate construction/geometry validation and public crate raw-walk validation.

### Controls

The following neighboring cases pass:

- `descriptors.malformed-d128-valid-res1`
- `descriptors.malformed-d128-skl`
- restoration of the original descriptor;
- `descriptors.d128-live`;
- D128 output-width acceptance and rejection matrices;
- D128 root-address and root-level boundary matrices.

### Evidence

- 2026-07-21 all-profile confirmation:
  - Normal address and RES0 cases failed with `reason=missing-fault expected=1 actual=0`.
  - Secure address and RES0 aliases failed with `reason=missing-fault expected=1 actual=0`.
  - Realm address and RES0 aliases failed with `reason=missing-fault expected=1 actual=0`.

Both underlying assertions remain registered and failing in every applicable profile.
