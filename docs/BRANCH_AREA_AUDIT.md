# `aarch64-vmsa` behavioral branch-area audit

This audit is deliberately stricter than the public-API inventory and the
coverage definition in `IMPLEMENTATION_PLAN.md`.  It expands generic public
implementations into coarse behavioral branch areas, including regime × stage
× format × granule combinations and ordering-sensitive live-table behavior.
It is not a line-coverage report: one checkbox represents a coherent family of
source branches with the same architectural observation.

Audit target:

- checkout: `/Users/boden/Documents/aarch64-vmsa`
- revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
- content fingerprint: `fnv1a64:efe950d65438f158`
- crate source: 10,196 Rust lines in 51 files
- coarse static decision sites inventoried: 671
- test catalog: 491 independently named cases

## Evidence rule

A checked box means every material alternative in that coarse area has a
concrete route at the stated evidence tier. A confirmed crate failure still
counts as coverage when the assertion remains enabled and isolated; it does
not count as correct behavior. Harness failures never count as coverage and
must be fixed and regression-tested. An unchecked box means missing, partial, only
representative, or unavailable evidence.  Generic evidence from another
regime is never inherited across a hardware-sensitive regime boundary.

Evidence tiers:

- **LIVE** — crate construction/decoding is tied to an installed table and an
  FVP access, fault, AT/PAR observation, hardware update, or stale-translation
  exclusion, followed by restoration.
- **INSPECT** — exact crate construction/decoding/walk inspection, but no
  independent hardware observation for every branch in the area.
- **VALUE** — bounded pure-value behavior for a branch with no architectural
  observation.
- **MALFORMED** — isolated negative input plus recovery; a model termination is
  valid evidence only when isolated as a destructive boot.
- **CFG** — compile-target branch.  It is checked only if that configuration
  was actually built and exercised.

`case:name` denotes one exact catalog identity.  `prefix:name` denotes every
registered identity beginning with that prefix.  These references are checked
by `tools/verify_branch_area_audit.py`.

## 1. Audit integrity and feature decoding

- [x] **BA-FEAT-001 — exact checkout and read-only provenance.** Evidence: **LIVE**, retained full-run provenance.
- [x] **BA-FEAT-002 — all crate source modules included in the branch-area inventory.** Evidence: **INSPECT**, `branch-area-source-inventory.csv` plus verifier.
- [x] **BA-FEAT-003 — every evidence route named below resolves to a current catalog identity.** Evidence: **INSPECT**, audit verifier.
- [x] **BA-FEAT-004 — live ID-register snapshot agrees with `decode_features` and adapter capabilities in every profile.** Evidence: **LIVE**, `case:features.live-snapshot-agreement`.
- [x] **BA-FEAT-005 — implemented/not-implemented feature states observed across Normal, Secure, Realm, REC, and Root profiles.** Evidence: **LIVE**, `case:features.live-snapshot-agreement`.
- [x] **BA-FEAT-006 — derived security-state membership for RME present/absent and EL3/SEL2 combinations represented by the selected profiles.** Evidence: **LIVE**, `case:features.security-state-membership`, `case:features.root-security-state-membership`.
- [x] **BA-FEAT-007 — feature requirement union and positive verification.** Evidence: **VALUE** plus live snapshot, `case:features.requirement-unions`.
- [x] **BA-FEAT-008 — regime validation success and capability-backed rejection for every public stage-1/stage-2 regime.** Evidence: **LIVE**, `case:features.regime-validation`.
- [x] **BA-FEAT-009 — format requirement union success/rejection for VMSA64, LPA2, and D128 over all three granules in each owning profile.** Evidence: **LIVE**, `case:features.regime-format-validation`.
- [x] **BA-FEAT-010 — all reserved/unknown raw encodings for binary features, EL2/EL3, RME, VARange, and PARange.** Evidence: **VALUE**, `prefix:features.decode-binary-`, `prefix:features.decode-exception-level-`, `prefix:features.decode-rme-`, `prefix:features.decode-varange-`, `prefix:features.decode-parange-`.
- [x] **BA-FEAT-011 — every `decode_lpa2` primary/secondary granule encoding and unknown-priority arm.** Evidence: **VALUE**, `prefix:features.decode-lpa2-`.
- [x] **BA-FEAT-012 — every `merge_derived` ordering of implemented, unknown, and absent primary/derived states.** Evidence: **VALUE**, `case:features.decode-derived-merge-orderings`.

## 2. Address, granule, geometry, and raw bounded values

- [x] **BA-GEO-001 — `Level` valid range, predecessor/successor, ordering, and before/after relations.** Evidence: **VALUE**, `case:geometry.value-boundaries`.
- [x] **BA-GEO-002 — level distance success and root-before-level rejection.** Evidence: **VALUE**, `case:geometry.path-boundaries`.
- [x] **BA-GEO-003 — 4/16/64 KiB granule kind, page shift, alignment mask, and page alignment.** Evidence: **VALUE** plus live mappings, `case:geometry.value-boundaries`, `prefix:mapper.live-parts-s1-`.
- [x] **BA-GEO-004 — `align_up` already-aligned, rounded, and overflow outcomes.** Evidence: **VALUE**, `case:geometry.value-boundaries`.
- [x] **BA-GEO-005 — valid and invalid table stride counts, encoded maximum, and geometry overflow.** Evidence: **VALUE**, `case:geometry.table-shape-transition-matrix`.
- [x] **BA-GEO-006 — checked entry counts, index masks, level shifts, covered size, and index extraction.** Evidence: **VALUE/INSPECT**, `case:geometry.value-boundaries`, `case:geometry.path-boundaries`.
- [x] **BA-GEO-007 — table-path length, stride, capacity, and unavailable-level branches.** Evidence: **VALUE**, `case:geometry.path-capacity-errors`, `case:geometry.cursor-next-table-errors`.
- [x] **BA-GEO-008 — input/output page alignment success and exact rejection.** Evidence: **LIVE/INSPECT**, `case:access.widths-and-alignment`, `case:mapper.unaligned-leaf-input`, `case:mapper.unaligned-leaf-output`.
- [x] **BA-GEO-009 — bounded `FourBit`, `ThreeBit`, `TenBit`, AP, XN, dirty, and shareability raw wrappers.** Evidence: **VALUE**, `case:descriptors.raw-field-bounds`, `case:descriptors.exact-errors`.
- [x] **BA-GEO-010 — software metadata full 4-bit and 10-bit spaces.** Evidence: **INSPECT**, `case:metadata.vmsa64-4bit-matrix`, `case:metadata.d128-stage1-10bit-matrix`, `case:metadata.d128-stage2-10bit-matrix`.

## 3. Memory-attribute and shareability branches

- [x] **BA-MEM-001 — MAIR slot search hit/miss in MAIR.** Evidence: **INSPECT**, `case:attributes.mair-device-matrix`, `case:attributes.mair-normal-matrix`, `case:attributes.mair-error-matrix`.
- [x] **BA-MEM-002 — MAIR2 present/absent, slot hit/miss, and extended index decoding.** Evidence: **INSPECT**, `case:attributes.d128-mair2-matrix`, `case:attributes.mair-error-matrix`.
- [x] **BA-MEM-003 — all four device memory types encode/decode.** Evidence: **INSPECT**, `case:attributes.mair-device-matrix`.
- [x] **BA-MEM-004 — normal-memory inner/outer cacheability cross-product, transient/policy/allocation branches.** Evidence: **INSPECT**, `case:attributes.mair-normal-matrix`; the 56 disagreement outcomes remain enabled under AVMSA-ATTR-001.
- [x] **BA-MEM-005 — illegal device and normal MAIR encodings.** Evidence: **INSPECT**, `case:attributes.mair-error-matrix`.
- [x] **BA-MEM-006 — stage-2 direct memory type encode/decode.** Evidence: **INSPECT/LIVE**, `case:attributes.stage2-combined-matrix`, `case:permissions.stage2-direct-semantic-mapper`.
- [x] **BA-MEM-007 — stage-2 FWB disabled/enabled and tagged/untagged combinations.** Evidence: **INSPECT**, `case:attributes.stage2-fwb-matrix`, `case:attributes.stage2-fwb-semantic-mapper`.
- [x] **BA-MEM-008 — effective shareability equal/mismatch branches.** Evidence: **INSPECT**, `case:attributes.lpa2-shareability-matrix`.
- [x] **BA-MEM-009 — LPA2 4/16 KiB shareability elision versus 64 KiB explicit shareability.** Evidence: **INSPECT/LIVE**, `case:attributes.lpa2-shareability-matrix`, `prefix:formats.lpa2-`.

## 4. PAS encoding and security-state branches

- [x] **BA-PAS-001 — fixed Non-secure stage-1 PAS encode/decode and live access.** Evidence: **LIVE**, `case:pas.fixed-non-secure-stage1-semantic-access`.
- [x] **BA-PAS-002 — fixed Realm-IPA stage-1 PAS encode/decode and live REC access.** Evidence: **LIVE**, `case:pas.fixed-realm-ipa-stage1-semantic-access`.
- [x] **BA-PAS-003 — Secure selectable stage-1 leaf/table Secure and Non-secure encodings.** Evidence: **LIVE**, `case:pas.secure-stage1-secure-access`, `case:pas.secure-stage1-non-secure-fault`.
- [x] **BA-PAS-004 — Realm-or-Non-secure stage-1 leaf/table encodings.** Evidence: **LIVE**, `case:pas.realm-stage1-realm-access`, `case:pas.realm-stage1-non-secure-fault`.
- [x] **BA-PAS-005 — Root Secure, Non-secure, Root, and Realm leaf/table encodings.** Evidence: **LIVE**, `prefix:pas.root-stage1-`.
- [x] **BA-PAS-006 — stage-2 fixed/configured Non-secure output PAS.** Evidence: **LIVE**, `case:pas.fixed-non-secure-stage2-semantic-access`.
- [x] **BA-PAS-007 — Secure-IPA configured Secure/Non-secure match and mismatch.** Evidence: **LIVE/INSPECT**, `case:pas.secure-ipa-stage2-configured`, `case:pas.secure-ipa-stage2-mismatch-rejection`.
- [x] **BA-PAS-008 — Non-secure-IPA configured Secure/Non-secure match and mismatch.** Evidence: **LIVE/INSPECT**, `case:pas.non-secure-ipa-stage2-configured`, `case:pas.non-secure-ipa-stage2-mismatch-rejection`.
- [x] **BA-PAS-009 — Realm stage-2 Realm and Non-secure output branches.** Evidence: **LIVE**, `case:pas.realm-stage2-realm-leaf`, `case:pas.realm-stage2-non-secure-leaf`.
- [x] **BA-PAS-010 — invalid fixed output PAS, invalid NSE/NS combination, and alias/PAS conflicts.** Evidence: **INSPECT/MALFORMED**, `case:attributes.invalid-fixed-output-pas`, `case:attributes.invalid-d128-alias`, `prefix:attributes.alias-`.
- [x] **BA-PAS-011 — delegated Realm page access from Root and exact GPC failures from other PAS selections.** Evidence: **LIVE**, `case:pas.root-delegated-realm-access`, `prefix:pas.root-delegated-realm-`.
- [ ] **BA-PAS-012 — live D128 PAS encoding in Secure EL2.** The existing current-regime transition failure is harness-owned and does not count as hardware evidence.
- [ ] **BA-PAS-013 — live D128 PAS encoding in Realm EL2 stage 1 and stage 2.** Installed inspection exists, but the hardware observation remains blocked by harness transition/access failures.
- [ ] **BA-PAS-014 — live LPA2 PAS encoding in Secure and Realm profiles.** Offline round trips exist; the harness-owned current-regime transitions must complete before this area closes.

## 5. Permission-resolution branches

- [x] **BA-PERM-001 — single-privilege stage-1 leaf AP None/RO/RW and execute/XN encode/decode.** Evidence: **INSPECT/LIVE**, `case:permissions.stage1-single-matrix`, `prefix:permissions.stage1-single-`.
- [x] **BA-PERM-002 — two-privilege leaf AP valid combinations and unencodable combinations.** Evidence: **INSPECT/LIVE**, `case:permissions.stage1-two-privilege-matrix`, `prefix:permissions.stage1-two-`.
- [x] **BA-PERM-003 — single-privilege and two-privilege table permission-limit branches.** Evidence: **INSPECT**, `case:permissions.stage1-single-matrix`, `case:permissions.stage1-two-privilege-matrix`.
- [x] **BA-PERM-004 — stage-2 direct AP None/RO/RW and direct XN branches.** Evidence: **INSPECT/LIVE**, `case:permissions.stage2-direct-xnx-matrix`, `prefix:permissions.stage2-`.
- [x] **BA-PERM-005 — stage-2 XNX privileged/unprivileged execute cross-product.** Evidence: **INSPECT/LIVE**, `case:permissions.stage2-direct-xnx-matrix`, `prefix:permissions.stage2-xnx-`.
- [x] **BA-PERM-006 — D128 stage-1 base-permission decode including GCS and WXN effects.** Evidence: **INSPECT**, `case:permissions.d128-stage1-indirection-matrix`.
- [x] **BA-PERM-007 — D128 stage-1 overlay applied/bypassed and MRO/execute/write combinations.** Evidence: **INSPECT**, `case:permissions.d128-stage1-indirection-matrix`.
- [x] **BA-PERM-008 — D128 stage-1 missing register, missing combination, duplicate, and conflict errors.** Evidence: **INSPECT**, `case:permissions.d128-stage1-indirection-unavailable`, `case:permissions.d128-stage1-missing-combination`, `case:permissions.d128-stage1-duplicate-selection`, `case:permissions.d128-stage1-conflicting-permissions`.
- [x] **BA-PERM-009 — D128 stage-2 base-permission decode.** Evidence: **INSPECT**, `case:permissions.d128-stage2-base-matrix`.
- [x] **BA-PERM-010 — D128 stage-2 overlay and MRO combination decode.** Evidence: **INSPECT**, `case:permissions.d128-stage2-overlay-matrix`.
- [x] **BA-PERM-011 — D128 stage-2 missing register, missing combination, and duplicate errors.** Evidence: **INSPECT**, `case:permissions.d128-stage2-indirection-unavailable`, `case:permissions.d128-stage2-missing-combination`, `case:permissions.d128-stage2-duplicate-selection`.
- [x] **BA-PERM-012 — hardware AF update enabled/disabled for VMSA64 and D128 stage 1.** Evidence: **LIVE**, `prefix:permissions.hardware-vmsa64-af-`, `prefix:permissions.hardware-d128-af-`.
- [x] **BA-PERM-013 — hardware dirty update enabled/disabled for VMSA64 and D128 stage 1.** Evidence: **LIVE**, `prefix:permissions.hardware-vmsa64-dirty-`, `prefix:permissions.hardware-d128-dirty-`.
- [x] **BA-PERM-014 — hardware AF and dirty update enabled/disabled for D128 stage 2.** Evidence: **LIVE**, `prefix:permissions.hardware-d128-stage2-`.
- [ ] **BA-PERM-015 — every D128 stage-1 indirection branch live, rather than typed inspection plus representative hardware cases.** Current exhaustive matrices are offline; live tests use a subset.
- [ ] **BA-PERM-016 — every D128 stage-2 indirection branch live.** Current exhaustive matrices are offline; live tests use a subset.
- [ ] **BA-PERM-017 — permission-indirection live behavior in Root D128.** `case:permissions.d128-indirection` uses an offline mapper; Root live D128 descriptor access is raw-field based.
- [ ] **BA-PERM-018 — D128 permission-indirection live behavior in Realm/Secure regimes.** The registered cases currently stop in harness-owned transition/access paths and have not produced an independent hardware result.

## 6. Semantic codec live cross-product

These boxes are intentionally per regime family.  A format test using raw
fields does not prove semantic attribute encoding/decoding in that regime.

- [x] **BA-CODEC-001 — Normal current EL2 stage 1, VMSA64, all 4/16/64 KiB legal leaf levels.** Evidence: **LIVE**, `prefix:formats.vmsa64-`.
- [x] **BA-CODEC-002 — Normal current EL2 stage 1, LPA2, all 4/16/64 KiB legal leaf levels.** Evidence: **LIVE**, `prefix:formats.lpa2-`.
- [x] **BA-CODEC-003 — Normal lower EL1 stage 1, D128, all 4/16/64 KiB legal leaf levels.** Evidence: **LIVE**, `prefix:formats.d128-`.
- [x] **BA-CODEC-004 — Normal EL2 stage 2 direct permissions, VMSA64/LPA2/D128, all legal granule/leaf combinations.** Evidence: **LIVE**, `prefix:formats.stage2-vmsa64-`, `prefix:formats.stage2-lpa2-`, `prefix:formats.stage2-d128-`.
- [x] **BA-CODEC-005 — Normal EL2 stage 2 XNX permissions, hardware-distinguishable execute branches.** Evidence: **LIVE**, `prefix:permissions.stage2-xnx-`.
- [x] **BA-CODEC-006 — Normal lower EL1 VMSA64 semantic codec across every granule/level.** Evidence: **LIVE**, `prefix:codec.normal-lower-vmsa64-` (all seven legal 4/16/64 KiB VMSA64 leaf levels; offline/live semantic equality plus lower-EL access).
- [x] **BA-CODEC-007 — Normal EL2&0 VMSA64 semantic codec across every granule/level.** Evidence: **LIVE**, `prefix:codec.normal-el2-el0-vmsa64-` (all seven legal leaf combinations with offline/live semantic equality and EL0-under-EL2 reads).
- [ ] **BA-CODEC-008 — Normal current EL2 D128 stage-1 semantic codec.** Semantic construction passes offline, but the harness-owned current-regime switch does not complete.
- [x] **BA-CODEC-009 — Secure current EL2 VMSA64 semantic PAS leaf/table encode/decode with hardware observation.** Evidence: **LIVE**, `case:pas.secure-stage1-secure-access`, `case:pas.secure-stage1-non-secure-fault`.
- [x] **BA-CODEC-010 — Secure lower EL1 VMSA64 semantic codec across permissions, controls, and all granules/levels.** Evidence: **LIVE**, `prefix:codec.secure-lower-vmsa64-`; all seven legal granule/level cases pass after fixing the harness TG1 encoding, 16 KiB model configuration, and physical cleanup stack (`secure-el2-00001784190242608113-85420`).
- [ ] **BA-CODEC-011 — Secure EL2&0 VMSA64 semantic codec.** Installed inspection completes, but the harness-owned EL0 conduit does not return.
- [ ] **BA-CODEC-012 — Secure Secure-IPA stage-2 VMSA64 codec for both direct and XNX permission models.** Hardware observations remain blocked by the Secure combined-access harness path.
- [ ] **BA-CODEC-013 — Secure Non-secure-IPA stage-2 VMSA64 codec for both direct and XNX permission models.** PAS inspection exists, but the full direct/XNX hardware matrix remains blocked by the harness path.
- [ ] **BA-CODEC-014 — Secure LPA2/D128 semantic codecs.** Both current-regime installations remain unresolved harness failures.
- [x] **BA-CODEC-015 — Realm current EL2 VMSA64 semantic PAS leaf/table encode/decode with hardware observation.** Evidence: **LIVE**, `case:pas.realm-stage1-realm-access`, `case:pas.realm-stage1-non-secure-fault`.
- [x] **BA-CODEC-016 — Realm lower EL1 VMSA64 semantic codec across permissions, controls, and all granules/levels.** Evidence: **LIVE**, `prefix:codec.realm-lower-vmsa64-`; all seven cases passed in `output/runs/realm-el2-00001784190700327548-87015`.
- [ ] **BA-CODEC-017 — Realm EL2&0 VMSA64 semantic codec.** Installed inspection completes, but the harness-owned EL0 conduit does not return.
- [x] **BA-CODEC-018 — Realm EL2 stage-2 VMSA64 PAS branches with live access/fault.** Evidence: **LIVE**, `case:pas.realm-stage2-realm-leaf`, `case:pas.realm-stage2-non-secure-leaf`.
- [ ] **BA-CODEC-019 — Realm EL2 stage-2 VMSA64 full memory/permission/control decoding for both permission models.** Unprivileged XNX observations still depend on a non-returning harness conduit.
- [x] **BA-CODEC-020 — Realm EL2 stage-2 LPA2 semantic decoding.** `case:codec.realm-stage2-lpa2-semantic` compares offline and installed semantic decoding and completes a combined lower-EL hardware read.
- [ ] **BA-CODEC-021 — Realm EL2 stage-2 D128 semantic decoding.** Installed decoding completes, but the harness-owned combined hardware access has not returned.
- [x] **BA-CODEC-023 — Root EL3 VMSA64 semantic PAS encoding for all four output spaces.** Evidence: **LIVE**, `prefix:pas.root-stage1-`.
- [ ] **BA-CODEC-024 — Root EL3 D128 semantic codec live.** D128 semantic permission/PAS construction is inspected offline; live Root D128 uses raw fields.
- [x] **BA-CODEC-025 — Root EL3 LPA2 semantic codec live.** Evidence: **LIVE**, `case:codec.root-lpa2-stage1-semantic`; the sandboxed EL3 geometry switch, Root NSE runtime mappings, semantic inspection, hardware read, and restoration passed in `output/runs/root-el3-00001784192886237362-92769`.

## 7. Descriptor layout, kind, address, and atomic-access branches

- [x] **BA-DESC-001 — VMSA64 stage-1 invalid/table/block/page kinds at every legal level and granule.** Evidence: **LIVE/MALFORMED**, `prefix:formats.vmsa64-`, `prefix:descriptors.malformed-vmsa64-`.
- [x] **BA-DESC-002 — VMSA64 stage-2 invalid/table/block/page kinds at every legal level and granule.** Evidence: **LIVE**, `prefix:formats.stage2-vmsa64-`.
- [x] **BA-DESC-003 — LPA2 stage-1 DS and non-DS address packing/unpacking for 4/16/64 KiB.** Evidence: **LIVE/MALFORMED**, `prefix:formats.lpa2-`, `prefix:descriptors.malformed-lpa2-`.
- [x] **BA-DESC-004 — LPA2 stage-2 DS and non-DS address packing/unpacking for 4/16/64 KiB.** Evidence: **LIVE**, `prefix:formats.stage2-lpa2-`.
- [x] **BA-DESC-005 — D128 stage-1 output/table address low/high halves and all legal leaf levels.** Evidence: **LIVE**, `prefix:formats.d128-`.
- [x] **BA-DESC-006 — D128 stage-2 output/table address low/high halves and all legal leaf levels.** Evidence: **LIVE**, `prefix:formats.stage2-d128-`.
- [x] **BA-DESC-007 — D128 valid-bit, SKL validity, final-level table, RES0, and RES1 checks.** Evidence: **INSPECT/MALFORMED**, `case:descriptors.exact-errors`, `prefix:descriptors.malformed-d128-`; accepted malformed branches remain under AVMSA-DESC-001.
- [x] **BA-DESC-008 — VMSA64/LPA2 reserved-type, RES0, and RES1 checks.** Evidence: **MALFORMED**, `prefix:descriptors.malformed-vmsa64-`, `prefix:descriptors.malformed-lpa2-`.
- [x] **BA-DESC-009 — D128 final-level BBM-NT and table NT/SKL0 rejection branches for both stages.** Evidence: **INSPECT**, `case:descriptors.d128-s1-final-bbm-nt`, `case:descriptors.d128-s2-final-bbm-nt`, `case:descriptors.d128-s1-table-nt-skl0`, `case:descriptors.d128-s2-table-nt-skl0`.
- [x] **BA-DESC-010 — target-selected D128 descriptor Acquire-load and Release-store code paths execute on live tables.** Evidence: **LIVE**, `prefix:mapper.live-parts-s1-d128-`, `prefix:mapper.live-parts-s2-d128-`, `prefix:formats.d128-`, `prefix:formats.stage2-d128-`.
- [ ] **BA-DESC-013 — all feasible D128 skipped-level/SKL transitions installed live.** The transition matrix is exhaustive offline, while live tests cover representative mapper-selected paths. Partial: `case:mapper.d128-skl-transition-matrix`, `prefix:mapper.live-parts-s1-d128-`, `prefix:mapper.live-parts-s2-d128-`.

## 8. Table access, recursive access, and walker branches

- [x] **BA-TABLE-001 — root table accessors and validated root construction.** Evidence: **INSPECT**, `prefix:mapper.offline-parts-`, `prefix:mapper.live-parts-`.
- [x] **BA-TABLE-002 — immutable/mutable table entry in-range and out-of-range access.** Evidence: **INSPECT**, `case:tables.translation-table-read-write`, `case:walk.error-entry-index`.
- [x] **BA-TABLE-003 — table allocation layout success, stride-zero, encoded-overflow, and layout-overflow branches.** Evidence: **VALUE**, `case:geometry.table-shape-transition-matrix`, `case:geometry.path-capacity-errors`.
- [x] **BA-TABLE-004 — `OffsetTableAccess` valid translation, arithmetic overflow, and null mapping.** Evidence: **LIVE/INSPECT**, `prefix:mapper.live-parts-`, `case:walk.error-access`, `case:tables.recursive-error-null-mapping`.
- [x] **BA-TABLE-005 — recursive access valid root recursion and table mapping.** Evidence: **LIVE**, `case:tables.recursive-access`.
- [x] **BA-TABLE-006 — recursive index, base, level, path, overflow, and null mapping errors.** Evidence: **INSPECT**, `prefix:tables.recursive-error-`.
- [x] **BA-WALK-001 — walker invalid, table, block, and page outcomes.** Evidence: **INSPECT/LIVE**, `case:walk.invalid-agreement`, `case:walk.block-agreement`, `case:walk.table-page-agreement`.
- [x] **BA-WALK-002 — cursor construction and next-table success/rejection.** Evidence: **INSPECT**, `case:walk.cursor-boundaries`, `case:geometry.cursor-next-table-errors`.
- [x] **BA-WALK-003 — access, access-location, cursor, table-address, entry-index, final-table, and output-overflow errors.** Evidence: **INSPECT**, `prefix:walk.error-`.
- [x] **BA-WALK-004 — translated output with nonzero offset and exact covered base/size.** Evidence: **LIVE**, `prefix:formats.vmsa64-`, `prefix:formats.lpa2-`, `prefix:formats.d128-`.

## 9. Mapper planning, operations, rollback, and reclaim

- [x] **BA-MAP-001 — mapper root level/address width/output width/alignment validation success and exact errors.** Evidence: **INSPECT**, `prefix:mapper.vmsa64-`, `prefix:mapper.lpa2-`, `prefix:mapper.d128-`, `case:mapper.unaligned-root-address`, `case:mapper.root-address-out-of-range`.
- [x] **BA-MAP-002 — step-by-one, bounded-SKL, maximum-SKL, no-plan, and allocation-bound planner paths.** Evidence: **INSPECT**, `case:mapper.step-by-one-plan`, `case:mapper.bounded-skl-plan`, `case:mapper.maximum-skl-plan`, `case:mapper.bounded-skl-no-plan`, `case:mapper.max-skl-extended-root`.
- [x] **BA-MAP-003 — page/block mapping outcomes and terminal table-growth boundary.** Evidence: **LIVE/INSPECT**, `case:mapper.exact-block-outcome`, `case:mapper.exact-page-outcome`, `case:mapper.block-page-boundary`, `case:mapper.terminal-table-growth-boundary`.
- [x] **BA-MAP-004 — maximum/one-past input and output, arithmetic overflow, and unaligned leaf inputs/outputs.** Evidence: **INSPECT**, `prefix:mapper.maximum-`, `prefix:mapper.one-past-`, `case:mapper.input-range-arithmetic-overflow`, `case:mapper.output-range-arithmetic-overflow`, `case:mapper.unaligned-leaf-input`, `case:mapper.unaligned-leaf-output`.
- [x] **BA-MAP-005 — leaf below root, past final, already-mapped leaf/table, and not-mapped operation branches.** Evidence: **INSPECT**, `case:mapper.leaf-level-below-root`, `case:mapper.leaf-level-past-final`, `case:mapper.already-mapped-leaf`, `case:mapper.already-mapped-table`, `prefix:mapper.not-mapped-`.
- [x] **BA-MAP-006 — map-range zero/single/multi mappings and invalid length/alignment/range-end branches.** Evidence: **LIVE/INSPECT**, `case:mapper.live-range`, `prefix:mapper.zero-range-`, `prefix:mapper.single-range-`, `case:mapper.invalid-range-length`, `case:mapper.unaligned-range-input`, `case:mapper.unaligned-range-output`, `case:mapper.input-range-end-out-of-range`.
- [x] **BA-MAP-007 — map-range partial-prefix postcondition after provider failure.** Evidence: **INSPECT**, `case:mapper.range-partial-prefix-postcondition`, `case:recovery.mapper-range`.
- [x] **BA-MAP-008 — unmap exact leaf base and non-leaf-base rejection.** Evidence: **INSPECT/LIVE**, `case:mapper.non-leaf-base-unmap`, `case:invalidation.translation-cycle`.
- [x] **BA-MAP-009 — recursive reclaim child-empty/nonempty, sibling preservation, root-empty, and frame-free failure.** Evidence: **LIVE/INSPECT**, `case:mapper.reclaim-sibling-lifecycle`, `case:mapper.live-reclaim-outcome`, `case:mapper.live-reclaim-post-fault`, `case:mapper.frame-free-provider-error`.
- [x] **BA-MAP-010 — access-read, descriptor-write, frame-allocate, and frame-free generic provider errors.** Evidence: **INSPECT**, `case:mapper.table-access-provider-error`, `case:mapper.descriptor-write-provider-error`, `case:mapper.frame-allocate-provider-error`, `case:mapper.frame-free-provider-error`.
- [x] **BA-MAP-011 — semantic mapper attribute error versus mapper error branches.** Evidence: **INSPECT**, `case:attributes.missing-memory-config`, `case:mapper.frame-provider-error`.
- [x] **BA-MAP-012 — map/protect/remap/unmap/reclaim injected failure, retry, restoration, and sentinel branches.** Evidence: **LIVE**, `prefix:recovery.mapper-`.
- [ ] **BA-MAP-013 — every planner family installed live for every format/granule/stage combination.** Planner result branches are exhaustive offline; only representative planner-backed mappings are live.

## 10. Live invalidation, break-before-make, and ordering

- [x] **BA-ORDER-001 — leaf insertion/removal callback and synchronization sequence.** Evidence: **INSPECT**, `case:mapper.break-before-make-ordering`.
- [x] **BA-ORDER-002 — table insertion/removal/reclaim callback branches.** Evidence: **INSPECT/LIVE**, `case:mapper.live-reclaim-outcome`, `case:mapper.live-reclaim-post-fault`.
- [x] **BA-ORDER-003 — live VMSA64 stage-1 mapping/protect/unmap/reclaim excludes stale translations.** Evidence: **LIVE**, `case:invalidation.translation-cycle`.
- [x] **BA-ORDER-004 — live VMSA64 stage-2 mapping/protect/unmap excludes stale translations.** Evidence: **LIVE**, `case:invalidation.stage2-translation-cycle`.
- [x] **BA-ORDER-005 — failed remap retains the old live mapping and successful retry works.** Evidence: **LIVE**, `case:recovery.mapper-remap`.
- [x] **BA-ORDER-006 — ASID and VMID independent roots, invalidation, and reuse.** Evidence: **LIVE**, `case:invalidation.asid-isolation`, `case:invalidation.vmid-isolation`.
- [x] **BA-ORDER-007 — combined stage-1/stage-2 mutation, stage-specific TLBI, and reverse restoration.** Evidence: **LIVE**, `case:invalidation.combined-stage1-stage2`.
- [x] **BA-ORDER-008 — VA, IPA, VA-range, IPA-range, ASID, VMID, and all-entry TLBI operation branches.** Evidence: **LIVE**, `case:invalidation.translation-cycle`, `case:invalidation.stage2-translation-cycle`, `case:invalidation.asid-isolation`, `case:invalidation.vmid-isolation`, `case:invalidation.combined-stage1-stage2`.
- [x] **BA-ORDER-009 — local versus inner-shareable visibility with a secondary PE.** Evidence: **LIVE**, `case:invalidation.multi-pe-visibility`.
- [x] **BA-ORDER-010 — invalidation, barrier, and TLBI injected failure recovery.** Evidence: **LIVE**, `case:recovery.invalidation`, `case:recovery.barrier`, `case:recovery.tlbi`.
- [x] **BA-ORDER-011 — generated-code data/instruction coherency sequence.** Evidence: **LIVE**, `case:invalidation.generated-code-coherency`.
- [ ] **BA-ORDER-012 — one end-to-end test observes break-before-make descriptor clearing, required barrier/TLBI, replacement, and hardware result as a single sequence.** Current callback ordering and hardware stale-exclusion evidence are separate tests.
- [ ] **BA-ORDER-015 — multi-PE visibility for 16/64 KiB VMSA64.** Current multi-PE test uses 4 KiB.
- [ ] **BA-ORDER-016 — multi-PE visibility for LPA2 at 4/16/64 KiB.** Current multi-PE test uses VMSA64.
- [ ] **BA-ORDER-018 — multi-PE stage-2 descriptor mutation for direct and XNX models.** Current multi-PE visibility test is stage 1.
- [ ] **BA-ORDER-019 — Secure, Realm EL2, Realm REC, and Root multi-PE invalidation.** Current secondary-PE mutation evidence is Normal-world only.

## 11. Fault, malformed, recovery, and isolation branches

- [x] **BA-FAULT-001 — current/lower stage-1 translation and permission faults with normalized ESR/FAR fields.** Evidence: **LIVE**, `case:faults.current-translation`, `case:faults.lower-el`.
- [x] **BA-FAULT-002 — stage-1 address-size fault at exact walk level.** Evidence: **LIVE**, `case:faults.stage1-address-size`.
- [x] **BA-FAULT-003 — malformed stage-2 walk produces exact stage-2 fault and IPA.** Evidence: **LIVE/MALFORMED**, `case:faults.stage2-malformed-walk`.
- [x] **BA-FAULT-004 — unexpected exception follows destructive fatal path and does not poison following boots.** Evidence: **LIVE**, `case:faults.unexpected-exception-destructive`.
- [x] **BA-FAULT-005 — malformed descriptor cases are isolated and later cases continue.** Evidence: **MALFORMED**, `prefix:descriptors.malformed-`.
- [x] **BA-FAULT-006 — LPA2 high-output destructive model exits are isolated as independent boots.** Evidence: **MALFORMED**, `case:descriptors.malformed-lpa2-ds-address`, `case:descriptors.malformed-lpa2-64k-address`.
- [x] **BA-FAULT-007 — allocation/install/lower/secondary/restore failure classes retry and run a fresh sentinel.** Evidence: **LIVE**, `prefix:recovery.allocation-`, `prefix:recovery.install-`, `prefix:recovery.lower-`, `prefix:recovery.secondary-`, `prefix:recovery.restore-`.
- [x] **BA-FAULT-008 — Realm delegation/create/REC/map/protect/unmap/destroy/undelegate recovery branches.** Evidence: **LIVE**, `prefix:realm-rec.recovery-`.
- [ ] **BA-FAULT-009 — every RES0/RES1 bit position for every descriptor layout is injected independently.** Current malformed tests target representative architectural gaps, not every bit position.
- [ ] **BA-FAULT-010 — every exact fault class repeated for every format/granule/regime.** Current exhaustive format matrix emphasizes successful walks; negative faults use representative combinations.

## 12. Realm REC ownership boundary

- [x] **BA-REC-001 — real Realm creation, activation, REC creation/entry, and destruction.** Evidence: **LIVE**, `case:realm-rec.live-stage2`.
- [x] **BA-REC-002 — protected Realm access and Non-secure unprotected map/unmap/protect transitions.** Evidence: **LIVE**, `case:realm-rec.live-stage2`.
- [x] **BA-REC-003 — exact REC fault injection/re-entry and R-EL1 AT/PAR observation.** Evidence: **LIVE**, `case:realm-rec.live-stage2`, `case:translation.current-at-par`.
- [x] **BA-REC-004 — REC operation failure injection and lifecycle reuse.** Evidence: **LIVE**, `prefix:realm-rec.recovery-`.

## 13. Current gap summary

Unchecked areas fall into four groups:

1. synthetic feature-decoder/compile-configuration branches;
2. semantic codec cross-products not repeated live in every regime;
3. capability-unavailable Secure/Realm/Root LPA2 or D128 combinations; and
4. concurrency/order stress, especially D128 no-tearing and insertion/reclaim
   publication across PEs.

The fourth group is the highest-priority extension because a sequentially
correct mapper can still violate architectural publication or invalidation
ordering.  The first concrete follow-up batch should therefore be a typed
multi-PE live-table protocol that repeatedly coordinates writer and walker PEs
for insert, replace, remove, and reclaim over VMSA64, LPA2, and D128, with
stage-1 and stage-2 variants wherever the FVP advertises support.
