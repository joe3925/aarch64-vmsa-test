# `aarch64-vmsa` FVP Coverage Completion TODO

This checklist is the return gate for the implementation described in
`IMPLEMENTATION_PLAN.md`. Do not check an item merely because code was written.
Each test item requires a cataloged test, execution in every applicable FVP
profile, exact results, cleanup/restoration evidence, and a following isolation
observation.

A passing test closes its item. A crate-caused failure closes its item only if
the test remains enabled and failing and the complete failure is appended to
`crate_report.md`. An unfixed harness failure, untriaged failure, missing
adapter, missing run, accidental skip, or missing artifact never closes an
item. Cache residency is the only accepted observational exception; encoding,
coherency, and data integrity are still mandatory.

## Scope and audit gate

- [ ] Record the tested checkout's HEAD, dirty status, and content/provenance fingerprint without modifying it.
- [ ] Confirm the crate is mounted read-only for every doctor, build, and test invocation.
- [ ] Regenerate the public API inventory for the exact checkout contents and record the expected item count.
- [ ] Classify every public item as type-only, value-only, typed inspection, direct FVP execution, isolated malformed input, or genuinely FVP-unsupported.
- [ ] Map every architecturally observable public item to one or more final catalog test identities.
- [ ] Validate that the final audit has zero blank classifications, zero blank routes, and zero incomplete observable routes.
- [ ] Confirm that no item count, classification, or route was weakened to conceal missing coverage.
- [ ] Confirm all test code uses the stable harness API; document and remove every accidental adapter-internal/raw-hardware dependency.

## Feature and regime tests

- [ ] Add live ID-register snapshot versus `decode_features` versus harness-capability agreement tests in every profile.
- [ ] Add positive hardware corroboration for EL2, EL3, EL2&0, SEL2, RME, stage 2, XNX, LPA2, D128, and D128 stage-2 feature claims.
- [ ] Add extended input-address and extended output-address positive and boundary tests.
- [ ] Add security-state membership and feature-requirement assertions to live profile cases.
- [ ] Add `validate_regime` coverage for every stage-1 and stage-2 regime in its owning profile.
- [ ] Add `validate_regime_format` coverage for every applicable regime/format/granule combination.
- [ ] Add exact unsupported-feature classification tests; prove supported applicable cases never become skips.
- [ ] Add a catalog/adapter completeness check that fails on any applicable row without a handler.

## Required profile matrix

- [ ] Complete Normal EL2 current-stage1 tests for `NonSecureEl2Stage1`.
- [ ] Complete Normal EL2 lower-EL1 tests for `NonSecureEl1Stage1`.
- [ ] Complete Normal EL2 EL2&0 tests for `NonSecureEl2HostStage1`.
- [ ] Complete Normal EL2 stage-2 tests for both `NonSecureEl2Stage2` permission models.
- [ ] Complete Normal EL2 combined stage1+stage2, ASID, VMID, and secondary-PE tests.
- [ ] Complete Secure EL2 current-stage1 tests for `SecureEl2Stage1`.
- [ ] Complete Secure EL2 lower-EL1 tests for `SecureEl1Stage1`.
- [ ] Complete Secure EL2 EL2&0 tests for `SecureEl2HostStage1`.
- [ ] Complete Secure-IPA and Non-secure-IPA stage-2 tests for both permission models.
- [ ] Complete Realm EL2 current-stage1 tests for `RealmEl2Stage1`.
- [ ] Complete Realm EL2 lower-EL1 tests for `RealmEl1Stage1`.
- [ ] Complete Realm EL2 EL2&0 tests for `RealmEl2HostStage1`.
- [ ] Complete Realm EL2 stage-2 tests for both permission models.
- [ ] Complete Realm REC RMM-owned stage-2 map/protect/unprotect/unmap/remap/fault/AT/lifecycle tests.
- [ ] Complete Root EL3 stage-1 tests for `RootEl3Stage1` across every supported format/granule.
- [ ] Confirm every payload-independent test implementation lives in common code with only thin payload handlers.

## Format, granule, level, and address tests

- [ ] Add VMSA64 4 KiB stage-1 and stage-2 active L1-block, L2-block, and L3-page cases.
- [ ] Add VMSA64 16 KiB stage-1 and stage-2 active L2-block and L3-page cases.
- [ ] Add VMSA64 64 KiB stage-1 and stage-2 active L2-block and L3-page cases.
- [ ] Add LPA2 4 KiB stage-1 and stage-2 active L0/L1/L2-block and L3-page cases.
- [ ] Add LPA2 16 KiB stage-1 and stage-2 active L1/L2-block and L3-page cases.
- [ ] Add LPA2 64 KiB stage-1 and stage-2 active L1/L2-block and L3-page cases.
- [ ] Add D128 4 KiB stage-1 and stage-2 active L0/L1/L2-block and L3-page cases.
- [ ] Add D128 16 KiB stage-1 and stage-2 active L1/L2-block and L3-page cases.
- [ ] Add D128 64 KiB stage-1 and stage-2 active L1/L2-block and L3-page cases.
- [ ] For every legal leaf case, assert exact kind, level, entry indexes, covered range, output base, nonzero-offset output, AT/PAR result, and real access.
- [ ] Add all valid root/start-level cases down to VMSA64 NEG1, LPA2 NEG1, and D128 NEG2.
- [ ] Add exact just-outside-range root/start/leaf-level rejection cases.
- [ ] Add step-by-one and every feasible D128 SKL transition plus bounded/no-plan cases.
- [ ] Add accepted 32/36/40/42/44/48/52/56-bit output-width cases for each permitting format.
- [ ] Add exact format-specific output-width rejection cases.
- [ ] Add minimum, maximum, and one-past-limit input/output address cases.
- [ ] Add high-address-bit active cases for LPA2 and D128 and verify no truncation or aliasing.
- [ ] Add input/output arithmetic-overflow and range-end-overflow cases.
- [ ] Add aligned/misaligned root, table, input, output, block, page, and range-length cases.
- [ ] Add page/block boundary, terminal-table growth boundary, sibling-preservation, and last-leaf reclaim cases.

## Address, geometry, table access, and walker tests

- [ ] Corroborate all `GranuleKind`, `TranslationGranule`, and `Level` calculations inside active hardware cases.
- [ ] Corroborate `TableGeometry` entries, index bits/masks, shifts, indexes, and offsets against inspected active walks.
- [ ] Add valid and invalid `TableStrideCount`, `TableShape`, allocation-layout, and base-validation cases.
- [ ] Add valid and invalid `TableTransition` step/stride/direction cases.
- [ ] Add complete `TableWalkPath` push/entry/index/level/terminal/capacity cases through bounded inspection APIs.
- [ ] Add `TableCursor`, `TableAccessLocation`, `NextTable`, and walk-cursor exact state/error cases.
- [ ] Add `OffsetTableAccess` offline and live behavior through stable mapper wrappers.
- [ ] Add live `RecursiveTableAccess` mapping, mutation, translation, and cleanup tests.
- [ ] Add exact recursive index, base, level, path, overflow, and null-mapping rejection tests.
- [ ] Add safe harness-mediated `TranslationTable` read and `TranslationTableMut` effect/bounds tests.
- [ ] Add walker invalid/table/block/page step tests and whole-walk/translate agreement tests.
- [ ] Add exact walker access, location, cursor, table-address, index, final-table, and output-overflow errors.

## Descriptor tests

- [ ] Exercise every `low_level::raw` bounded constructor/accessor at zero, maximum, and first-invalid values and classify these assertions as value-only.
- [ ] Route every raw field that can enter a descriptor to typed viable-table inspection or an isolated malformed-table case.
- [ ] Add VMSA64 stage-1 leaf/table field construction, live inspection, and hardware-agreement tests.
- [ ] Add VMSA64 stage-2 leaf/table field construction, live inspection, and hardware-agreement tests.
- [ ] Add LPA2 stage-1 DS and 64 KiB non-DS leaf/table address and field tests.
- [ ] Add LPA2 stage-2 DS and 64 KiB non-DS leaf/table address and field tests.
- [ ] Add D128 stage-1 page/block/table/SKL field and next-table tests.
- [ ] Add D128 stage-2 page/block/table/SKL field and next-table tests.
- [ ] Add exact offline-versus-installed raw width, kind, path, output, and decoded-field agreement tests.
- [ ] Add exact invalid leaf-level and invalid table-transition descriptor errors.
- [ ] Add exact D128 NT/BBM final-level and table-NT/SKL reserved-field errors.
- [ ] Add isolated malformed VMSA64 reserved type/RES0/RES1/final-table recovery cases.
- [ ] Add isolated malformed LPA2 reserved type/address/RES0/RES1 recovery cases for DS and 64 KiB encodings.
- [ ] Add isolated malformed D128 valid/SKL/address/RES0/RES1 recovery cases.
- [ ] For every malformed case, assert exact fault/rejection, sandbox restoration, emergency restoration, and a fresh successful mapping.

## Semantic memory-attribute tests

- [ ] Exhaust all four device-memory types through MAIR semantic construction and decode.
- [ ] Exhaust Non-cacheable and all encodable normal-memory inner/outer cache policy, transience, and allocation-hint combinations.
- [ ] Add every unencodable MAIR/cacheability combination with exact `AttrError`.
- [ ] Add MAIR duplicate-slot deterministic selection and missing-attribute errors.
- [ ] Add D128 MAIR2 slots 8-15, duplicate-slot behavior, unavailable-MAIR2, and invalid-entry errors.
- [ ] Exhaust stage-2 combined device and normal-memory encodings and invalid combinations.
- [ ] Exhaust all FWB device/normal encodings with FWB enabled and disabled.
- [ ] Add FWB MTE-permission allowed/denied, wrong-mode, and invalid-encoding cases.
- [ ] Add VMSA64/LPA2/D128 stage-1 semantic memory map/inspect/access/restore cases.
- [ ] Add VMSA64/LPA2/D128 stage-2 semantic memory map/inspect/access/restore cases.
- [ ] Exhaust valid/invalid shareability and LPA2 DS effective-shareability match/mismatch behavior, including the distinct 64 KiB rule.
- [ ] Add active MAIR/MAIR2/control restoration and following-test isolation checks.
- [ ] Add generated-code coherency and multi-PE data publication checks for cache/shareability sequences.
- [ ] Record only cache residency/replacement as unobservable; verify that no broader cache claim is exempted.

## Stage-1 permission and control tests

- [ ] Exhaust single-privilege leaf ReadWrite/ReadOnly plus execute true/false in active contexts.
- [ ] Add exact single-privilege None/invalid AP/unencodable execute-field errors.
- [ ] Exhaust single-privilege table data and execute limits plus invalid combinations.
- [ ] Exhaust all valid two-privilege leaf AP data pairs and all four execute pairs.
- [ ] Add every invalid two-privilege leaf data pair with exact error.
- [ ] Exhaust all valid two-privilege table AP data-limit pairs and execute-limit pairs.
- [ ] Add every invalid two-privilege table-limit pair with exact error.
- [ ] Exhaust D128 stage-1 PI base entries, including reserved behavior and GCS gating.
- [ ] Exhaust D128 stage-1 PO overlay entries, WXN behavior, and no-overlay behavior.
- [ ] Exhaust privileged/unprivileged register presence combinations and effective permission results.
- [ ] Add deterministic duplicate match, unavailable indirection, missing combination, and unencodable effective permission errors.
- [ ] Add active privileged and unprivileged read/write/execute success and exact denial faults for every distinguishable result.
- [ ] Add AF and dirty transitions with HA/HD disabled/enabled for VMSA64 and D128 stage 1.
- [ ] Exhaust global/non-global, Root NSE, and D128 alias modes plus all conflict/invalid-alias errors.
- [ ] Cover contiguous, guarded, protected, BBM/NT, table-NT, DISCH, and table access-flag controls.
- [ ] Exhaust 4-bit and 10-bit stage-1 software metadata values and exact out-of-range errors.

## Stage-2 permission and control tests

- [ ] Exhaust direct stage-2 DataAccess values and both valid non-XNX execute states.
- [ ] Add exact non-XNX mixed privileged/unprivileged execute rejection cases.
- [ ] Exhaust all XNX data and privileged/unprivileged execute combinations.
- [ ] Add invalid stage-2 AP and execute-never decode/rejection cases.
- [ ] Exhaust all D128 `Stage2Permission` variants, execute combinations, MostlyReadOnly qualifiers, and WriteOnly.
- [ ] Exhaust all 16 D128 stage-2 PI base entries including reserved-as-no-access.
- [ ] Exhaust all 16 D128 stage-2 PO overlay entries and their full effective combination matrix.
- [ ] Add deterministic duplicate match, missing registers, missing combination, and no-overlay cases.
- [ ] Add active stage-2 read/write/execute success and exact denial faults for every hardware-distinguishable result.
- [ ] Add D128 stage-2 dirty/access-flag hardware update cases where exposed.
- [ ] Cover force-no-execute, contiguous, assured-only, BBM/NT, table-NT, and table access-flag controls.
- [ ] Exhaust 4-bit and 10-bit stage-2 software metadata values and exact out-of-range/conflict errors.

## PAS tests

- [ ] Add fixed Non-secure stage-1 and stage-2 semantic/access tests.
- [ ] Add fixed Realm IPA stage-1 semantic/access tests.
- [ ] Add Secure-selectable stage-1 Secure and Non-secure leaf/table/access/fault tests.
- [ ] Add Secure-IPA and Non-secure-IPA stage-2 configured PAS tests and mismatch rejection.
- [ ] Add Realm-or-Non-secure stage-1 and stage-2 leaf/access/fault tests.
- [ ] Add Root Secure/Non-secure/Root/Realm leaf/access/fault tests.
- [ ] Add table PAS inheritance and NS/NSE alias behavior tests.
- [ ] Add malformed fixed/selectable PAS decode and conflicting semantic attribute errors.
- [ ] Add exact GPC fault class/status/stage/level/FAR/IPA assertions where supplied.
- [ ] Add owned PAS allocation, unavailable-PAS rejection, cleanup, delegation reversal, and leak checks.
- [ ] If an applicable owned PAS pool is absent, add and verify a scoped typed harness allocator before closing PAS coverage.

## Mapper tests

- [ ] Add offline mapper construction/accessor/`into_parts` tests for every format/granule/stage class.
- [ ] Add live mapper construction/accessor/invalidation/`into_parts` tests for every format/granule/stage class.
- [ ] Add page and block `map_leaf` tests with exact `MapLeafOutcome` fields.
- [ ] Add `map_leaf_with_plan` tests for step-by-one, bounded SKL, and maximum SKL planners.
- [ ] Add zero, single, multi-page, multi-table, and boundary-crossing `map_range` tests with exact outcome fields.
- [ ] Add semantic-map and semantic leaf/table decode tests corroborated by hardware.
- [ ] Add software `translate` None/Some and exact `Mapping` field tests, including block offsets.
- [ ] Add `unmap` exact old-mapping and post-unmap fault tests.
- [ ] Add `unmap_reclaim` sibling, table-free count, root-empty, retry, and post-fault tests.
- [ ] Add already-mapped table/leaf and not-mapped translate/unmap/reclaim tests.
- [ ] Add non-leaf-base unmap and range length/alignment errors.
- [ ] Add invalid root level, root address bits, output width, root/output range, and root address errors.
- [ ] Add invalid leaf level, input range, output range, overflow, and invalid-level errors.
- [ ] Add injected table-access, frame-allocation, frame-free, descriptor-write, and generic provider errors.
- [ ] Add partial table-growth failure inspection, cleanup/retry, and resource-accounting tests.
- [ ] Determine and test the public/name-implied failure postcondition of range mapping; report any crate mismatch without changing the crate.
- [ ] Demonstrate exact coverage or explicit audit classification for every `MapperError` variant and payload field.

## Live invalidation and mutation tests

- [ ] Add live leaf insertion/removal invalidation and synchronization tests.
- [ ] Add live table insertion/removal/reclaim invalidation and synchronization tests.
- [ ] Add protect read-success/write-fault/restore tests for every stage and format family.
- [ ] Add remap new-output and failed-remap old-output rollback tests.
- [ ] Add break-before-make ordering and failed-replacement rollback tests.
- [ ] Add unmap/reclaim stale-translation exclusion tests.
- [ ] Add VA, IPA, VA-range, IPA-range, ASID, VMID, and all-entry TLBI tests.
- [ ] Add local and inner-shareable TLBI scope tests with primary/secondary PE observation.
- [ ] Add wrong-stage, wrong-identifier, invalid-range, and invalid-scope TLBI rejection tests.
- [ ] Add independent ASID root/value isolation and transactional reuse tests.
- [ ] Add independent VMID root/value isolation and transactional reuse tests.
- [ ] Add mixed-format/granule/width combined stage1+stage2 access and inspection tests.
- [ ] Add combined per-stage protect/remap/unmap/fault/TLBI and reverse restoration tests.

## Failure, recovery, and lifecycle tests

- [ ] Inject and verify every page/contiguous/root/table allocation failure boundary.
- [ ] Inject and verify mapper map/range/remap/protect/unmap/reclaim failure boundaries.
- [ ] Inject and verify translation installation, lower installation, and partial combined-install failure boundaries.
- [ ] Inject and verify invalidation/barrier/TLBI failure rollback boundaries exposed by the harness.
- [ ] Inject and verify lower-context entry/action/return failure boundaries.
- [ ] Inject and verify secondary-PE start/rendezvous/action/stop/timeout cleanup boundaries.
- [ ] Inject and verify Realm delegation/create/map/REC/enter/mutate/destroy/undelegate failure boundaries.
- [ ] Inject and verify explicit restore, Drop restore, and runner emergency-restore boundaries.
- [ ] After every recoverable failure, inspect state/resources, retry, restore, and pass a fresh mapping sentinel.
- [ ] Run malformed/corrupting cases in separate or destructive boots with exact expected termination classification.
- [ ] Verify later independent boots continue after isolated/destructive cases.
- [ ] Verify no test relies on ordering, leaked mappings, retained memory, or a later test for cleanup.

## Fault precision tests

- [ ] Add exact stage-1 address-size, translation, permission, access-flag, alignment, execute, and malformed-walk faults.
- [ ] Add exact stage-2 translation, permission, access-flag, execute, and malformed-walk faults.
- [ ] Add exact Realm GPC/PAS faults where applicable.
- [ ] Assert fault class, status, access kind, stage, level, FAR, and IPA whenever architecturally supplied.
- [ ] Add current EL, EL1, EL0/EL1, EL2&0, Realm REC, and secondary-PE guarded-fault recovery cases.
- [ ] Verify every expected fault returns through the harness and a following access succeeds.
- [ ] Verify an unexpected exception corrupts only the current boot, retains artifacts, and does not become a crate skip.

## Smoke-test removal and code quality

- [ ] Migrate useful target-crate coverage from `target/payloads/common/smoke.rs` into narrow domain tests.
- [ ] Migrate useful target-crate coverage from `target/payloads/common/translation_smoke.rs` into narrow domain tests.
- [ ] Remove standalone harness demonstrations that do not prove target-crate behavior.
- [ ] Delete both smoke source files and their module declarations.
- [ ] Remove every `smoke.*` registry/catalog identity.
- [ ] Remove or update every documentation and source reference to smoke tests.
- [ ] Confirm no smoke function was merely renamed while retaining unrelated multi-purpose assertions.
- [ ] Deduplicate common setup/builders and keep payload-specific code limited to true platform differences.
- [ ] Format and lint the harness/test repository without touching the tested checkout.
- [ ] Review unsafe code additions; require a documented invariant and eliminate any test-side arbitrary pointer/register access.

## Failure disposition gate

- [ ] Demonstrate exact test coverage or explicit public-unreachability classification for every `AttrError` variant.
- [ ] Preserve original artifacts for every failure before changing harness or tests.
- [ ] Classify every failure as harness, crate, genuinely unsupported FVP capability, or approved cache unobservability.
- [ ] Fix every harness-caused failure and add a regression assertion.
- [ ] Rerun each harness fix's failing case, isolation sentinel, and all affected profiles.
- [ ] For every crate-caused failure, keep the test enabled and append the complete required entry to `crate_report.md`.
- [ ] Confirm no crate-caused test was removed, ignored, weakened, converted to expected failure, or hidden by a filter.
- [ ] Confirm every unsupported result is backed by an FVP capability/ID observation and is not an adapter gap.
- [ ] Confirm no untriaged failure, boot corruption, timeout, or incomplete run remains.

## Final execution and return gate

- [ ] Validate catalog identity uniqueness, matrix applicability, API audit, and firmware ABIs.
- [ ] Run every test family in every applicable Normal, Secure, Realm EL2, Realm REC, and Root profile.
- [ ] Run the full explicit-path command against `C:\Users\Boden\Documents\temp\aarch64-vmsa`.
- [ ] Run the complete suite again in a fresh invocation to expose order and retained-state dependencies.
- [ ] Retain complete artifacts for all crate failures, unsupported cases, destructive cases, and unexpected results.
- [ ] Confirm all passing runs cleaned their run directories according to policy and all required retained evidence is addressable.
- [ ] Confirm the tested checkout's final status/content fingerprint matches the initial fingerprint.
- [ ] Confirm every checkbox above is checked under the stated pass-or-reported-crate-failure rule.
- [ ] Prepare a final handoff with crate fingerprint, profiles, result totals, evidence paths, harness changes, smoke-removal confirmation, read-only-checkout confirmation, and `crate_report.md` location if created.
