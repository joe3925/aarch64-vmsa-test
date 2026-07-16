# `aarch64-vmsa` remaining branch-gap TODO

Source of truth: `IMPLEMENTATION_PLAN.md` and
`docs/BRANCH_AREA_AUDIT.md`. Starting scope: 34 unchecked areas.

Rules for every checkbox:

- Keep `/Users/boden/Documents/aarch64-vmsa` read-only.
- Test the crate, not a duplicate harness implementation of VMSA logic.
- Add the complete coherent batch before compiling; run cases in bulk.
- Keep cases independent. Split any case whose failed result is not required
  by its later checks.
- Never add a one-failure exception branch, weaken an assertion, or hide a
  failure with skip/ignore/filtering.
- Fix every harness-caused failure and add a regression assertion.
- Keep every crate-caused assertion enabled and append its full evidence only
  to `crate_report.md`.
- Treat unsupported as valid only after live ID-register confirmation with the
  required model/firmware configuration present.

## Baseline and profile preparation

- [x] Record the crate revision, dirty state, content fingerprint, and
      read-only mount evidence before changing tests.
- [x] Run the audit, API, harness-boundary, catalog, ABI, and formatting checks
      to establish a clean harness baseline.
- [x] Replace hard-coded extended-format rejection checks with generic live
      feature/format agreement for every profile.
- [x] Enable Realm LPA2 and 52-bit addressing in Realm EL2 and Realm REC.
- [x] Enable Realm D128/D128-stage2 model support and the required TF-A REC
      feature configuration.
- [x] Probe and configure Secure LPA2/D128 and Root LPA2; prove genuine
      unavailability before retaining any unsupported classification.
- [x] Bulk-run feature snapshot and regime/format validation in every affected
      profile before adding semantic cases.

## Feature decoder gaps

- [x] **BA-FEAT-010:** independently drive every absent/implemented/reserved/
      unknown binary, EL2/EL3, RME, VARange, and PARange decoder arm.
- [x] **BA-FEAT-011:** drive every LPA2 primary/secondary granule encoding and
      unknown-priority arm.
- [x] **BA-FEAT-012:** drive every implemented/unknown/absent derived-state
      merge ordering.

## PAS gaps

- [ ] **BA-PAS-012:** live Secure EL2 D128 PAS semantic encoding and hardware
      observation.
- [ ] **BA-PAS-013:** live Realm EL2 D128 PAS encoding at stage 1 and stage 2.
- [ ] **BA-PAS-014:** live Secure and Realm LPA2 PAS encoding.

## Permission gaps

- [ ] **BA-PERM-015:** every D128 stage-1 indirection branch in independently
      named live cases.
- [ ] **BA-PERM-016:** every D128 stage-2 indirection branch in independently
      named live cases.
- [ ] **BA-PERM-017:** Root D128 permission-indirection live behavior.
- [ ] **BA-PERM-018:** Realm and Secure D128 permission-indirection live
      behavior.

## Semantic codec gaps

- [x] **BA-CODEC-006:** Normal lower-EL1 VMSA64 semantic codec at every
      granule/legal level.
- [x] **BA-CODEC-007:** Normal EL2&0 VMSA64 semantic codec at every
      granule/legal level.
- [ ] **BA-CODEC-008:** isolated enabled Normal current-EL2 D128 semantic codec
      observation; retain the model fault without suppressing other tests.
- [x] **BA-CODEC-010:** Secure lower-EL1 VMSA64 permissions, controls,
      granules, and levels.
- [ ] **BA-CODEC-011:** Secure EL2&0 VMSA64 semantic codec.
- [ ] **BA-CODEC-012:** Secure Secure-IPA stage-2 VMSA64 direct and XNX codec
      matrices.
- [ ] **BA-CODEC-013:** Secure Non-secure-IPA stage-2 VMSA64 direct and XNX
      codec matrices.
- [ ] **BA-CODEC-014:** Secure LPA2 and D128 semantic codecs after capability
      configuration/proof.
- [x] **BA-CODEC-016:** Realm lower-EL1 VMSA64 permissions, controls,
      granules, and levels.
- [ ] **BA-CODEC-017:** Realm EL2&0 VMSA64 semantic codec.
- [ ] **BA-CODEC-019:** Realm EL2 stage-2 VMSA64 memory, permissions, controls,
      direct, and XNX branches.
- [x] **BA-CODEC-020:** Realm EL2 stage-2 LPA2 semantic decoding live.
- [ ] **BA-CODEC-021:** Realm EL2 stage-2 D128 semantic decoding live.
- [ ] **BA-CODEC-024:** Root EL3 D128 semantic codec live.
- [x] **BA-CODEC-025:** Root EL3 LPA2 semantic codec live.

## Descriptor, mapper, and BBM gaps

- [ ] **BA-DESC-013:** install every feasible D128 skipped-level/SKL
      transition live across granules and stages.
- [ ] **BA-MAP-013:** install every planner family live for every supported
      format/granule/stage combination.
- [ ] **BA-ORDER-012:** one completed end-to-end BBM case observes clearing,
      barrier/TLBI, replacement, hardware result, and restoration.

## Completed-mutation cross-PE gaps

- [ ] **BA-ORDER-015:** VMSA64 16/64 KiB completed-mutation visibility on a
      secondary PE.
- [ ] **BA-ORDER-016:** LPA2 4/16/64 KiB completed-mutation visibility on a
      secondary PE.
- [ ] **BA-ORDER-018:** stage-2 direct/XNX completed-mutation visibility on a
      secondary PE.
- [ ] **BA-ORDER-019:** Secure, Realm EL2, Realm REC, and Root completed
      invalidation visibility, with general firmware setup/restoration.

## Fault gaps

- [ ] **BA-FAULT-009:** independently inject every RES0/RES1 bit in every real
      descriptor layout; isolate every accepted/terminating case.
- [ ] **BA-FAULT-010:** repeat every exact applicable fault class across every
      supported format, granule, and regime with exact normalized fields.

## Failure and isolation gate

- [ ] Confirm every applicable registered case has a handler; fix every
      adapter/profile omission as a harness failure.
- [ ] Confirm each failing assertion is independently named and later unrelated
      identities still execute.
- [ ] Confirm every harness failure is fixed, regression-tested, and absent
      from `crate_report.md`.
- [ ] Confirm every crate failure remains enabled and has a complete appended
      `crate_report.md` entry with retained evidence.
- [ ] Confirm no test contains a failure-specific acceptance branch, weakened
      assertion, fake success, or capability skip caused by missing harness
      support.

## Bulk validation and completion

- [ ] Run formatting, linting, audit/API/harness-boundary/catalog/ABI validators
      after all case batches are added.
- [ ] Run `doctor` against the explicit read-only crate path.
- [ ] Run the largest useful filtered family/profile batches after each build,
      not one compile per case.
- [ ] Run `test all` across every profile.
- [ ] Run `test all` again in a fresh invocation to detect order/state coupling.
- [ ] Verify restoration, cleanup, destructive-boot isolation, retained
      evidence, and unchanged crate fingerprint.
- [ ] Check every one of the 34 audit areas only after its route resolves and
      its required evidence has actually executed.
- [ ] Run `python3 tools/verify_branch_area_audit.py` and confirm zero unchecked
      branch areas.
- [ ] Remove these implementation-only root plan/TODO files after the final
      handoff is complete.
