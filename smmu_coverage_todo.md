# SMMU coverage TODO

This list tracks public `aarch64-vmsa` behavior that is not yet covered by the
enabled SMMU tests. It intentionally excludes private implementation details.

## Resolved crate failures

- [x] After the crate supplies the missing public codecs, add semantic
  encode/decode matrices for every SMMUv2 VMSA64 stage-1 regime and every
  SMMUv3 VMSA64/VMSA64-LPA2 stage-1 regime, across all supported endians and
  granules. Keep `tools/probe_smmu_stage1_semantics.py` enabled until then.
- [x] After SMMUv2 `output_address` normalizes by translation level, extend the
  existing walker/mapper checks to assert block and 16/64 KiB page output bases.
  Keep `smmu.v2-stage2-output-normalization` enabled until then.

The complete reproductions and evidence are in `crate_report.md`.

## Public API coverage still to add

- [x] Add semantic mapper and walker round trips for SMMUv3 VMSA128 stage-1,
  including every stream regime, PAS choice, granule, endian, map, remap,
  unmap, reclaim, and allocator-error path.
- [x] Add exhaustive SMMUv2 stage-2 semantic mapper coverage for all legal
  allocation-hint, software-metadata, memory-attribute, permission,
  shareability, contiguous, and access-flag combinations.
- [x] Add SMMUv3 stage-2 mapper coverage for VMSA64,
  VMSA64-LPA2, and VMSA128, both public permission models, every stage-2
  regime/PAS choice, and representative boundary/mixed-bit table-control
  propagation combinations. Opaque software metadata does not require 1,024
  complete mapper lifecycle repetitions per format.
- [x] Add negative matrices for reserved raw values, invalid level/kind
  combinations, misaligned table/output addresses, address-width overflow,
  unsupported granule/format combinations, and semantic configuration errors
  for every SMMU regime rather than representative regimes only.
- [x] Add descriptor mutation/round-trip checks that independently cover every
  public SMMU-specific raw field and ensure unrelated bits are preserved.

## Live SMMUv3 coverage still to add

- [x] Exercise live VMSA64-LPA2 stream tables.
- [ ] Exercise live VMSA128/D128 stream tables on a capable model. FVP Base
  RevC 11.30.27 and 11.31.28 advertise the configurable IDR5 field but reject
  a D128 STE during translation; do not register this boot until a model with
  an implemented D128 SMMU translation path is selected.
- [ ] Expand live stage-1 beyond non-secure 4 KiB little-endian: add 16/64 KiB,
  big-endian, privileged-stream, Secure, and Realm cases after their semantic
  codec blockers are resolved.
- [x] Add `SecureStreamNonSecureIpaStage2` live translation and both public
  stage-2 permission models, including XNX execute permissions.
- [x] Add live stage-2 table-descriptor controls, multi-level and block walks,
  and table access-flag faults through the external translation agent. Public
  contiguous/dirty encodings and break-before-make behavior are covered by the
  descriptor and live PE tests; repeating SMMU command mechanics would not
  exercise additional public `aarch64-vmsa` behavior.
- [x] Add independently isolated live translation, address-size, access, and
  permission fault cases. Validate exact event records where the model commits
  them and exact terminated-transfer/no-write observations otherwise.
- [x] Add multiple StreamIDs and, where advertised, SubstreamID/context-table
  selection instead of exercising only SID 0 and one context descriptor.
- [x] Add retained-state checks that run successful and faulting SMMU cases in
  different orders and prove CR0/CR1, stream tables, queues, test-engine state,
  and modified memory are restored between boots.

## SMMUv2 live validation

- [ ] Route SMMUv2 tests to independent hardware or an SMMUv2-capable model.
  Cover stage-1 and stage-2 page/block walks, permissions, faults, TLB
  invalidation, all supported granules, and both descriptor endians. Do not
  report `Unsupported` until live feature registers establish that the selected
  target lacks SMMUv2 after all model/firmware configuration attempts.

## Completion gate

- [x] Before claiming 100%, run doctor and the complete suite, run it again in a
  fresh invocation, verify the crate checkout is byte-for-byte unchanged from
  its recorded baseline, and retain evidence for every remaining crate failure.
  Doctor and the public codec probe passed; fresh sessions
  `session-00001788150648053489-73822` and
  `session-00001788150815502023-78314` produced identical 907-pass results.
  The intentionally modified read-only crate remained at revision
  `5251c2c5498c021eee95217f44930b28078cffc0` with content fingerprint
  `fnv1a64:31acfb77f13ff50c`.
