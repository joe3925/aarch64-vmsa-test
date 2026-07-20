# `aarch64-vmsa` failure triage

This file records reproducible failures whose ownership is not yet established. An item remains
here until evidence attributes it to the crate, the harness/test oracle, firmware, or the FVP.

Confirmed crate defects belong in `crate_report.md`. Confirmed harness defects must be fixed in the
harness and must not be copied into `crate_report.md`.

## Current context

- Latest full command: `cargo run test all --crate "/Users/boden/Documents/aarch64-vmsa"`
- Latest NS-EL2 result: `passed=463 failed=7 skipped=0`
- Latest retained evidence:
  `output/runs/ns-el2-00001784524182676390-74198/`
- Reference crate checkout used by this campaign:
  - HEAD: `ada32824cd813c16ab6ea30322ee396aad3aaa75`
  - Dirty content fingerprint: `fnv1a64:efe950d65438f158`

Four of the seven latest failures are confirmed crate defects and are documented in
`crate_report.md`. The remaining three failures are tracked below.

## TRIAGE-DESC-001 — VMSA64/LPA2 RES0 mutations complete on FVP

- Status: unresolved
- Candidate owners: crate raw-walk validation, malformed-descriptor test oracle, or FVP behavior
- Profile: Normal EL2 (`ns-el2`)
- Catalog cases:
  - `descriptors.malformed-vmsa64-res0`
  - `descriptors.malformed-lpa2-ds-res0`
  - `descriptors.malformed-lpa2-64k-res0`
- Related passing controls:
  - `descriptors.malformed-vmsa64-reserved-type`
  - `descriptors.malformed-vmsa64-res1`
  - `descriptors.malformed-lpa2-ds-reserved-type`
  - `descriptors.malformed-lpa2-ds-res1`
  - `descriptors.malformed-lpa2-64k-reserved-type`
  - `descriptors.malformed-lpa2-64k-res1`
  - fresh valid mapping and restoration checks following every case

### Observed behavior

Each case creates a valid typed mapping through the public mapper, prepares the transition
runtime, obtains the valid terminal raw descriptor through public typed inspection, and then
mutates one bit through the harness's isolated malformed-table surface:

| Case | Format and geometry | Mutation | Expected by test | Actual |
|---|---|---:|---|---|
| `descriptors.malformed-vmsa64-res0` | VMSA64, 4 KiB, L3 | set bit 48 | stage-1 translation fault | load completes with `0x4d414c464f524d45` |
| `descriptors.malformed-lpa2-ds-res0` | LPA2 DS, 4 KiB, L3 | set bit 59 | stage-1 translation fault | load completes with `0x4c5041324d414c46` |
| `descriptors.malformed-lpa2-64k-res0` | LPA2, 64 KiB, L3 | set bit 48 | stage-1 translation fault | load completes with `0x4c5041324d414c46` |

The loaded values are the seeded sentinel values, so the malformed hardware access completed
rather than entering the expected fault path.

The reserved-type and cleared-RES1 neighboring mutations fault and recover as expected, which
shows that installation, exception capture, sandbox restoration, and the general fault matcher are
operational.

### Why ownership is unresolved

The test calls `mapper.inspect_walk(ADDRESS)` before mutation to locate the valid terminal
descriptor. After mutation, it immediately installs the table and uses the hardware load as the
oracle.

It does not currently call a public crate walk or decoder after the RES0 mutation. Therefore the
failure does not establish that the crate accepts the mutated raw descriptor.

The hardware result alone is also insufficient to assign a crate failure. Before the expected-fault
oracle can be treated as authoritative, the exact architectural consequence of setting each bit
must be verified for the selected format, granule, DS setting, level, and translation controls.
A bit identified as RES0 by the crate layout is forbidden for software construction, but this
triage item must not assume without direct architectural evidence that hardware is required to
raise the specific translation fault expected by the test.


### Promotion and closure rules

Move a case to `crate_report.md` only when all of the following are true:

1. the post-mutation public crate walk or decoder accepts the descriptor;
2. the crate's public layout/validation contract identifies the mutated bit as invalid for that
   exact format and geometry;
3. the failure reproduces without relying on candidate-table setup, exception routing, or cleanup;
4. the valid neighboring and restoration controls still pass.

Classify a case as a harness/test-oracle failure when:

- the public crate walk rejects the descriptor but the test still reports failure solely because
  the hardware access completed; or
- architecture review shows that the selected RES0 mutation is not required to produce the
  expected translation fault; or
- the raw mutation does not reach the intended terminal descriptor under the installed controls.

Classify a case as an FVP/platform discrepancy when:

- the public crate walk rejects the descriptor;
- the architecture unambiguously requires the expected fault for the exact configuration; and
- independent inspection confirms that the intended raw descriptor was installed and observed by
  the translation walk.

### Evidence

- Latest full reproduction:
  `output/runs/ns-el2-00001784524182676390-74198/`
- Earlier malformed-descriptor family:
  `output/runs/ns-el2-00001784190427877626-86399/`
- Isolated LPA2 high-address controls:
  - `output/runs/ns-el2-00001784190451388919-86399/`
  - `output/runs/ns-el2-00001784190474790436-86399/`

### Current disposition

Do not include these three cases in `crate_report.md` yet. Keep all assertions enabled and retain
the current hardware observations while adding the post-mutation crate-side oracle.

