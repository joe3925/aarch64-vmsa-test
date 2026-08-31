# `aarch64-vmsa` crate failures

## SMMU stage-1 semantic codecs are unavailable for VMSA64 formats

Status: resolved in the current crate working tree. The original reproduction is retained below.

Resolution evidence:

- `SmmuStreamPermissions` now uses the established two-privilege direct permission codec and
  `SmmuPrivilegedStreamPermissions` uses the established single-privilege codec.
- `tools/probe_smmu_stage1_semantics.py` now succeeds across every advertised SMMUv2/SMMUv3
  stage-1 regime, VMSA64/VMSA64-LPA2 format, descriptor endian, and translation granule.
- External cases `smmu.vmsa64-stage1-semantic-matrix` and
  `smmu.vmsa64-stage1-mapper-walker` pass, covering semantic leaf/table round trips and mapper
  lifecycle behavior.
- Focused result: session `session-00001788149588239012-61134`, two passed and zero failed.

Crate evidence identity:

- checkout: `/Users/boden/Documents/aarch64-vmsa`
- `HEAD`: `5251c2c5498c021eee95217f44930b28078cffc0`
- current dirty-tree content fingerprint: `fnv1a64:31acfb77f13ff50c`

Public behavior under test:

- The crate publicly exposes SMMUv2 and SMMUv3 stage-1 regimes.
- Those regimes publicly select VMSA64 stage-1 descriptor layouts through
  `HasRegimeLayout`.
- VMSA64, VMSA64-LPA2, and the SMMU descriptor interpretations publicly expose semantic
  attribute schemas.
- A caller therefore attempts the public `AttributeCodec<R, G, Cfg>` contract for those
  advertised format/regime combinations. This is a compile-time public API contract; the probe
  does not reproduce crate encoding or decoding logic.

Minimal probe (`Cargo.toml` depends only on the read-only crate path):

```rust
use aarch64_vmsa::address::TranslationGranule;
use aarch64_vmsa::attrs::{AttributeCodec, LiveVmsaConfig};
use aarch64_vmsa::config::format::{Vmsa64, Vmsa64Lpa2, Vmsa128};
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};
use aarch64_vmsa::regime::TranslationRegime;

fn require_codec<F, R, G, C>()
where
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<R, G, C>,
{}

fn main() {
    // Positive control: this compiles and does not appear in the diagnostics.
    require_codec::<Vmsa128, smmu_v3::NonSecureStreamStage1,
        Granule4KiB, LiveVmsaConfig>();

    require_codec::<Vmsa64, smmu_v2::NonSecureStreamStage1,
        Granule4KiB, LiveVmsaConfig>();
    require_codec::<Vmsa64, smmu_v2::NonSecurePrivilegedStreamStage1,
        Granule4KiB, LiveVmsaConfig>();
    require_codec::<Vmsa64, smmu_v3::NonSecureStreamStage1,
        Granule4KiB, LiveVmsaConfig>();
    require_codec::<Vmsa64Lpa2, smmu_v3::NonSecureStreamStage1,
        Granule4KiB, LiveVmsaConfig>();
    require_codec::<Vmsa64Lpa2, smmu_v3::NonSecurePrivilegedStreamStage1,
        Granule4KiB, LiveVmsaConfig>();
}
```

The enabled probe source is `tools/probes/smmu_stage1_semantics.rs`; its runner creates all Cargo
artifacts outside both repositories.

Reproduction command and result:

```text
$ python3 tools/probe_smmu_stage1_semantics.py --crate /Users/boden/Documents/aarch64-vmsa
exit status: 101

error[E0277]: the trait bound `SmmuStreamPermissions: Stage1DirectPermissionModel` is not satisfied
  = help: `Stage1DirectPermissionModel` is not implemented for `SmmuStreamPermissions`
  = note: required for `Stage1` to implement
          `AttributeCodecCell<Vmsa64, NonSecureStreamStage1, Granule4KiB, ...>`
  = note: required for `Vmsa64` to implement
          `AttributeCodec<NonSecureStreamStage1, Granule4KiB, LiveVmsaConfig>`

error[E0277]: the trait bound `SmmuPrivilegedStreamPermissions: Stage1DirectPermissionModel` is not satisfied
  = help: `Stage1DirectPermissionModel` is not implemented for
          `SmmuPrivilegedStreamPermissions`
  = note: required for `Stage1` to implement
          `AttributeCodecCell<Vmsa64, NonSecurePrivilegedStreamStage1, Granule4KiB, ...>`

The same `SmmuStreamPermissions` error is emitted for SMMUv3 with `Vmsa64` and
`Vmsa64Lpa2`; the same `SmmuPrivilegedStreamPermissions` error is emitted for the privileged
SMMUv3 VMSA64-LPA2 combination. Cargo reports five E0277 errors and does not compile the probe.
```

Independent controls and scope:

- The positive-control SMMUv3 `Vmsa128` `AttributeCodec` bound resolves and its semantic
  encode/decode behavior passes the harness matrix for all descriptor endians, all translation
  granules, all six SMMUv3 stage-1 regimes, and all applicable PAS choices.
- Raw stage-1 leaf/table descriptor construction, decoding, kind selection, address recovery,
  and next-table traversal pass for every SMMUv2/SMMUv3 stage-1 regime and every supported
  format/endian/granule axis.
- The failure therefore blocks semantic `AttributeCodec` and semantic mapper coverage for all
  SMMUv2 VMSA64 stage-1 regimes and all SMMUv3 VMSA64/VMSA64-LPA2 stage-1 regimes. It does not
  block their public raw descriptor layouts, nor SMMUv3 VMSA-128 stage-1 semantics.

The failing semantic combinations cannot be placed in the firmware registry because the public
crate API fails during trait resolution and would suppress every unrelated runtime case at payload
compile time. The external compile probe preserves that failure independently while the runtime
cases remain enabled and isolated.

## SMMUv2 leaf output addresses are not normalized for their translation level

Status: resolved in the current crate working tree. The original reproduction is retained below.

Resolution evidence:

- `SmmuV2Vmsa64Stage2Layout::output_address` now applies the shared level/granule geometry
  normalization after extracting the descriptor address field.
- `smmu.v2-stage2-output-normalization` remains enabled and passes direct descriptor checks and
  walker translations for every supported 4/16/64 KiB block/page level.
- Focused result: session `session-00001788149595352091-61233`, one passed and zero failed. The
  complete NS-EL2 SMMU batch also passed 47/47 in session
  `session-00001788149901275485-66334`.

Evidence identity is the same read-only crate checkout and dirty-tree fingerprint recorded above.

Public behavior and independent expectation:

- Input PA: `0x0000_1234_5678_f000`.
- The test constructs a public SMMUv2 stage-2 leaf through `DescriptorLayout::leaf_descriptor`
  and recovers its base through `DescriptorLayout::output_address`.
- AArch64 translation geometry requires the output base to clear every bit below the level size.
  The test uses the architectural shifts directly: 4 KiB L1/L2/L3 = 30/21/12, 16 KiB L2/L3 =
  25/14, and 64 KiB L2/L3 = 29/16.
- These constants and the explicit PA are the oracle; no crate alignment helper is used.

Observed matrix:

| Granule/level | Expected output base | Public crate result |
| --- | ---: | ---: |
| 4 KiB L1 | `0x0000_1234_4000_0000` | `0x0000_1234_5678_f000` |
| 4 KiB L2 | `0x0000_1234_5660_0000` | `0x0000_1234_5678_f000` |
| 4 KiB L3 | `0x0000_1234_5678_f000` | `0x0000_1234_5678_f000` |
| 16 KiB L2 | `0x0000_1234_5600_0000` | `0x0000_1234_5678_f000` |
| 16 KiB L3 | `0x0000_1234_5678_c000` | `0x0000_1234_5678_f000` |
| 64 KiB L2 | `0x0000_1234_4000_0000` | `0x0000_1234_5678_f000` |
| 64 KiB L3 | `0x0000_1234_5678_0000` | `0x0000_1234_5678_f000` |

Reproduction result:

```text
$ host/target/release/vmsa-test test ns-el2 \
    --crate /Users/boden/Documents/aarch64-vmsa --filter smmu. \
    --keep --max-conc 1 --build-conc 1

@@VMSA RUN smmu.v2-stage2-output-normalization
@@VMSA FAIL smmu.v2-stage2-output-normalization reason=wrong-value expected=0 actual=6
```

Full log:
`output/runs/session-00001787932611423625-17873/results.log`.

The adjacent 4 KiB L3 positive control passes because the supplied address is already 4 KiB
aligned. All six cases that require additional normalization fail. Inspection after reproduction
shows the SMMUv2 layout's public `output_address` implementation masks only the descriptor address
field and ignores its `level` argument; the shared VMSA64 layouts normalize by level. That is the
diagnosis, not the test oracle.

Impact: walker and mapper translations of SMMUv2 blocks, plus 16/64 KiB pages whose raw address
contains architecturally ignored low bits, can report a PA base that hardware would not produce.
