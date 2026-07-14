# Test-author capability model

This table is the acceptance contract for the stable test-author API. The code
representation is `target/harness/src/matrix.rs`; logical registrations and
their requirements are in `target/harness/src/catalog.rs`.

Matrix enumeration is deterministic and includes boot profile as a
runtime-distinguishing dimension. Exact identity formatting plus applicable,
inapplicable, unsupported, adapter-missing, isolated, and destructive
classification are verified by `smoke.matrix-catalog` in
`ns-el2-00001783974632697437-31100`.

Evidence states are deliberately strict:

- `verified` names a retained FVP artifact.
- `implemented` means a typed API exists, but the required positive, negative,
  restoration, cleanup, and isolation evidence is not yet complete.
- `gap` means an architecturally meaningful adapter path is still absent. It
  must produce `adapter-missing`, never `SKIP`.
- `unsupported` means the selected FVP reports the feature absent.

## Matrix dimensions

| Dimension | Typed values | Minimum evidence | Current state |
|---|---|---|---|
| Security environment | Normal, Secure, Realm, Root | Current access, expected fault, AT/PAR, restoration in each environment | latest full NS evidence `ns-el2-00001783975317518334-13372` (33/33); Secure `secure-el2-00001783946755246056-25048`; Realm EL2 `realm-el2-00001783946801774784-31996`; Root `root-el3-00001783946837346567-22864` |
| Boot profile | NS EL2, Secure EL2, Realm EL2, Realm REC stage 2, Root EL3 | Typed profile filtering and one isolated boot per profile | all profiles boot; the complete applicable REC catalog (5 cases), RMI-owned mutation, and three sequential clean lifecycles pass in `realm-stage2-00001783973852390504-29600` |
| Translation ownership | Current S1, lower S1, EL2 S2, combined S1+S2, REC Realm S2, Root S1 | Active mapping, mutation, fault, exact restore for each owner | current/lower/EL2/root verified; combined independently owns 16 KiB/52-bit LPA2 S1 + ASID and 4 KiB/52-bit D128 S2 + VMID with stage-specific mutation/fault/TLBI and reverse restoration (`ns-el2-00001784002095602554-6956`); REC protected access and restore in `realm-stage2-00001783949184626574-25908`, guarded faults in `realm-stage2-00001783972080430609-31984`, and owned map/protect/unmap/remap restoration in `realm-stage2-00001783973693132319-28616` |
| Execution context | Current EL, EL1, EL0/EL1, EL2&0, Realm REC, secondary PE | Successful access, expected fault, clean return, following-test isolation | non-REC contexts verified in `ns-el2-00001783946524214516-29364`; typed `ExecutionContext::RealmRec` success, return, destruction, lifecycle reuse, and guarded fault normalization verified in `realm-stage2-00001783972080430609-31984` |
| Descriptor format | VMSA64, LPA2, D128 | Active hardware walk, mutation, fault, TLBI, restoration | active walks verified; typed D128 stage-1 PI/AF/dirty mutation passes in `ns-el2-00001783997397100091-28552`; independently owned D128 stage 2, S2PI, mutation, exact faults, IPA TLBI, and restoration pass in `ns-el2-00001784000240914246-628` |
| Granule | 4 KiB, 16 KiB, 64 KiB | Active hardware walk and following-test isolation | verified in NS EL2 |
| PAS | Non-secure, Secure, Realm, Root, firmware-shared, delegated Realm | Owned allocation, access, cleanup, leak check | typed native-PAS allocation and unavailable-PAS rejection pass in all five profiles (`ns-el2-00001783980555850326-24940`, `secure-el2-00001783980587394352-24940`, `realm-el2-00001783980625760427-24940`, `realm-stage2-00001783980654756337-24940`, `root-el3-00001783980733413882-24940`); firmware-shared/delegated pools remain gaps |
| PE requirement | Primary only, secondary required | Bounded start/rendezvous/action/observe/synchronize/stop/cleanup | owned session, drop cleanup, immediate reuse, and explicit stop verified in `ns-el2-00001783946201262618-31004`; timeout recovery breadth incomplete |
| Firmware | None, TF-A Tests, Hafnium, TF-RMM, Trusted Realm Payload | ABI validation and applicable adapter execution | TF-A/Hafnium/TRP/RMM execute the versioned REC adapter; mutation evidence is `realm-stage2-00001783972792306798-29180` |
| Isolation | Sequential, separate boot, destructive boot | Deterministic grouping and later-boot continuation | 31 sequential state-machine-scoped NS cases, including owned affine roots plus lower-EL and secondary transients, verified in `ns-el2-00001783945329114348-22896`; five-profile continuation verified; destructive cases incomplete |
| Termination | Returns, expected model termination | Exact host classification and process-tree cleanup | returning boots verified; expected termination incomplete |

## Translation and inspection capabilities

| Capability | Minimal smoke evidence | Current state |
|---|---|---|
| Create root | Allocate aligned zeroed root, install, reset scope | verified in active-format smokes |
| Map page | Active access through page descriptor | verified: active 4 KiB |
| Map block | Active access through block descriptor | a live L2 block returns exact typed kind/level/output and hardware AT/PAR resolves a nonzero block offset before typed unmap; the surrounding translation cycle restores and passes (`ns-el2-00001783998349282560-17100`) |
| Map range | Exact normalized range/walk results plus cross-page active reads/writes and post-unmap faults | verified through stable API: `smoke.live-range-mapping`, `ns-el2-00001783944671234473-18804` |
| Create intermediate tables | Grow walk and inspect path | verified by active mapping; boundary-growth evidence incomplete |
| Remap | Observe new output after required invalidation; rejected replacement restores old mapping | verified for EL2-owned translation in `ns-el2-00001783944784622771-25432` and RMM-owned REC translation in `realm-stage2-00001783972792306798-29180`; typed TLBI breadth incomplete |
| Protect | Read succeeds, write faults, restore | verified for EL2-owned translation in `ns-el2-00001783944784622771-25432` and REC-owned stage 2 in `realm-stage2-00001783973693132319-28616` |
| Unmap | Translation fault after live unmap | verified in EL2 and REC translation cycles; REC evidence `realm-stage2-00001783972792306798-29180` |
| Translate | Mapper result and hardware AT/PAR agree | verified in NS/Secure/Realm/Root |
| Inspect walk | Exact levels, descriptors, and output | implemented; full formats/levels evidence incomplete |
| Transition sandbox ownership | Dedicated granule-aligned stack/mailbox, independent 4 KiB recovery root, and separate recovery vector remain owned across candidate install and exact restoration | active VMSA64 4/16/64 KiB and LPA2, guarded reads through both fixed 64 KiB sandbox mappings and restored backing (`ns-el2-00001783982349218621-32300`), plus active/recovered VBAR assertions (`ns-el2-00001783987208158616-28172`); exception-driven emergency register restoration remains incomplete |
| MMU-off transition stack | Geometry install/restore selects and probes owned physical backing while translation is disabled, enters the independent recovery root, then selects invariant candidate VA before restoring the original SP | active 16 KiB (`ns-el2-00001783984915342430-30544`) and sequential VMSA64/LPA2 breadth (`ns-el2-00001783984953062935-11552`); current-EL D128 is limited by the selected FVP as recorded below |
| Inspect descriptor | VMSA64/LPA2/D128 typed fields | typed raw/path/output inspection is verified for active VMSA64/LPA2/D128 and dedicated offline 16/64-KiB intermediate-table paths (`ns-el2-00001783998454750321-9168`); generic typed codec inspection returns equal offline/live semantics in `ns-el2-00001783998981063224-6492`; complete active stage-level breadth remains incomplete |
| Break-before-make | Ordered invalidate/mutate/reinstall observation | verified through transactional protect and rollback: `ns-el2-00001783944784622771-25432`; explicit TLBI variants incomplete |
| Install translation | Active hardware observation | verified across current/lower/S2; combined performs a real typed lower-EL load through mixed-format/mixed-granule stages, exact S2 permission/translation faults, live remap, and complete restoration in `ns-el2-00001784002095602554-6956`; public semantic construction is wrapped offline and live and passes encode/install/inspect/decode/restore plus every following NS case in `ns-el2-00001784003436354671-13700` |
| Mutate installed translation | Access changes while installed through stable API with no raw live mapper exposure | verified for VMSA64, AF/HD, execute permissions, reclaim, and recursive tables in `ns-el2-00001783945931510375-27644`; D128 stage-1 evidence is `ns-el2-00001783997397100091-28552`, and D128 stage-2 protect/remap/unmap plus exact S2 faults is `ns-el2-00001784000240914246-628` |
| Restore translation | Exact saved controls and following test | verified in sequential NS, Secure, Realm EL2, Root boots |
| Offline construction | Construct/inspect without installation | verified by mapper-format smokes |
| Raw malformed construction | Explicit affine offline descriptor replacement plus recoverable candidate fault | final-level reserved type encoding faults under an active 16 KiB candidate and restores through the sandbox (`ns-el2-00001783987716834632-12536`); reserved D128 rejection is also verified at Root and typed page/contiguous/root/table allocation injection in `ns-el2-00001783946675570564-25284`; remaining negative-category breadth is tracked in the implementation checklist |

## Access, control, and maintenance capabilities

| Capability | Minimal smoke evidence | Current state |
|---|---|---|
| Byte/half/word/double | Exact values plus alignment faults | verified: `smoke.access-widths` |
| Pair access | Exact two-register read/write | verified: `smoke.pair-access` |
| Ordered access | Acquire/release observation | verified: `smoke.ordered-atomic-access` |
| Atomic access | Swap and exclusive update | verified: `smoke.ordered-atomic-access` |
| Indirect execution | Execute mapped function and return | implemented; dedicated evidence incomplete |
| Generated execution | D-cache clean, I-cache invalidate, execute | verified: `smoke.generated-execution` |
| AT/PAR | Success and fault at current/lower regimes | verified across four security environments; R-EL1 exact IPA semantics before/after S2 unmap in `realm-stage2-00001783973375086139-7320` (combined S1+S2 AT is EL2-only) |
| ASID | Affine independent roots, opaque root IDs, transactional reuse | verified: `smoke.asid-isolation`, `ns-el2-00001783945504078341-16288` |
| VMID | Independent stage-2 identities | verified: `smoke.vmid-isolation` |
| Address widths | Maximum input/output validation and active walk | implemented; boundary evidence incomplete |
| Starting lookup level | Valid growth and invalid-level rejection | implemented; negative evidence incomplete |
| TCR/TCR2 | Typed install and exact restore | active VMSA64/LPA2/D128 verified; failure injection incomplete |
| 64-bit TTBR | Typed install and restore | verified |
| 128-bit TTBR | MRRS/MSRR active walk and restore | verified for TTBR0_EL1 and VTTBR_EL2; D128 S2 evidence `ns-el2-00001784000240914246-628` |
| MAIR/MAIR2 | Typed semantic attribute slots and exact restore | D128 slot 8 is encoded through `Stage1MemoryControls`, read by active lower-EL hardware, and MAIR2 is restored transactionally (`ns-el2-00001784006041086405-28536`) |
| HA/HD | Hardware updates reflected in descriptor | verified: `smoke.hardware-access-dirty` |
| Permission indirection | D128 PI decode and active RX/RW separation | verified: active D128 and Root PI smoke |
| Permission overlay | Typed encode/decode and active permission result | implemented; active evidence incomplete |
| Stage-2 memory controls | Typed VTCR/HCR and effective attributes | combined mode, every FWB encoding, MTE-gated encodings, and exact wrong-mode errors pass through the stable semantic mapper (`ns-el2-00001784005229606967-31968`) |
| Shareability/cacheability | Semantic construction/decode plus coherent access | source-reviewed semantic coverage is complete; active VMSA64 and D128 mappings exercise configured MAIR/MAIR2 values |
| Typed TLBI | VA/IPA/ASID/VMID/range/local/broadcast/combined | gap: architecture helpers exist but stable complete API/evidence does not |
| Cache maintenance | I/D coherence, table visibility, multi-PE visibility | generated execution verified; complete typed API/evidence incomplete |

## Fault and recovery capabilities

| Capability | Minimal smoke evidence | Current state |
|---|---|---|
| Normalized fault | Exact class/status/access/stage/level/FAR/IPA | translation, permission, address-size, alignment, and Realm GPC paths implemented; full matrix incomplete |
| Exact fault matcher | Typed semantic fields plus optional exact class/FAR/IPA | two architectural alignment faults match DataAbort/write/stage1/exact FAR/no IPA (`ns-el2-00001783978422394930-4152`); internal FSC table breadth passes in `ns-el2-00001783978317494410-13588` |
| Guarded expected fault | Returns `AccessResult::Fault` and next test passes | verified across NS/Secure/Realm/Root |
| Unexpected exception | Harness failure, artifact retention, boot stop | verified during bring-up; deliberate final smoke incomplete |
| Transition sandbox | Candidate-independent code/stack/mailbox/vector and emergency restore | independently owned recovery root, stack, mailbox, and vector are active across candidate VMSA64 4/16/64 KiB and LPA2 state; a malformed 16 KiB candidate abort is normalized and restored (`ns-el2-00001783987716834632-12536`); exception-driven emergency register restoration and the remaining destructive breadth remain gaps |
| Emergency restoration | Runner restores independently of explicit restoration | injected explicit-restoration failure is recovered by the consumed guard's independent Drop path, followed by a fresh install/restore (`ns-el2-00001783975922598639-28636`); runner-level emergency-injection breadth remains incomplete |
| Secondary cleanup recovery | Explicit shutdown failure cannot strand a PE | injected shutdown is recovered by session Drop, followed by a fresh rendezvous/access/stop (`ns-el2-00001783975922598639-28636`) |
| Partial table-growth recovery | Intermediate allocation failure leaves no false leaf and permits retry | one intermediate allocation succeeds, the next fails, the same root translates as unmapped and then accepts an exactly inspected retry (`ns-el2-00001783976041570614-1516`) |
| Range-map failure recovery | Typed map injection is atomic at the range boundary | injected range is entirely absent, then the reset path maps/accesses/unmaps all pages (`ns-el2-00001783976189280484-23896`) |
| Typed TLBI selection | VA/IPA/ASID/VMID and local/inner-shareable requests cannot target the wrong regime or identifier | stage-1 cycle, EL1 ASID isolation, and stage-2 VMID isolation pass sequentially with negative checks (`ns-el2-00001783976472815860-30080`; 33/33) |
| Combined TLBI | Combined guard routes stage-specific invalidations and orders whole invalidation stage 2 before stage 1 | wrong-stage negative plus local VA, ASID, IPA, VMID, and whole-combined operations (`ns-el2-00001783976594057704-31940`) |
| Cache maintenance | Typed instruction coherency, data clean/invalidate, table visibility, and multi-PE visibility | generated execution and mutation pass after the complete maintenance sequence (`ns-el2-00001783978044754521-29568`); secondary PE observes published data/table state and cleans up (`ns-el2-00001783978121542138-21608`) |
| Typed walk path | Live/offline inspection returns bounded level/index/kind/raw/next/output steps | effective L1→L2→L3 VMSA64 page path and exact PA (`ns-el2-00001783977180855032-21060`) |
| Format/granule walk inspection | Offline path inspection precedes active hardware installation | all five formats/geometries inspect/access/restore; VMSA64 4/16/64 KiB and LPA2 additionally inspect through candidate-active table access (`ns-el2-00001783977755338883-3004`), while lower-EL D128 candidate-context inspection awaits the independent sandbox |
| Corrupted state | Stop later tests in boot and preserve independent boots | implemented at runner outcome level; explicit adapter state machine gap |

## Resource and infrastructure capabilities

| Capability | Minimal smoke evidence | Current state |
|---|---|---|
| Memory scope | Alignment, zeroing, overlap prevention, reset, leak detection | basic allocation/reset verified; misuse/boundary breadth incomplete |
| Arena capacity | Maximum contiguous allocation, exact exhaustion, scope recovery | exact remaining capacity is consumed and the next page reports exhaustion; all following NS cases pass after reset (`ns-el2-00001783978915286853-6096`; 33/33) |
| Table growth boundary | Range crosses into another leaf table with exact allocation/path evidence | two new L3 tables, distinct walk frames, active access/unmap/fault/restore (`ns-el2-00001783979422982268-24956`) |
| Protocol boundaries | Bounded process lines, protocol records, names, and filters | 64 KiB process, 512-byte protocol, 128-byte name/filter limits; strict doctor passes oversized-line/name rejection and a 129-byte filter exits 7 before execution |
| Checkout compatibility | Exact read-only local source or retained build error | incompatible virtual manifest is retained and classified `build-error`, exit 2, before FVP (`ns-el2-00001783979109341238-29528`); provenance records `ro=true` source mount |
| Crate selection | Required canonical local checkout or explicit default clone | cwd-independent doctor passes from `C:\`; `--crate default` cloned revision `ab20bfa19aa275c15fedb8949746207c660f6622` and doctor passed |
| PAS ownership | NS/Secure/Realm/Root/shared/delegated ownership transitions | `PhysicalAddressSpace`-checked native allocation and negative unavailable-PAS evidence pass in every profile; shared/delegated allocation transitions remain gaps |
| Secondary PE | Bounded session and timeout cleanup | owned start/rendezvous/action/observe/synchronize/stop session verified; timeout recovery breadth incomplete |
| Realm lifecycle | delegate/create RTT/map/create REC/enter/destroy/undelegate | three TFTF/TF-RMM-owned lifecycles finish before protocol publication; typed protected access, unprotected mutation, guarded faults, invalid ABI rejection, and valid reuse are verified in `realm-stage2-00001783972792306798-29180`; permission mutation and injected lifecycle failures remain gaps |
| Failure injection | Scoped injection and automatic reset for every boundary | allocation categories verified in `ns-el2-00001783946675570564-25284`; map/remap/protect/unmap in `ns-el2-00001783975056122743-17168`; installation in `ns-el2-00001783975156912882-31372`; partial combined in `ns-el2-00001783975256046403-28288`; lower entry and secondary startup in `ns-el2-00001783975420926692-3348` and `ns-el2-00001783975460167046-4652`; remaining firmware/REC/cleanup boundaries are gaps |
| ABI validation | Version, size, alignment, required fields, reserved fields | boot ABI v3 negative validation passes in all five firmware profiles (`ns-el2-00001783978618900443-27772`, `secure-el2-00001783978648300108-27772`, `realm-el2-00001783978686090435-27772`, `realm-stage2-00001783978715510310-27772`, `root-el3-00001783978795036058-27772`); Realm/REC ABI v2 mismatch, cleanup, records, and reuse pass in `realm-stage2-00001783972792306798-29180` |
| Adapter state machine | Reject invalid transitions and enter Corrupted on unprovable restore | every named state is explicit; nested-scope rejection and state preservation pass across all five adapters in the `00001783974167197970` through `00001783974355539128` retained runs; injected corrupted recovery evidence remains incomplete |
| Boot isolation | Compatible grouping and independent continuation | five-profile sequential host execution verified; destructive breadth incomplete |
| Process cleanup | cancellation, timeout, END/exit races, tree termination | timeout termination verified; cancellation/partial-build breadth incomplete |
| Reproducibility | revisions/state, image, firmware, FVP, host, profile, capabilities, commands | verified: `root-el3-00001783943004054360-14692/provenance.txt` |

## Completion gate

No row marked `gap` may remain. An `implemented` row becomes `verified` only
after its positive, negative, exact-result, restoration, cleanup, isolation,
applicable-environment, and applicable-boot evidence is retained. FVP absence is
reported as `unsupported`; an applicable missing adapter always fails the
harness.
