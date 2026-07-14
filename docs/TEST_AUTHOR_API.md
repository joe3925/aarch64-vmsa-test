# Test-author API

This guide describes the stable, high-level surface available to guest test
logic. Firmware adapters use the rustdoc-hidden `adapter` module; tests must not.
Every allocation and installed translation is scoped to the current test. Drop
performs normal cleanup and the runner independently invokes emergency restore
before resetting the memory scope.

The examples use the payload's `CurrentEnvironment`, `CurrentRegime`, and (where
applicable) `Stage2Regime` aliases. They never access exception records, system
registers, firmware callbacks, UART, or frame-provider internals.

## PAS-appropriate memory

```rust
let pas = context.native_pas();
let page = context.allocate_page_in(pas)?;
let run = context.allocate_contiguous_in(pas, 4)?;
let aligned_16k = context.allocate_granule(vmsa_test_harness::Granule::Size16KiB)?;
let root = context.allocate_root_in(pas, vmsa_test_harness::Granule::Size4KiB)?;
```

Requesting a PAS that the active adapter does not own returns
`HarnessError::InvalidState` before the arena is changed. Firmware-shared and
delegated-Realm pools are not yet exposed and remain completion gaps.

## Offline construction and live stage 1

Offline construction is deliberately separate from installation:

```rust
use aarch64_vmsa::address::Granule4KiB;
use aarch64_vmsa::descriptor::Vmsa64;
use vmsa_test_harness::{
    AddressBits, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
    RegimeAttributes, TranslationFormat, TranslationSetup, TranslationStage,
    vmsa64_el2_stage1_controls,
};

const VA: u64 = 0x6000_0000;
let page = context.allocate_page()?;
let mut root = context.allocate_root()?;
let input = AddressBits::new(39).ok_or(HarnessError::InvalidState)?;
let output = AddressBits::new(48).ok_or(HarnessError::InvalidState)?;
let level = vmsa_test_harness::stage1_start_level(
    TranslationFormat::Vmsa64,
    Granule::Size4KiB,
    input,
).ok_or(HarnessError::InvalidState)?;

{
    let mut mapper = context.offline_mapper_for_format_with_geometry::<
        CurrentRegime,
        Granule4KiB,
        Vmsa64,
    >(
        &mut root,
        aarch64_vmsa::address::Level::L1,
        input.get(),
        output.get(),
    )?;
    mapper.map_page(VA, page.phys_addr())?;
}

let root_address = PhysicalAddress::new(root.phys_addr());
let mut live = context.install_owned(
    root,
    TranslationSetup {
        root: root_address,
        stage: TranslationStage::Stage1,
        granule: Granule::Size4KiB,
        format: TranslationFormat::Vmsa64,
        input_bits: input,
        output_bits: output,
        start_level: Some(level),
        asid: None,
        vmid: None,
        controls: vmsa64_el2_stage1_controls(Granule::Size4KiB, input, output)
            .ok_or(HarnessError::InvalidState)?,
        regime: RegimeAttributes::Normal,
    },
)?;
```

The concrete control helper must match the adapter's owning EL. Typed builders
for every format/regime are still being completed; tests must not synthesize raw
TCR bits as a workaround.

When a test is about architectural attributes, construct the crate's semantic
leaf/table values and call `TestMapper::map_semantic_leaf`. The corresponding
installed operation is `LiveTranslation::map_semantic_for`; both accept the
typed codec/config and never expose raw descriptor bits. Use
`inspect_semantic_leaf` or `inspect_semantic_for` to compare the effective
decoded value.

Semantic construction and inspection preserve crate attribute failures as the
closed harness `AttributeError` enum. Tests can therefore match, for example,
`HarnessError::Attribute(AttributeError::MemoryAttributeNotConfigured)` without
depending on crate internals or raw descriptor encodings.

## Live mutation, BBM, TLBI, and inspection

```rust
let walk = live.inspect_walk::<Vmsa64, Granule4KiB>(VA)?;
let descriptor = walk.leaf().ok_or(HarnessError::InvalidState)?;
let mapping = live.inspect::<Vmsa64, Granule4KiB>(VA)?
    .ok_or(HarnessError::InvalidState)?;
let semantic = live.inspect_semantic_for::<
    CurrentRegime,
    Vmsa64,
    Granule4KiB,
    aarch64_vmsa::attrs::VmsaAttributeCodec,
    _,
>(VA, &live_vmsa_config)?
    .ok_or(HarnessError::InvalidState)?;

live.protect::<Vmsa64, Granule4KiB>(VA, MappingAttributes::READ_ONLY)?;
live.break_before_make::<Vmsa64, Granule4KiB>(
    VA,
    Some(page.phys_addr()),
    MappingAttributes::READ_WRITE,
)?;
live.tlbi_scoped(
    vmsa_test_harness::TlbiScope::InnerShareable,
    vmsa_test_harness::TlbiOperation::VirtualAddress(VA),
)?;
let old = live.unmap_reclaim::<Vmsa64, Granule4KiB>(VA)?;
```

For a live translation owned by a regime other than the adapter's current
regime, use the regime-explicit variants. The owned root and restoration duty
remain unchanged while the descriptor stage is selected at compile time:

```rust
let walk = live.inspect_walk_for::<LowerRegime, Vmsa128, Granule4KiB>(VA)?;
let state = live.inspect_d128_hardware_updates_for::<LowerRegime>(VA)?;
live.protect_d128_stage1_for::<LowerRegime>(
    VA,
    D128MappingPermissions::ReadExecute,
)?;
live.remap_d128_stage1_for::<LowerRegime>(
    VA,
    replacement.phys_addr(),
    D128MappingPermissions::ReadWrite,
)?;
let old = live.unmap_for::<LowerRegime, Vmsa128, Granule4KiB>(VA)?;
live.tlbi(TlbiOperation::VirtualAddress(VA))?;
```

For D128 stage 2, construct the root with
`offline_mapper_for_format_with_geometry::<Stage2Regime, Granule4KiB, Vmsa128>`,
select `d128_stage2_controls_4k`, and install it as the stage-2 half of an owned
combined translation. Live permission changes and remaps remain typed:

```rust
combined.stage2_mut()?.protect_d128_stage2_for::<Stage2Regime>(
    IPA,
    MappingAttributes::READ_ONLY,
)?;
combined.stage2_mut()?.remap_d128_stage2_for::<Stage2Regime>(
    IPA,
    replacement.phys_addr(),
    MappingAttributes::READ_WRITE,
)?;
combined.tlbi(
    TlbiScope::InnerShareable,
    CombinedTlbiOperation::Stage2(TlbiOperation::IntermediatePhysicalAddress(IPA)),
)?;
```

`remap`, `protect`, and `break_before_make` own the invalidation/barrier sequence
and roll back a failed replacement. `WalkInspection` and
`WalkDescriptorInspection` contain normalized paths, descriptor kinds, outputs,
and raw bits for isolated observation; semantic inspection returns the crate's
typed codec result directly. Callers do not decode raw fields or dereference
table frames.

## Stage 2 and combined translation

Stage-2 construction uses `Stage2Regime`, `TranslationStage::Stage2`, a VMID,
and the typed stage-2 control helper. It is installed with `install_owned`.
Combined translation installs lower stage 1 first and stage 2 second as one
transaction. Roots, formats, granules, widths, ASID, and VMID are independent.
The active mixed-geometry pattern uses an LPA2 16 KiB/52-bit lower-stage root
and a D128 4 KiB/52-bit stage-2 root; the adapter owns the dedicated aligned
lower stack and reverse-order restoration:

```rust
let mut combined = context.install_combined_owned(
    stage1_root,
    stage1_setup,
    stage2_root,
    stage2_setup,
)?;

let observation = combined.read_u64(VA);
let query = combined.translate(VA, TranslationQueryAccess::Read);
combined.stage1_mut()?.protect_for::<LowerRegime, Vmsa64, Granule4KiB>(
    VA,
    MappingAttributes::READ_ONLY,
)?;
combined.tlbi(
    vmsa_test_harness::TlbiScope::InnerShareable,
    vmsa_test_harness::CombinedTlbiOperation::All,
)?;
combined.restore()?;
```

Use `stage1_mut` and `stage2_mut` for stage-specific mutation or inspection.
Never install either stage separately when the test requires transactional
combined state.

## Execution contexts

```rust
let mut execution = context.execution(vmsa_test_harness::ExecutionContext::El1)?;
let result = execution.read_u64(VA);
let translation = execution.translate(VA, TranslationQueryAccess::Read);
let ordered = execution.read_acquire_u64(VA);
let old = execution.atomic_swap_u64(VA, 7);
let pair = execution.read_pair_u64(VA);
execution.finish()?;
```

The same API selects current EL, EL1, EL0 under EL1, EL2&0, Realm REC, or the
secondary PE when applicable. Entry, SPSR/ELR, stacks, HCR, vectors, return
conduits, and recovery state remain adapter-owned.

## Secondary PE

```rust
let mut secondary = context.secondary_pe_session()?;
let result = secondary.read_u64(VA);
secondary.stop()?;
```

The session enforces rendezvous/action/observe/synchronize/stop states. Drop
attempts stop if the explicit call is skipped, and the runner treats failed
cleanup as boot corruption.

## Realm REC-owned stage 2

```rust
let mut realm = context.realm_rec_stage2()?;
realm.map()?;
let ipa = realm.input_address();
let mut rec = context.execution(vmsa_test_harness::ExecutionContext::RealmRec)?;
let result = rec.read_u64(ipa);
rec.finish()?;
realm.protect_read_only()?;
realm.unmap()?;
realm.finish()?;
```

TF-RMM owns delegation, Realm/RTT/REC creation, entry, destruction, and
undelegation. Test logic sees only the bounded session.

## Exact normalized faults

```rust
let expected = vmsa_test_harness::ExpectedFault {
    status: Some(vmsa_test_harness::FaultStatus::Permission),
    access: Some(vmsa_test_harness::AccessKind::Write),
    stage: Some(vmsa_test_harness::FaultStage::Stage1),
    level: None,
};
let matcher = vmsa_test_harness::FaultMatcher::new(expected)
    .with_class(vmsa_test_harness::FaultClass::DataAbort)
    .at_address(VA)
    .with_ipa(None);
return vmsa_test_harness::expect_matching_fault(result, matcher);
```

Fault matching covers class, status, access, stage, level, FAR, and optional IPA
without exposing ESR/HPFAR decoding.

## Matrix requirements and boot isolation

Each catalog entry owns a `MatrixRequirements` value. Set environments,
ownership, contexts, formats, granules, capability/PAS/PE/firmware requirements,
boot geometry, isolation, and expected model termination there. Applicability is
architectural; a supported applicable case with no adapter handler is a harness
failure, not a skip.

Add one row to `target/harness/src/registry.rs`. The row names the logical test,
its typed catalog builder and requirements, and the handler (or `none`) for each
fixed adapter. The declarative registry generates `LogicalTest`, `TEST_CATALOG`,
and every exhaustive payload dispatch. No payload registration, firmware path,
host configuration, or runtime discovery entry is added separately.

A normal sequential test uses `entry(...)`. Cases requiring a fixed profile,
separate boot, or expected model termination use `isolated_profile_entry(...)`
with `IsolationRequirement::SeparateBoot` or
`IsolationRequirement::Destructive`. The one registry row remains the only
registration regardless of isolation:

```rust
ExampleCase, "smoke.example-case",
isolated_profile_entry(
    SecurityEnvironments::NORMAL,
    BootProfiles::one(BootProfile::NsEl2),
    IsolationRequirement::SeparateBoot,
    false,
    Requirements::LPA2,
),
(smoke::example_case), (none), (none), (none), (none);
```

`none` is explicit architectural inapplicability for that adapter. If the
matrix says the case applies but the selected adapter has no handler, the
runner reports `adapter-missing`, corrupts that boot, and stops its later cases.

## Isolated malformed tables

Malformed descriptors are constructed only through the explicit affine negative-
test surface, before the table is installed:

```rust
use vmsa_test_harness::DescriptorBits;

let walk = mapper.inspect_walk(VA)?;
let leaf = walk.leaf().ok_or(HarnessError::InvalidState)?;
let mut reserved_type = leaf.raw.ok_or(HarnessError::InvalidState)?;
reserved_type.low &= !0b10;

let original = mapper
    .isolated_malformed_table()
    .replace_terminal_descriptor(VA, reserved_type)?;
if Some(original) != leaf.raw {
    return Err(HarnessError::InvalidState);
}
```

`IsolatedMalformedTable` exposes neither table pointers nor frame allocation,
translation registers, exception state, or cleanup. The owning environment
installs this candidate through `TransitionSandbox`, converts an expected abort
to a normalized `AccessResult::Fault`, restores the original translation and
vector state, and invokes runner-level emergency restoration before the next
test. Tests must not write table memory or handle exceptions directly.
