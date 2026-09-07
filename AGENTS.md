# AGENTS.md

## General Rules

* Treat `/Users/boden/Documents/aarch64-vmsa` as strictly read-only. Never patch, format, test inside, or write build artifacts into it.
* Exercise only public `aarch64-vmsa` behavior. Harness code may provide setup, execution, observation, fault capture, and cleanup, but must never duplicate crate logic as an oracle.
* Derive expectations from architectural constants, explicit test inputs, public crate errors, or independent hardware/FVP observations.
* Fix missing or broken behavior in the general harness abstraction. Never add case-specific bypasses, weaken assertions, or special-case a failing test.
* Keep tests independently named and isolated. One failure must not suppress unrelated cases. Destructive or model-terminating cases must run in separate boots.
* Restore all modified architectural state. Treat restoration, cleanup, isolation, timeout, ABI, profile, and capability-routing defects as harness failures.
* A crate failure requires independent evidence against public crate behavior. Keep the test enabled and failing, and append the full evidence to `crate_report.md`. Never modify the crate to make the harness pass.
* `Unsupported` is valid only when live architectural feature registers report the capability absent after all required model and firmware configuration has been attempted.
* Never hide, skip, reinterpret, or downgrade an untriaged failure.
* Add coherent batches before compiling or booting. After a harness fix, rerun the affected batch and every impacted profile.
* Run FVP test commands with `--build-conc 5 --max-conc 14` unless the user explicitly requests different concurrency settings.
* Run validators, doctor, and the complete suite before declaring completion. Run the full suite again in a fresh invocation to detect retained-state or ordering bugs.
* Verify the tested crate checkout remains unchanged.
  :::

## Failure Ownership and Required Action

* A **harness failure** is any failure caused by the test infrastructure rather than public `aarch64-vmsa` behavior. This includes incorrect setup or expectations, broken execution or observation, fault-capture and exception-handler defects, missing mappings, ABI or profile mistakes, state leakage, cleanup or restoration defects, capability-routing errors, and harness timeouts or isolation failures. Fix harness failures immediately in the general harness abstraction unless the user explicitly directs otherwise. Do not add them to `crate_report.md`, weaken assertions, or introduce case-specific bypasses. Rerun the affected batch and every impacted profile after the fix.
* A **crate failure** is a reproducible defect in the public behavior of `aarch64-vmsa`, established using an independent architectural constant, explicit test input, public crate error, or hardware/FVP observation rather than duplicated crate logic. Keep the failing test enabled, do not modify the read-only crate, preserve the complete evidence, and add the failure to `crate_report.md`. If ownership is not yet proven, keep it as an untriaged failure rather than labeling it a crate failure.

## Runtime Hang and Watchdog Debugging Tips

* Treat a watchdog timeout as a likely recursive exception: the original fault may be followed by another fault in the vector, stack, or reporting path.
* Reproduce the smallest filtered launch first before widening back to the complete profile.
* With Iris, stop at the exception vector and inspect `ESR_EL2`, `FAR_EL2`, `ELR_EL2`, `SPSR_EL2`, `VBAR_EL2`, the active stack pointers, and the EL2 translation registers. Walk the mappings for the faulting PC, FAR, vector, and exception stack.
* Compare state immediately before an exception-level or VHE mode transition with state at the vector to separate a bad mapping from transition corruption.
* Verify that vectors, exception stacks, runtime/linkage data, and fatal-report callbacks have the intended permissions. Keep page-table frames privileged even when command-owned EL0 data must be writable.
* Make translation-control changes transactionally, including the required barriers and invalidation, and restore the original state symmetrically.
* After a generic harness fix, rerun the affected launch family and then a fresh profile invocation to catch retained-state and ordering problems.

## Registered Test Contract

* This harness exists only to verify public crate behavior against FVP or real architectural hardware behavior. It must contain zero registered unit-test-style tests. Every registered test must execute an architectural operation and use its independently observed result in the pass/fail decision.
* Every registered test must prove public crate behavior through an independent architectural observation made by the PE, SMMU, or FVP. Valid oracles are completed accesses, returned values, execution results, architectural translation results, faults and syndromes, and translation or invalidation effects observed by a later hardware operation.
* Never register a test that can pass without its FVP or hardware operation running. Comparing two software values, checking a crate return value, inspecting crate-generated table memory, or successfully completing setup is never sufficient for a pass.
* The crate may build, update, protect, remap, unmap, or reclaim the tables used to set up a test. Mapper results, crate walkers, semantic decoders, geometry calculations, software reference models, and a second harness implementation of crate logic must never decide whether a registered test passes.
* A setup, installation, invalidation, restoration, or cleanup error is a harness/infrastructure failure. Do not turn an infrastructure error into evidence that the crate produced an architecturally incorrect descriptor.
* Test architectural SKL behavior by having hardware walk deliberately skipped levels and observing the resulting translation or fault. Do not test which SKL planning policy the crate selected or compare the resulting software table shape with a harness oracle.
* Only test descriptor fields when changing the field has an architecturally required and independently observable effect. Do not register tests whose only evidence is the encoded value of software metadata, cache allocation hints, contiguous hints, BBM `NT`, or other implementation-permitted hints.
* Treat every SMMUv3 regime combined with `Vmsa128` as not live-testable until a model with a working SMMUv3 D128 translation path exists. Do not register semantic, walker, or raw-descriptor comparisons as substitutes for missing SMMUv3 D128 hardware behavior.
* Keep each architectural matrix coordinate independently named so a failure in one format, granule, stage, regime, level, SKL value, permission, PAS, or invalidation scope does not suppress another coordinate.
