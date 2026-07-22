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
