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
* Preserve provenance and failure artifacts, and verify the tested crate checkout remains unchanged.
  :::
