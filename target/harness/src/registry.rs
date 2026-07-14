/// Expands the complete logical test registry into a consumer macro.
///
/// Each row is the sole registration point for one logical test: catalog
/// metadata and the handler selected by each fixed environment adapter live
/// together. `none` means architecturally inapplicable for that adapter; an
/// applicable row with no handler is still reported as `adapter-missing` by
/// the runner.
#[doc(hidden)]
#[macro_export]
macro_rules! for_each_registered_test {
    ($consumer:ident) => {
        $consumer! {
            CurrentAccess, "smoke.current-access", entry(ALL_ENVIRONMENTS, Requirements::NONE), (current_access), (current_access), (current_access), (current_access), (current_access);
            CurrentFault, "smoke.current-fault", entry(ALL_ENVIRONMENTS, Requirements::NONE), (current_fault), (current_fault), (current_fault), (current_fault), (current_fault);
            AdapterStateMachine, "smoke.adapter-state-machine", capability_entry(ALL_ENVIRONMENTS, $crate::HarnessCapability::AdapterStateMachine, Requirements::NONE), (smoke::adapter_state_machine), (smoke::adapter_state_machine), (smoke::adapter_state_machine), (smoke::adapter_state_machine), (smoke::adapter_state_machine);
            MatrixCatalog, "smoke.matrix-catalog", capability_entry(NORMAL, $crate::HarnessCapability::AdapterStateMachine, Requirements::NONE), (smoke::matrix_catalog), (none), (none), (none), (none);
            AccessWidths, "smoke.access-widths", entry(NORMAL, Requirements::NONE), (access_widths), (none), (none), (none), (none);
            PairAccess, "smoke.pair-access", entry(NORMAL, Requirements::NONE), (pair_access), (none), (none), (none), (none);
            OrderedAtomicAccess, "smoke.ordered-atomic-access", entry(NORMAL, Requirements::NONE), (ordered_atomic_access), (none), (none), (none), (none);
            AddressTranslation, "smoke.address-translation", entry(NORMAL_SECURE_REALM_ROOT, Requirements::NONE), (address_translation), (address_translation), (address_translation), (address_translation), (address_translation);
            LowerAddressTranslation, "smoke.lower-address-translation", entry(NORMAL, Requirements::NONE), (lower_address_translation), (none), (none), (none), (none);
            GeneratedExecution, "smoke.generated-execution", entry(NORMAL, Requirements::NONE), (generated_execution), (none), (none), (none), (none);
            LiveRangeMapping, "smoke.live-range-mapping", entry(NORMAL, Requirements::NONE), (live_range_mapping), (none), (none), (none), (none);
            MultiPeVisibility, "smoke.multi-pe-visibility", entry(NORMAL, Requirements::NONE), (multi_pe_visibility), (none), (none), (none), (none);
            SemanticCodec, "smoke.semantic-codec", entry(NORMAL, Requirements::NONE), (semantic_codec), (none), (none), (none), (none);
            PasSemantics, "smoke.pas-semantics", entry(SecurityEnvironments::SECURE.union(SecurityEnvironments::REALM), Requirements::NONE), (none), (pas_semantics), (pas_semantics), (pas_semantics), (none);
            PermissionSemantics, "smoke.permission-semantics", entry(NORMAL, Requirements::NONE), (permission_semantics), (none), (none), (none), (none);
            HardwareAccessDirty, "smoke.hardware-access-dirty", entry(NORMAL, Requirements::NONE), (hardware_access_dirty), (none), (none), (none), (none);
            RecursiveTableAccess, "smoke.recursive-table-access", entry(NORMAL, Requirements::NONE), (recursive_table_access), (none), (none), (none), (none);
            AllocationFailure, "smoke.allocation-failure", entry(NORMAL, Requirements::NONE), (allocation_failure), (none), (none), (none), (none);
            LowerAccess, "smoke.lower-access", profile_entry(NORMAL_SECURE.union(SecurityEnvironments::REALM), NON_REC_PROFILES, Requirements::NONE), (lower_access), (lower_access), (lower_access), (none), (none);
            LowerFault, "smoke.lower-fault", profile_entry(NORMAL_SECURE.union(SecurityEnvironments::REALM), NON_REC_PROFILES, Requirements::NONE), (lower_fault), (lower_fault), (lower_fault), (none), (none);
            El0Access, "smoke.el0-access", entry(NORMAL, Requirements::NONE), (el0_access), (none), (none), (none), (none);
            El2El0Access, "smoke.el2-el0-access", entry(NORMAL, Requirements::NONE), (el2_el0_access), (none), (none), (none), (none);
            TranslationCycle, "smoke.translation-cycle", entry(ALL_ENVIRONMENTS, Requirements::NONE), (translation_cycle), (translation_cycle), (translation_cycle), (realm_translation_cycle), (translation_cycle);
            AsidIsolation, "smoke.asid-isolation", entry(NORMAL, Requirements::NONE), (asid_isolation), (none), (none), (none), (none);
            VmidIsolation, "smoke.vmid-isolation", entry(NORMAL, Requirements::NONE), (vmid_isolation), (none), (none), (none), (none);
            CombinedStage1Stage2, "smoke.combined-stage1-stage2", entry(NORMAL, Requirements::NONE), (combined_stage1_stage2), (none), (none), (none), (none);
            Active4KiB, "smoke.active-4k", entry(NORMAL, Requirements::GRANULE_4K), (active_4k), (none), (none), (none), (none);
            Mapper16KiB, "smoke.mapper-16k", entry(NORMAL, Requirements::GRANULE_16K), (mapper_16k), (none), (none), (none), (none);
            Mapper64KiB, "smoke.mapper-64k", entry(NORMAL, Requirements::GRANULE_64K), (mapper_64k), (none), (none), (none), (none);
            Active16KiB, "smoke.active-16k", entry(NORMAL, Requirements::GRANULE_16K), (active_16k), (none), (none), (none), (none);
            Active64KiB, "smoke.active-64k", entry(NORMAL, Requirements::GRANULE_64K), (active_64k), (none), (none), (none), (none);
            ActiveLpa2, "smoke.active-lpa2", entry(NORMAL, Requirements::LPA2), (active_lpa2), (none), (none), (none), (none);
            ActiveD128, "smoke.active-d128", entry(NORMAL, Requirements::D128), (active_d128), (none), (none), (none), (none);
            ActiveD128Stage2, "smoke.active-d128-stage2", entry(NORMAL, Requirements::D128), (active_d128_stage2), (none), (none), (none), (none);
            MalformedDescriptorRecovery, "smoke.malformed-descriptor-recovery", isolated_profile_entry(NORMAL, BootProfiles::ALL, IsolationRequirement::SeparateBoot, false, Requirements::GRANULE_16K), (malformed_descriptor_recovery), (none), (none), (none), (none);
            Lpa2Descriptor, "smoke.lpa2-descriptor", entry(NORMAL_SECURE, Requirements::LPA2), (lpa2_mapper), (lpa2_mapper), (none), (none), (none);
            D128Descriptor, "smoke.d128-descriptor", entry(NORMAL_ROOT, Requirements::D128), (d128_mapper), (none), (none), (none), (d128_mapper);
            LiveStage2, "smoke.live-stage2", isolated_profile_entry(SecurityEnvironments::REALM, BootProfiles::one(BootProfile::RealmRecStage2), IsolationRequirement::Sequential, false, Requirements::RME), (none), (none), (none), (live_stage2), (none);
            RealmFailureInjection, "smoke.realm-failure-injection", isolated_profile_entry(SecurityEnvironments::REALM, BootProfiles::one(BootProfile::RealmRecStage2), IsolationRequirement::Sequential, false, Requirements::RME), (none), (none), (none), (realm_failure_injection), (none);
            D128ReservedRejection, "smoke.d128-reserved-rejection", entry(SecurityEnvironments::ROOT, Requirements::D128), (none), (none), (none), (none), (d128_reserved_rejection);
            D128PermissionIndirection, "smoke.d128-permission-indirection", entry(SecurityEnvironments::ROOT, Requirements::D128), (none), (none), (none), (none), (d128_permission_indirection);
        }
    };
}
