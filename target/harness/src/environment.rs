use crate::access::AccessRequest;
use crate::lower_el::LowerElRequest;
use crate::memory::TestMemory;
use crate::report::ReportEvent;
use crate::translation::{InstalledTranslation, TransitionStack};
use crate::{
    AccessResult, Asid, Capabilities, HarnessError, PhysicalAddress, RealmStage2Mutation,
    RealmStage2Region, TranslationSetup,
};

pub trait Environment {
    type Error;

    fn error_code(error: &Self::Error) -> u64;

    fn begin_test_scope(&mut self) -> Result<(), Self::Error>;
    fn end_test_scope(&mut self) -> Result<(), Self::Error>;
    fn mark_corrupted(&mut self);
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn capabilities(&self) -> Capabilities;
    fn memory_pas(&self) -> crate::PhysicalAddressSpace;
    fn transition_runtime_data(&self) -> [u64; 4];
    fn memory(&mut self) -> &mut TestMemory;
    fn allocate_page_in(
        &mut self,
        pas: crate::PhysicalAddressSpace,
    ) -> Result<crate::Page, HarnessError> {
        if pas != self.memory_pas() {
            return Err(HarnessError::InvalidState);
        }
        self.memory()
            .allocate_page()
            .map_err(|_| HarnessError::Memory)
    }
    fn install_translation(
        &mut self,
        setup: TranslationSetup,
        transition_stack: Option<TransitionStack>,
    ) -> Result<InstalledTranslation, Self::Error>;

    fn install_lower_translation(
        &mut self,
        setup: TranslationSetup,
    ) -> Result<InstalledTranslation, Self::Error>;
    fn switch_lower_stage1_root(
        &mut self,
        installed: InstalledTranslation,
        root: PhysicalAddress,
        asid: Asid,
    ) -> Result<InstalledTranslation, Self::Error>;
    fn perform_access(&mut self, request: AccessRequest) -> AccessResult;
    fn realm_rec_is_current(&self) -> bool {
        false
    }
    fn verify_invalid_transition_rejected(&mut self) -> bool;
    fn verify_common_abi_rejection(&self) -> bool;
    fn begin_realm_stage2_session(&mut self) -> Result<RealmStage2Region, HarnessError> {
        Err(HarnessError::Environment)
    }
    fn mutate_realm_stage2(&mut self, _mutation: RealmStage2Mutation) -> Result<(), HarnessError> {
        Err(HarnessError::Environment)
    }
    fn end_realm_stage2_session(&mut self) -> Result<(), HarnessError> {
        Err(HarnessError::Environment)
    }
    fn begin_secondary_session(&mut self) -> Result<(), Self::Error>;
    fn perform_secondary_access(&mut self, request: AccessRequest) -> AccessResult;
    fn end_secondary_session(&mut self) -> Result<(), Self::Error>;
    fn run_lower_el(&mut self, request: LowerElRequest) -> AccessResult;
    fn restore_translation(&mut self, installed: InstalledTranslation) -> Result<(), Self::Error>;
    fn emergency_restore(&mut self);
    fn report(&mut self, event: ReportEvent);
}

pub trait TranslationRegimeEnvironment: Environment {
    type Regime: crate::translation::TestRegime;
}
