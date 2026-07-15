use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::exception::VectorGuard;
use crate::registers;

static LOWER_ACTIVE: AtomicBool = AtomicBool::new(false);
static LOWER_RECOVERY: AtomicU64 = AtomicU64::new(0);
static LOWER_RECOVERY_SPSR: AtomicU64 = AtomicU64::new(0);
static LOWER_RETURN_EXCEPTION_CLASS: AtomicU64 = AtomicU64::new(0);
static LOWER_TARGET_EL0: AtomicBool = AtomicBool::new(false);
static HOST_EL0_TRANSLATION_ACTIVE: AtomicBool = AtomicBool::new(false);
static HOST_EL0_TRANSLATION_ADDRESS: AtomicU64 = AtomicU64::new(0);
static HOST_EL0_TRANSLATION_WRITE: AtomicBool = AtomicBool::new(false);
static HOST_EL0_TRANSLATION_RESULT: AtomicU64 = AtomicU64::new(0);
static HOST_EL0_TRANSLATION_COMPLETE: AtomicBool = AtomicBool::new(false);

#[inline(never)]
pub fn runtime_state_address() -> u64 {
    core::ptr::addr_of!(LOWER_ACTIVE) as u64
}

pub fn runtime_code_address() -> u64 {
    vmsa_lower_begin as *const () as u64
}

unsafe extern "C" {
    fn vmsa_enter_lower_el_asm(
        entry: u64,
        stack: u64,
        mailbox: u64,
        spsr: u64,
        stage1: u64,
        target_el0: u64,
        exception_stack: u64,
    ) -> u64;
    fn vmsa_lower_el1_return();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum LowerElStage1Mode {
    Preserve = 0,
    Disable = 1,
    Configured = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum LowerElReturnConduit {
    Hvc = 0,
    Smc = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerElTarget {
    El1,
    El0,
    El2El0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostEl0Translation {
    pub address: u64,
    pub access: crate::translation::TranslationAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerElOutcome {
    Returned,
    HostEl0Translation { par: u64 },
}

impl LowerElReturnConduit {
    pub const fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Hvc),
            1 => Some(Self::Smc),
            _ => None,
        }
    }

    const fn exception_class(self) -> u8 {
        match self {
            Self::Hvc => 0x16,
            Self::Smc => 0x17,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    ArchitecturalState,
    Busy,
    InvalidAddress,
    WrongExceptionLevel,
}

pub fn enter_lower_el(
    entry: u64,
    stack: u64,
    exception_stack: u64,
    mailbox: u64,
    stage1: LowerElStage1Mode,
    return_conduit: LowerElReturnConduit,
    target: LowerElTarget,
    host_el0_translation: Option<HostEl0Translation>,
) -> Result<LowerElOutcome, TransitionError> {
    if registers::current_el() != 2 {
        return Err(TransitionError::WrongExceptionLevel);
    }
    if entry & 0x3 != 0
        || stack & 0xf != 0
        || exception_stack & 0xf != 0
        || entry == 0
        || stack == 0
        || exception_stack == 0
        || mailbox == 0
    {
        return Err(TransitionError::InvalidAddress);
    }
    if host_el0_translation.is_some() && target != LowerElTarget::El2El0 {
        return Err(TransitionError::ArchitecturalState);
    }
    let saved_stage1 = match stage1 {
        LowerElStage1Mode::Preserve => None,
        LowerElStage1Mode::Disable => {
            // SAFETY: The transition exclusively owns EL1 state until the
            // helper returns to EL2 through the selected conduit.
            Some(
                unsafe { registers::disable_el1_stage1() }
                    .ok_or(TransitionError::ArchitecturalState)?,
            )
        }
        LowerElStage1Mode::Configured => None,
    };

    let saved_smc_routing = match return_conduit {
        LowerElReturnConduit::Hvc => None,
        LowerElReturnConduit::Smc => {
            // SAFETY: The transition exclusively owns HCR_EL2 until the helper
            // returns and the captured value is restored below.
            Some(
                unsafe { registers::route_el1_smc_to_el2() }
                    .ok_or(TransitionError::ArchitecturalState)?,
            )
        }
    };

    LOWER_RETURN_EXCEPTION_CLASS.store(
        match target {
            LowerElTarget::El2El0 => 0x15,
            _ => return_conduit.exception_class() as u64,
        },
        Ordering::Release,
    );
    LOWER_TARGET_EL0.store(target == LowerElTarget::El0, Ordering::Release);
    if let Some(request) = host_el0_translation {
        HOST_EL0_TRANSLATION_ADDRESS.store(request.address, Ordering::Release);
        HOST_EL0_TRANSLATION_WRITE.store(
            request.access == crate::translation::TranslationAccess::Write,
            Ordering::Release,
        );
        HOST_EL0_TRANSLATION_RESULT.store(0, Ordering::Release);
        HOST_EL0_TRANSLATION_COMPLETE.store(false, Ordering::Release);
        HOST_EL0_TRANSLATION_ACTIVE.store(true, Ordering::Release);
    }
    let lower_vectors = VectorGuard::install_el1();

    // SAFETY: Addresses were validated; the assembly preserves AAPCS64 callee
    // registers and the EL2 vector handler returns at its recovery label.
    let (spsr, target_el0) = match target {
        LowerElTarget::El1 => (0x3c5, 0),
        LowerElTarget::El0 => (0x3c0, 1),
        LowerElTarget::El2El0 => (0x3c0, 2),
    };
    let status = unsafe {
        vmsa_enter_lower_el_asm(
            entry,
            stack,
            mailbox,
            spsr,
            stage1 as u64,
            target_el0,
            exception_stack,
        )
    };

    LOWER_RETURN_EXCEPTION_CLASS.store(0, Ordering::Release);
    LOWER_TARGET_EL0.store(false, Ordering::Release);
    HOST_EL0_TRANSLATION_ACTIVE.store(false, Ordering::Release);
    drop(lower_vectors);

    let mut restored = true;
    if let Some(state) = saved_smc_routing {
        // SAFETY: The state was captured immediately before this transition on
        // the same PE, and execution has returned to EL2.
        restored &= unsafe { registers::restore_el1_smc_routing(state) };
    }
    if let Some(state) = saved_stage1 {
        // SAFETY: The state was captured immediately before this transition on
        // the same PE, and execution has returned to EL2.
        restored &= unsafe { registers::restore_disabled_el1_stage1(state) };
    }
    if !restored {
        return Err(TransitionError::ArchitecturalState);
    }

    if status != 0 {
        return Err(TransitionError::Busy);
    }
    match host_el0_translation {
        Some(_) if HOST_EL0_TRANSLATION_COMPLETE.swap(false, Ordering::AcqRel) => {
            Ok(LowerElOutcome::HostEl0Translation {
                par: HOST_EL0_TRANSLATION_RESULT.load(Ordering::Acquire),
            })
        }
        Some(_) => Err(TransitionError::ArchitecturalState),
        None => Ok(LowerElOutcome::Returned),
    }
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_begin(recovery: u64, recovery_spsr: u64) -> u64 {
    if recovery == 0 || recovery & 0x3 != 0 {
        return 0;
    }
    if LOWER_RETURN_EXCEPTION_CLASS.load(Ordering::Acquire) == 0 {
        return 0;
    }
    if LOWER_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return 0;
    }
    LOWER_RECOVERY.store(recovery, Ordering::Release);
    LOWER_RECOVERY_SPSR.store(recovery_spsr, Ordering::Release);
    1
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_complete() {
    LOWER_RECOVERY_SPSR.store(0, Ordering::Release);
    LOWER_RECOVERY.store(0, Ordering::Release);
    LOWER_ACTIVE.store(false, Ordering::Release);
}

pub(crate) fn handle_lower_return(exception_class: u8) -> Option<(u64, u64)> {
    if !LOWER_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let expected = LOWER_RETURN_EXCEPTION_CLASS.load(Ordering::Acquire);
    if expected == 0 || expected != exception_class as u64 {
        return None;
    }
    let recovery = LOWER_RECOVERY.load(Ordering::Acquire);
    let recovery_spsr = LOWER_RECOVERY_SPSR.load(Ordering::Acquire);
    if HOST_EL0_TRANSLATION_ACTIVE.load(Ordering::Acquire) {
        let access = if HOST_EL0_TRANSLATION_WRITE.load(Ordering::Acquire) {
            crate::translation::TranslationAccess::Write
        } else {
            crate::translation::TranslationAccess::Read
        };
        let par = crate::translation::active_host_el0_stage1(
            HOST_EL0_TRANSLATION_ADDRESS.load(Ordering::Acquire),
            access,
        )?;
        HOST_EL0_TRANSLATION_RESULT.store(par, Ordering::Release);
        HOST_EL0_TRANSLATION_COMPLETE.store(true, Ordering::Release);
    }
    (recovery != 0).then_some((recovery, recovery_spsr))
}

pub(crate) fn handle_lower_el0_return(exception_class: u8) -> Option<(u64, u64)> {
    if registers::current_el() != 1
        || exception_class != 0x15
        || !LOWER_ACTIVE.load(Ordering::Acquire)
        || !LOWER_TARGET_EL0.load(Ordering::Acquire)
    {
        return None;
    }
    Some((vmsa_lower_el1_return as *const () as u64, 0x3c5))
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_return_conduit() -> u64 {
    match LOWER_RETURN_EXCEPTION_CLASS.load(Ordering::Acquire) {
        0x17 => 1,
        _ => 0,
    }
}
