use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::exception::{RawFault, VectorGuard};
use crate::registers;

const EXCEPTION_CLASS_SVC_AARCH64: u8 = 0x15;
const EXCEPTION_CLASS_HVC_AARCH64: u8 = 0x16;
const EXCEPTION_CLASS_SMC_AARCH64: u8 = 0x17;
const EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER: u8 = 0x20;
const EXCEPTION_CLASS_INSTRUCTION_ABORT_CURRENT: u8 = 0x21;
const EXCEPTION_CLASS_DATA_ABORT_LOWER: u8 = 0x24;
const EXCEPTION_CLASS_DATA_ABORT_CURRENT: u8 = 0x25;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LowerPhase {
    Idle = 0,
    Prepared = 1,
    Active = 2,
    Bridging = 3,
    Returning = 4,
}

struct FaultSlot(UnsafeCell<Option<RawFault>>);

unsafe impl Sync for FaultSlot {}

#[repr(C)]
struct LowerRuntimeState {
    phase: AtomicU64,
    recovery: AtomicU64,
    recovery_spsr: AtomicU64,
    return_exception_class: AtomicU64,
    target: AtomicU64,
    fault: FaultSlot,
    fault_valid: AtomicBool,
}

impl LowerRuntimeState {
    const fn new() -> Self {
        Self {
            phase: AtomicU64::new(LowerPhase::Idle as u64),
            recovery: AtomicU64::new(0),
            recovery_spsr: AtomicU64::new(0),
            return_exception_class: AtomicU64::new(0),
            target: AtomicU64::new(LowerElTarget::El1 as u64),
            fault: FaultSlot(UnsafeCell::new(None)),
            fault_valid: AtomicBool::new(false),
        }
    }

    fn prepare(
        &self,
        return_exception_class: u8,
        target: LowerElTarget,
    ) -> Result<(), TransitionError> {
        if self
            .phase
            .compare_exchange(
                LowerPhase::Idle as u64,
                LowerPhase::Prepared as u64,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(TransitionError::Busy);
        }
        self.recovery.store(0, Ordering::Release);
        self.recovery_spsr.store(0, Ordering::Release);
        self.return_exception_class
            .store(return_exception_class as u64, Ordering::Release);
        self.target.store(target as u64, Ordering::Release);
        self.fault_valid.store(false, Ordering::Release);
        unsafe { *self.fault.0.get() = None };
        Ok(())
    }

    fn reset(&self) {
        self.recovery.store(0, Ordering::Release);
        self.recovery_spsr.store(0, Ordering::Release);
        self.return_exception_class.store(0, Ordering::Release);
        self.target
            .store(LowerElTarget::El1 as u64, Ordering::Release);
        self.fault_valid.store(false, Ordering::Release);
        unsafe { *self.fault.0.get() = None };
        self.phase
            .store(LowerPhase::Idle as u64, Ordering::Release);
    }

    fn phase(&self) -> u64 {
        self.phase.load(Ordering::Acquire)
    }

    fn is_active(&self) -> bool {
        self.phase() == LowerPhase::Active as u64
    }

    fn begin_bridge(&self) -> bool {
        self.phase
            .compare_exchange(
                LowerPhase::Active as u64,
                LowerPhase::Bridging as u64,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn begin_return(&self) -> bool {
        let phase = self.phase.load(Ordering::Acquire);
        if phase != LowerPhase::Active as u64 && phase != LowerPhase::Bridging as u64 {
            return false;
        }
        self.phase
            .compare_exchange(
                phase,
                LowerPhase::Returning as u64,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn record_fault(&self, fault: RawFault) {
        unsafe { *self.fault.0.get() = Some(fault) };
        self.fault_valid.store(true, Ordering::Release);
    }

    fn take_fault(&self) -> Option<RawFault> {
        if !self.fault_valid.swap(false, Ordering::AcqRel) {
            return None;
        }
        unsafe { (*self.fault.0.get()).take() }
    }

    fn target(&self) -> LowerElTarget {
        LowerElTarget::from_raw(self.target.load(Ordering::Acquire))
            .unwrap_or(LowerElTarget::El1)
    }

    fn return_conduit(&self) -> LowerElReturnConduit {
        match self.return_exception_class.load(Ordering::Acquire) as u8 {
            EXCEPTION_CLASS_SMC_AARCH64 => LowerElReturnConduit::Smc,
            _ => LowerElReturnConduit::Hvc,
        }
    }
}

#[repr(C, align(4096))]
struct LowerRuntimeStorage(LowerRuntimeState);

const _: () = assert!(core::mem::size_of::<LowerRuntimeStorage>() == 4096);

#[unsafe(link_section = ".data.vmsa_lower_runtime_state")]
static LOWER_RUNTIME_STATE: LowerRuntimeStorage = LowerRuntimeStorage(LowerRuntimeState::new());

#[inline(never)]
pub fn runtime_state_address() -> u64 {
    core::ptr::addr_of!(LOWER_RUNTIME_STATE) as u64
}

pub fn runtime_code_address() -> u64 {
    vmsa_lower_begin as *const () as u64
}

#[doc(hidden)]
pub fn initialize_runtime_state() {
    LOWER_RUNTIME_STATE.0.reset();
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
    Configure = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum LowerElReturnConduit {
    Hvc = 0,
    Smc = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum LowerElTarget {
    El1 = 0,
    El0 = 1,
    El2El0 = 2,
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
    Fault(RawFault),
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
            Self::Hvc => EXCEPTION_CLASS_HVC_AARCH64,
            Self::Smc => EXCEPTION_CLASS_SMC_AARCH64,
        }
    }
}

impl LowerElTarget {
    pub const fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::El1),
            1 => Some(Self::El0),
            2 => Some(Self::El2El0),
            _ => None,
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

pub fn configured_return_conduit() -> LowerElReturnConduit {
    LOWER_RUNTIME_STATE.0.return_conduit()
}

pub fn configured_target() -> LowerElTarget {
    LOWER_RUNTIME_STATE.0.target()
}

pub(crate) fn recovery_in_progress() -> bool {
    matches!(
        LOWER_RUNTIME_STATE.0.phase(),
        phase if phase == LowerPhase::Bridging as u64
            || phase == LowerPhase::Returning as u64
    )
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

    let saved_stage1 = prepare_stage1(stage1)?;
    let saved_smc_routing = match prepare_return_routing(return_conduit) {
        Ok(state) => state,
        Err(error) => {
            restore_stage1(saved_stage1);
            return Err(error);
        }
    };

    let return_exception_class = match target {
        LowerElTarget::El2El0 => EXCEPTION_CLASS_SVC_AARCH64,
        LowerElTarget::El1 | LowerElTarget::El0 => return_conduit.exception_class(),
    };
    if let Err(error) = LOWER_RUNTIME_STATE
        .0
        .prepare(return_exception_class, target)
    {
        restore_environment(saved_stage1, saved_smc_routing);
        return Err(error);
    }

    let lower_vectors = VectorGuard::install_el1();
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

    let fault = LOWER_RUNTIME_STATE.0.take_fault();
    let host_el0_par = if status == 0 && fault.is_none() {
        host_el0_translation.and_then(|request| {
            crate::translation::active_host_el0_stage1(request.address, request.access)
        })
    } else {
        None
    };
    LOWER_RUNTIME_STATE.0.reset();
    drop(lower_vectors);

    if !restore_environment(saved_stage1, saved_smc_routing) {
        return Err(TransitionError::ArchitecturalState);
    }
    if status != 0 {
        return Err(TransitionError::Busy);
    }
    if let Some(fault) = fault {
        return Ok(LowerElOutcome::Fault(fault));
    }
    match host_el0_translation {
        Some(_) => host_el0_par
            .map(|par| LowerElOutcome::HostEl0Translation { par })
            .ok_or(TransitionError::ArchitecturalState),
        None => Ok(LowerElOutcome::Returned),
    }
}

fn prepare_stage1(
    stage1: LowerElStage1Mode,
) -> Result<Option<crate::registers::El1Stage1State>, TransitionError> {
    match stage1 {
        LowerElStage1Mode::Preserve
        | LowerElStage1Mode::Configured
        | LowerElStage1Mode::Configure => Ok(None),
        LowerElStage1Mode::Disable => unsafe { registers::disable_el1_stage1() }
            .map(Some)
            .ok_or(TransitionError::ArchitecturalState),
    }
}

fn prepare_return_routing(
    return_conduit: LowerElReturnConduit,
) -> Result<Option<crate::registers::El1SmcRoutingState>, TransitionError> {
    match return_conduit {
        LowerElReturnConduit::Hvc => Ok(None),
        LowerElReturnConduit::Smc => unsafe { registers::route_el1_smc_to_el2() }
            .map(Some)
            .ok_or(TransitionError::ArchitecturalState),
    }
}

fn restore_stage1(state: Option<crate::registers::El1Stage1State>) -> bool {
    state.is_none_or(|state| unsafe { registers::restore_disabled_el1_stage1(state) })
}

fn restore_environment(
    stage1: Option<crate::registers::El1Stage1State>,
    smc_routing: Option<crate::registers::El1SmcRoutingState>,
) -> bool {
    let routing_restored = smc_routing
        .is_none_or(|state| unsafe { registers::restore_el1_smc_routing(state) });
    restore_stage1(stage1) && routing_restored
}

pub(crate) fn handle_lower_fault(
    exception_class: u8,
    state: (u64, u64, Option<u64>, u64, u64),
) -> Option<(u64, u64)> {
    let runtime = &LOWER_RUNTIME_STATE.0;
    if !runtime.is_active() || !is_abort(exception_class) {
        return None;
    }
    let expected_origin = match runtime.target() {
        LowerElTarget::El1 => 1,
        LowerElTarget::El0 | LowerElTarget::El2El0 => 0,
    };
    if exception_origin_el(state.4) != expected_origin {
        return None;
    }
    let recovery = runtime.recovery.load(Ordering::Acquire);
    let recovery_spsr = runtime.recovery_spsr.load(Ordering::Acquire);
    if recovery == 0 {
        return None;
    }
    let target = match registers::current_el() {
        1 if runtime.begin_bridge() => (vmsa_lower_el1_return as *const () as u64, 0x3c5),
        2 if runtime.begin_return() => (recovery, recovery_spsr),
        _ => return None,
    };
    runtime.record_fault(RawFault {
        esr: state.0,
        far: state.1,
        hpfar: state.2,
        elr: state.3,
        spsr: state.4,
    });
    Some(target)
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_begin(recovery: u64, recovery_spsr: u64) -> u64 {
    if recovery == 0 || recovery & 0x3 != 0 {
        return 0;
    }
    let state = &LOWER_RUNTIME_STATE.0;
    if state.return_exception_class.load(Ordering::Acquire) == 0 {
        return 0;
    }
    state.recovery.store(recovery, Ordering::Release);
    state.recovery_spsr.store(recovery_spsr, Ordering::Release);
    if state
        .phase
        .compare_exchange(
            LowerPhase::Prepared as u64,
            LowerPhase::Active as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        state.recovery.store(0, Ordering::Release);
        state.recovery_spsr.store(0, Ordering::Release);
        return 0;
    }
    1
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_complete() {
    let state = &LOWER_RUNTIME_STATE.0;
    state.recovery.store(0, Ordering::Release);
    state.recovery_spsr.store(0, Ordering::Release);
}

pub(crate) fn handle_lower_return(
    exception_class: u8,
    exception_spsr: u64,
) -> Option<(u64, u64)> {
    let state = &LOWER_RUNTIME_STATE.0;
    if registers::current_el() != 2 {
        return None;
    }
    let expected = state.return_exception_class.load(Ordering::Acquire);
    if expected == 0 || expected != exception_class as u64 {
        return None;
    }
    let expected_origin = match (state.phase(), state.target()) {
        (phase, _) if phase == LowerPhase::Bridging as u64 => 1,
        (phase, LowerElTarget::El1) if phase == LowerPhase::Active as u64 => 1,
        (phase, LowerElTarget::El2El0) if phase == LowerPhase::Active as u64 => 0,
        _ => return None,
    };
    if exception_origin_el(exception_spsr) != expected_origin {
        return None;
    }
    let recovery = state.recovery.load(Ordering::Acquire);
    let recovery_spsr = state.recovery_spsr.load(Ordering::Acquire);
    if recovery == 0 || !state.begin_return() {
        return None;
    }
    Some((recovery, recovery_spsr))
}

pub(crate) fn handle_lower_el0_return(
    exception_class: u8,
    exception_spsr: u64,
) -> Option<(u64, u64)> {
    let state = &LOWER_RUNTIME_STATE.0;
    if registers::current_el() != 1
        || exception_class != EXCEPTION_CLASS_SVC_AARCH64
        || exception_origin_el(exception_spsr) != 0
        || state.target() != LowerElTarget::El0
        || !state.begin_bridge()
    {
        return None;
    }
    Some((vmsa_lower_el1_return as *const () as u64, 0x3c5))
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_lower_return_conduit() -> u64 {
    configured_return_conduit() as u64
}

const fn exception_origin_el(spsr: u64) -> u8 {
    ((spsr >> 2) & 0x3) as u8
}

const fn is_abort(exception_class: u8) -> bool {
    matches!(
        exception_class,
        EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER
            | EXCEPTION_CLASS_INSTRUCTION_ABORT_CURRENT
            | EXCEPTION_CLASS_DATA_ABORT_LOWER
            | EXCEPTION_CLASS_DATA_ABORT_CURRENT
    )
}
