use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::{registers, transition};

const EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER: u8 = 0x20;
const EXCEPTION_CLASS_INSTRUCTION_ABORT_CURRENT: u8 = 0x21;
const EXCEPTION_CLASS_DATA_ABORT_LOWER: u8 = 0x24;
const EXCEPTION_CLASS_DATA_ABORT_CURRENT: u8 = 0x25;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardPhase {
    Idle = 0,
    Armed = 1,
    Recovering = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawFault {
    pub esr: u64,
    pub far: u64,
    pub hpfar: Option<u64>,
    pub elr: u64,
    pub spsr: u64,
}

impl RawFault {
    const EMPTY: Self = Self {
        esr: 0,
        far: 0,
        hpfar: None,
        elr: 0,
        spsr: 0,
    };

    const fn from_registers(state: (u64, u64, Option<u64>, u64, u64)) -> Self {
        Self {
            esr: state.0,
            far: state.1,
            hpfar: state.2,
            elr: state.3,
            spsr: state.4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum FatalExceptionKind {
    Unexpected = 0,
    InvalidRuntimeState = 1,
    DoubleFault = 2,
    GuardStateViolation = 3,
    LowerElRecoveryFault = 4,
}

impl FatalExceptionKind {
    const fn from_raw(value: u64) -> Self {
        match value {
            1 => Self::InvalidRuntimeState,
            2 => Self::DoubleFault,
            3 => Self::GuardStateViolation,
            4 => Self::LowerElRecoveryFault,
            _ => Self::Unexpected,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FatalExceptionRecord {
    pub kind: FatalExceptionKind,
    pub primary: RawFault,
    pub secondary: Option<RawFault>,
}

struct FaultSlot(UnsafeCell<Option<RawFault>>);

unsafe impl Sync for FaultSlot {}

struct FatalSlot(UnsafeCell<FatalExceptionRecord>);

unsafe impl Sync for FatalSlot {}

#[repr(C)]
struct ExceptionRuntimeState {
    guard_phase: AtomicU64,
    guard_recovery: AtomicU64,
    guard_origin_el: AtomicU64,
    guard_fault: FaultSlot,
    dispatch_active: AtomicBool,
    dispatch_fault: FaultSlot,
    fatal_active: AtomicBool,
    fatal_handler: AtomicUsize,
    fatal_kind: AtomicU64,
    fatal_record: FatalSlot,
}

impl ExceptionRuntimeState {
    const fn new() -> Self {
        Self {
            guard_phase: AtomicU64::new(GuardPhase::Idle as u64),
            guard_recovery: AtomicU64::new(0),
            guard_origin_el: AtomicU64::new(0),
            guard_fault: FaultSlot(UnsafeCell::new(None)),
            dispatch_active: AtomicBool::new(false),
            dispatch_fault: FaultSlot(UnsafeCell::new(None)),
            fatal_active: AtomicBool::new(false),
            fatal_handler: AtomicUsize::new(0),
            fatal_kind: AtomicU64::new(FatalExceptionKind::Unexpected as u64),
            fatal_record: FatalSlot(UnsafeCell::new(FatalExceptionRecord {
                kind: FatalExceptionKind::Unexpected,
                primary: RawFault::EMPTY,
                secondary: None,
            })),
        }
    }

    fn reset(&self) {
        self.guard_phase
            .store(GuardPhase::Idle as u64, Ordering::Release);
        self.guard_recovery.store(0, Ordering::Release);
        self.guard_origin_el.store(0, Ordering::Release);
        self.dispatch_active.store(false, Ordering::Release);
        self.fatal_active.store(false, Ordering::Release);
        self.fatal_handler.store(0, Ordering::Release);
        self.fatal_kind
            .store(FatalExceptionKind::Unexpected as u64, Ordering::Release);
        unsafe {
            *self.guard_fault.0.get() = None;
            *self.dispatch_fault.0.get() = None;
            *self.fatal_record.0.get() = FatalExceptionRecord {
                kind: FatalExceptionKind::Unexpected,
                primary: RawFault::EMPTY,
                secondary: None,
            };
        }
    }

    fn record_fatal(&self, kind: FatalExceptionKind, fault: RawFault) {
        self.fatal_kind.store(kind as u64, Ordering::Release);
        unsafe {
            *self.fatal_record.0.get() = FatalExceptionRecord {
                kind,
                primary: fault,
                secondary: None,
            };
        }
    }

    fn record_double_fault(&self, secondary: RawFault) {
        self.fatal_kind
            .store(FatalExceptionKind::DoubleFault as u64, Ordering::Release);
        let primary = unsafe { (*self.dispatch_fault.0.get()).unwrap_or(RawFault::EMPTY) };
        unsafe {
            *self.fatal_record.0.get() = FatalExceptionRecord {
                kind: FatalExceptionKind::DoubleFault,
                primary,
                secondary: Some(secondary),
            };
        }
    }
}

#[cfg_attr(feature = "runtime-64k-alignment", repr(C, align(65536)))]
#[cfg_attr(not(feature = "runtime-64k-alignment"), repr(C, align(4096)))]
struct ExceptionRuntimeStorage(ExceptionRuntimeState);

#[cfg(feature = "runtime-64k-alignment")]
const _: () = assert!(core::mem::size_of::<ExceptionRuntimeStorage>() == 65536);
#[cfg(not(feature = "runtime-64k-alignment"))]
const _: () = assert!(core::mem::size_of::<ExceptionRuntimeStorage>() == 4096);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.vmsa_exception_runtime_state")]
static VMSA_EXCEPTION_RUNTIME_STATE: ExceptionRuntimeStorage =
    ExceptionRuntimeStorage(ExceptionRuntimeState::new());

unsafe extern "C" {
    static vmsa_exception_vectors: u8;
    static vmsa_recovery_vectors: u8;
    #[link_name = "_GLOBAL_OFFSET_TABLE_"]
    static VMSA_GLOBAL_OFFSET_TABLE: u8;
}

pub fn vector_address() -> u64 {
    core::ptr::addr_of!(vmsa_exception_vectors) as u64
}

pub fn recovery_vector_address() -> u64 {
    core::ptr::addr_of!(vmsa_recovery_vectors) as u64
}

/// Returns an address in the relocation-backed linkage data used by this
/// linked payload. Candidate translations must keep this data readable while
/// harness helpers and exception dispatch are active.
pub fn linkage_data_address() -> u64 {
    core::ptr::addr_of!(VMSA_GLOBAL_OFFSET_TABLE) as u64
}

pub fn primary_vectors_active() -> bool {
    registers::current_vbar() == vector_address()
}

pub fn recovery_vectors_active() -> bool {
    registers::current_vbar() == recovery_vector_address()
}

#[inline(never)]
pub fn runtime_state_address() -> u64 {
    core::ptr::addr_of!(VMSA_EXCEPTION_RUNTIME_STATE) as u64
}

fn runtime_state() -> &'static ExceptionRuntimeState {
    &VMSA_EXCEPTION_RUNTIME_STATE.0
}

#[doc(hidden)]
pub fn initialize_runtime_state() {
    runtime_state().reset();
}

fn passed_runtime_state(address: u64) -> Option<&'static ExceptionRuntimeState> {
    if address == 0
        || !(address as usize).is_multiple_of(core::mem::align_of::<ExceptionRuntimeStorage>())
    {
        return None;
    }
    Some(unsafe { &*(address as *const ExceptionRuntimeState) })
}

pub fn runtime_code_address() -> u64 {
    vmsa_guard_begin as *const () as u64
}

fn fatal_exception_record() -> FatalExceptionRecord {
    unsafe { *runtime_state().fatal_record.0.get() }
}

pub fn fatal_exception_kind() -> FatalExceptionKind {
    FatalExceptionKind::from_raw(runtime_state().fatal_kind.load(Ordering::Acquire))
}

pub struct VectorGuard {
    previous: u64,
    el: u8,
    restored: bool,
}

pub struct FatalExceptionGuard {
    previous: usize,
}

impl FatalExceptionGuard {
    pub fn install(handler: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> !) -> Self {
        let previous = runtime_state()
            .fatal_handler
            .swap(handler as usize, Ordering::AcqRel);
        Self { previous }
    }
}

impl Drop for FatalExceptionGuard {
    fn drop(&mut self) {
        runtime_state()
            .fatal_handler
            .store(self.previous, Ordering::Release);
    }
}

impl VectorGuard {
    pub fn install() -> Self {
        let el = registers::current_el();
        let address = vector_address();
        let previous = registers::replace_vbar_for_el(el, address);
        Self {
            previous,
            el,
            restored: false,
        }
    }

    pub fn install_el1() -> Self {
        let address = vector_address();
        let previous = registers::replace_vbar_for_el(1, address);
        Self {
            previous,
            el: 1,
            restored: false,
        }
    }

    pub fn restore(mut self) {
        self.restore_inner();
    }

    fn restore_inner(&mut self) {
        if !self.restored {
            registers::replace_vbar_for_el(self.el, self.previous);
            self.restored = true;
        }
    }
}

impl Drop for VectorGuard {
    fn drop(&mut self) {
        self.restore_inner();
    }
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_guard_begin(recovery: u64, state_address: u64, origin_el: u64) -> u64 {
    if recovery == 0 || recovery & 0x3 != 0 || origin_el > 3 {
        return 0;
    }
    let Some(state) = passed_runtime_state(state_address) else {
        return 0;
    };
    if state
        .guard_phase
        .compare_exchange(
            GuardPhase::Idle as u64,
            GuardPhase::Armed as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return 0;
    }
    unsafe { *state.guard_fault.0.get() = None };
    state.guard_origin_el.store(origin_el, Ordering::Release);
    state.guard_recovery.store(recovery, Ordering::Release);
    1
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_guard_complete(state_address: u64) {
    let Some(state) = passed_runtime_state(state_address) else {
        return;
    };
    state.guard_recovery.store(0, Ordering::Release);
    state.guard_origin_el.store(0, Ordering::Release);
    state
        .guard_phase
        .store(GuardPhase::Idle as u64, Ordering::Release);
}

pub(crate) fn take_fault(state_address: u64) -> Option<RawFault> {
    let state = passed_runtime_state(state_address)?;
    let fault = unsafe { (*state.guard_fault.0.get()).take() };
    if fault.is_some() {
        state.guard_recovery.store(0, Ordering::Release);
        state.guard_origin_el.store(0, Ordering::Release);
        state
            .guard_phase
            .store(GuardPhase::Idle as u64, Ordering::Release);
    }
    fault
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_arch_handle_sync(state_address: u64) -> u64 {
    let exception = registers::read_exception_state();
    let fault = RawFault::from_registers(exception);
    let state = runtime_state();

    if state
        .dispatch_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        state.record_double_fault(fault);
        return 0;
    }

    unsafe { *state.dispatch_fault.0.get() = Some(fault) };
    let handled = dispatch_sync(state_address, exception);
    if handled {
        unsafe { *state.dispatch_fault.0.get() = None };
        state.dispatch_active.store(false, Ordering::Release);
        return 1;
    }

    let kind = if passed_runtime_state(state_address).is_none() {
        FatalExceptionKind::InvalidRuntimeState
    } else if guard_in_progress(state_address) {
        FatalExceptionKind::GuardStateViolation
    } else if transition::recovery_in_progress() {
        FatalExceptionKind::LowerElRecoveryFault
    } else {
        FatalExceptionKind::Unexpected
    };
    state.record_fatal(kind, fault);
    0
}

fn dispatch_sync(state_address: u64, exception: (u64, u64, Option<u64>, u64, u64)) -> bool {
    let exception_class = ((exception.0 >> 26) & 0x3f) as u8;

    if let Some((recovery, recovery_spsr)) =
        transition::handle_lower_el0_return(exception_class, exception.4)
    {
        registers::write_exception_return(recovery, Some(recovery_spsr));
        return true;
    }
    if let Some((recovery, recovery_spsr)) =
        transition::handle_lower_return(exception_class, exception.4)
    {
        registers::write_exception_return(recovery, Some(recovery_spsr));
        return true;
    }
    if handle_guarded_fault(state_address, exception_class, exception) {
        return true;
    }
    if guard_in_progress(state_address) {
        return false;
    }
    if let Some((recovery, recovery_spsr)) =
        transition::handle_lower_fault(exception_class, exception)
    {
        registers::write_exception_return(recovery, Some(recovery_spsr));
        return true;
    }
    false
}

fn guard_in_progress(state_address: u64) -> bool {
    passed_runtime_state(state_address)
        .is_some_and(|state| state.guard_phase.load(Ordering::Acquire) != GuardPhase::Idle as u64)
}

fn handle_guarded_fault(
    state_address: u64,
    exception_class: u8,
    exception: (u64, u64, Option<u64>, u64, u64),
) -> bool {
    if !is_abort(exception_class) {
        return false;
    }
    let Some(state) = passed_runtime_state(state_address) else {
        return false;
    };
    let origin_el = ((exception.4 >> 2) & 0x3) as u8;
    if state.guard_origin_el.load(Ordering::Acquire) as u8 != origin_el {
        return false;
    }
    if state
        .guard_phase
        .compare_exchange(
            GuardPhase::Armed as u64,
            GuardPhase::Recovering as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }
    state.guard_origin_el.store(0, Ordering::Release);
    let recovery = state.guard_recovery.swap(0, Ordering::AcqRel);
    if recovery == 0 {
        return false;
    }
    unsafe {
        *state.guard_fault.0.get() = Some(RawFault::from_registers(exception));
    }
    registers::write_exception_return(recovery, None);
    true
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

#[unsafe(no_mangle)]
extern "C" fn vmsa_arch_unexpected_exception() -> ! {
    let state = runtime_state();
    if state.fatal_active.swap(true, Ordering::AcqRel) {
        halt()
    }
    let handler = state.fatal_handler.load(Ordering::Acquire);
    if handler != 0 {
        let handler: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> ! =
            unsafe { core::mem::transmute(handler) };
        let record = fatal_exception_record();
        let fault = record.primary;
        unsafe {
            handler(
                fault.esr,
                fault.far,
                fault.hpfar.unwrap_or(0),
                fault.hpfar.is_some() as u64,
                fault.elr,
                fault.spsr,
            )
        }
    }
    halt()
}

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) }
    }
}
