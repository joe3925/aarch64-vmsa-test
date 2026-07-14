use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::{registers, transition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawFault {
    pub esr: u64,
    pub far: u64,
    pub hpfar: Option<u64>,
    pub elr: u64,
    pub spsr: u64,
}

struct FaultSlot(UnsafeCell<Option<RawFault>>);

// SAFETY: Guard activation serializes access and payload execution is single-core.
unsafe impl Sync for FaultSlot {}

#[repr(C)]
struct ExceptionRuntimeState {
    guard_active: AtomicBool,
    recovery: AtomicU64,
    fault: FaultSlot,
    unexpected_fault: FaultSlot,
    fatal_handler: AtomicUsize,
}

#[unsafe(no_mangle)]
static VMSA_EXCEPTION_RUNTIME_STATE: ExceptionRuntimeState = ExceptionRuntimeState {
    guard_active: AtomicBool::new(false),
    recovery: AtomicU64::new(0),
    fault: FaultSlot(UnsafeCell::new(None)),
    unexpected_fault: FaultSlot(UnsafeCell::new(None)),
    fatal_handler: AtomicUsize::new(0),
};

unsafe extern "C" {
    static vmsa_exception_vectors: u8;
    static vmsa_recovery_vectors: u8;
}

pub fn vector_address() -> u64 {
    core::ptr::addr_of!(vmsa_exception_vectors) as u64
}

pub fn recovery_vector_address() -> u64 {
    core::ptr::addr_of!(vmsa_recovery_vectors) as u64
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
    &VMSA_EXCEPTION_RUNTIME_STATE
}

fn passed_runtime_state(address: u64) -> Option<&'static ExceptionRuntimeState> {
    if address == 0
        || !(address as usize).is_multiple_of(core::mem::align_of::<ExceptionRuntimeState>())
    {
        return None;
    }
    // SAFETY: This private ABI accepts addresses only from an owning adapter;
    // tests cannot construct or invoke guarded architecture operations directly.
    Some(unsafe { &*(address as *const ExceptionRuntimeState) })
}

pub fn runtime_code_address() -> u64 {
    vmsa_guard_begin as *const () as u64
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
extern "C" fn vmsa_guard_begin(recovery: u64, state_address: u64) -> u64 {
    if recovery == 0 || recovery & 0x3 != 0 {
        return 0;
    }
    let Some(state) = passed_runtime_state(state_address) else {
        return 0;
    };
    if state.guard_active.load(Ordering::Acquire) {
        return 0;
    }
    state.guard_active.store(true, Ordering::Release);
    // SAFETY: This slot is exclusively owned while the guard is active.
    unsafe { *state.fault.0.get() = None };
    state.recovery.store(recovery, Ordering::Release);
    1
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_guard_complete(state_address: u64) {
    let Some(state) = passed_runtime_state(state_address) else {
        return;
    };
    state.recovery.store(0, Ordering::Release);
    state.guard_active.store(false, Ordering::Release);
}

pub(crate) fn take_fault(state_address: u64) -> Option<RawFault> {
    let state = passed_runtime_state(state_address)?;
    // SAFETY: The access assembly has cleared the guard before this read and
    // no new guarded operation can start on the same execution thread.
    unsafe { (*state.fault.0.get()).take() }
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_arch_handle_sync(state_address: u64) -> u64 {
    let exception = registers::read_exception_state();
    let exception_class = ((exception.0 >> 26) & 0x3f) as u8;
    if let Some((recovery, recovery_spsr)) = transition::handle_lower_el0_return(exception_class) {
        registers::write_exception_return(recovery, Some(recovery_spsr));
        return 1;
    }
    if let Some((recovery, recovery_spsr)) = transition::handle_lower_return(exception_class) {
        registers::write_exception_return(recovery, Some(recovery_spsr));
        return 1;
    }
    let Some(state) = passed_runtime_state(state_address) else {
        store_unexpected(exception);
        return 0;
    };
    if !state.guard_active.load(Ordering::Acquire) {
        store_unexpected(exception);
        return 0;
    }
    let recovery = state.recovery.load(Ordering::Acquire);
    if recovery == 0 {
        store_unexpected(exception);
        return 0;
    }
    // SAFETY: The active guard exclusively owns the fault slot until recovery.
    unsafe {
        *state.fault.0.get() = Some(RawFault {
            esr: exception.0,
            far: exception.1,
            hpfar: exception.2,
            elr: exception.3,
            spsr: exception.4,
        });
    }
    registers::write_exception_return(recovery, None);
    1
}

fn store_unexpected(state: (u64, u64, Option<u64>, u64, u64)) {
    // SAFETY: An unexpected exception is terminal and payload execution is
    // single-core, so the fatal path exclusively owns this slot.
    unsafe {
        *runtime_state().unexpected_fault.0.get() = Some(RawFault {
            esr: state.0,
            far: state.1,
            hpfar: state.2,
            elr: state.3,
            spsr: state.4,
        });
    }
}

#[unsafe(no_mangle)]
extern "C" fn vmsa_arch_unexpected_exception() -> ! {
    let handler = runtime_state().fatal_handler.load(Ordering::Acquire);
    if handler != 0 {
        // SAFETY: FatalExceptionGuard installs only a function pointer with this
        // ABI and remains alive while the payload owns the exception vectors.
        let handler: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> ! =
            unsafe { core::mem::transmute(handler) };
        // SAFETY: Fatal handling is terminal and exclusively reads this slot.
        let fault = unsafe { *runtime_state().unexpected_fault.0.get() };
        let (esr, far, hpfar, valid, elr, spsr) = match fault {
            Some(fault) => (
                fault.esr,
                fault.far,
                fault.hpfar.map_or(0, |value| value),
                fault.hpfar.is_some() as u64,
                fault.elr,
                fault.spsr,
            ),
            None => (0, 0, 0, 0, 0, 0),
        };
        // SAFETY: The registered fatal callback is live and never returns.
        unsafe { handler(esr, far, hpfar, valid, elr, spsr) }
    }
    loop {
        // SAFETY: WFE only changes the processor's wait state.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) }
    }
}
