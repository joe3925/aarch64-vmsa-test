#![no_std]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("vmsa-test-architecture requires AArch64");

use core::arch::{asm, global_asm};

global_asm!(include_str!("../asm/access.S"));
global_asm!(include_str!("../asm/lower_el.S"));
global_asm!(include_str!("../asm/vectors.S"));

pub mod barriers;
pub mod exception;
pub mod registers;
pub mod transition;
pub mod translation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AccessWidth {
    Byte = 0,
    Half = 1,
    Word = 2,
    Double = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardError {
    Busy,
    UnexpectedState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardedResult {
    Completed(u64),
    Fault(exception::RawFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardedPairResult {
    Completed { first: u64, second: u64 },
    Fault(exception::RawFault),
}

#[repr(C)]
struct AssemblyAccessResult {
    status: u64,
    value: u64,
}

unsafe extern "C" {
    fn vmsa_guarded_read(
        address: u64,
        width: u64,
        state: u64,
        origin_el: u64,
    ) -> AssemblyAccessResult;
    fn vmsa_guarded_write(
        address: u64,
        width: u64,
        value: u64,
        state: u64,
        origin_el: u64,
    ) -> AssemblyAccessResult;
    fn vmsa_guarded_execute(address: u64, state: u64, origin_el: u64) -> AssemblyAccessResult;
    fn vmsa_guarded_ordered(
        address: u64,
        value: u64,
        operation: u64,
        state: u64,
        origin_el: u64,
    ) -> AssemblyAccessResult;
    fn vmsa_guarded_pair(
        address: u64,
        first: u64,
        second: u64,
        write: u64,
        result: *mut [u64; 2],
        state: u64,
        origin_el: u64,
    ) -> u64;
}

/// Raises a deliberate synchronous exception for destructive fatal-path tests.
///
/// The caller must run in a boot that is expected to terminate. A fault is
/// handled by the installed fatal exception callback rather than recovered.
#[doc(hidden)]
pub fn trigger_unexpected_exception() {
    DELIBERATE_UNEXPECTED_EXCEPTION.store(true, core::sync::atomic::Ordering::Release);
    // SAFETY: This instruction intentionally has no guarded recovery interval;
    // the destructive test owns the boot and requires the fatal vector path.
    unsafe { asm!(".inst 0", options(nostack)) }
}

static DELIBERATE_UNEXPECTED_EXCEPTION: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Returns whether the fatal vector was reached from the harness's deliberately
/// armed terminal exception. The flag is consumed so an unrelated later fault
/// cannot inherit terminal authorization.
#[doc(hidden)]
pub fn take_deliberate_unexpected_exception() -> bool {
    DELIBERATE_UNEXPECTED_EXCEPTION.swap(false, core::sync::atomic::Ordering::AcqRel)
}

pub fn guarded_read(address: u64, width: AccessWidth) -> Result<GuardedResult, GuardError> {
    // SAFETY: The assembly routine follows AAPCS64 and contains the potentially
    // faulting access inside the guarded-recovery interval.
    guarded_read_with_state(exception::runtime_state_address(), address, width)
}

#[doc(hidden)]
pub fn guarded_read_with_state(
    state: u64,
    address: u64,
    width: AccessWidth,
) -> Result<GuardedResult, GuardError> {
    guarded_read_with_state_at_el(state, address, width, registers::current_el())
}

#[doc(hidden)]
pub fn guarded_read_with_state_at_el(
    state: u64,
    address: u64,
    width: AccessWidth,
    origin_el: u8,
) -> Result<GuardedResult, GuardError> {
    if origin_el > 3 {
        return Err(GuardError::UnexpectedState);
    }
    // SAFETY: The owning adapter supplies the address of its live exception
    // state and the assembly encloses the access in its guarded interval.
    decode_assembly_result(
        unsafe { vmsa_guarded_read(address, width as u64, state, origin_el as u64) },
        state,
    )
}

pub fn guarded_write(
    address: u64,
    width: AccessWidth,
    value: u64,
) -> Result<GuardedResult, GuardError> {
    // SAFETY: The assembly routine follows AAPCS64 and contains the potentially
    // faulting access inside the guarded-recovery interval.
    guarded_write_with_state(exception::runtime_state_address(), address, width, value)
}

#[doc(hidden)]
pub fn guarded_write_with_state(
    state: u64,
    address: u64,
    width: AccessWidth,
    value: u64,
) -> Result<GuardedResult, GuardError> {
    guarded_write_with_state_at_el(state, address, width, value, registers::current_el())
}

#[doc(hidden)]
pub fn guarded_write_with_state_at_el(
    state: u64,
    address: u64,
    width: AccessWidth,
    value: u64,
    origin_el: u8,
) -> Result<GuardedResult, GuardError> {
    if origin_el > 3 {
        return Err(GuardError::UnexpectedState);
    }
    // SAFETY: See guarded_read_with_state.
    decode_assembly_result(
        unsafe { vmsa_guarded_write(address, width as u64, value, state, origin_el as u64) },
        state,
    )
}

pub fn guarded_execute(address: u64) -> Result<GuardedResult, GuardError> {
    // SAFETY: The caller selects executable memory; a synchronous instruction
    // abort is redirected through the same guarded-recovery contract.
    guarded_execute_with_state(exception::runtime_state_address(), address)
}

#[doc(hidden)]
pub fn guarded_execute_with_state(state: u64, address: u64) -> Result<GuardedResult, GuardError> {
    guarded_execute_with_state_at_el(state, address, registers::current_el())
}

#[doc(hidden)]
pub fn guarded_execute_with_state_at_el(
    state: u64,
    address: u64,
    origin_el: u8,
) -> Result<GuardedResult, GuardError> {
    if origin_el > 3 {
        return Err(GuardError::UnexpectedState);
    }
    // SAFETY: See guarded_read_with_state.
    decode_assembly_result(
        unsafe { vmsa_guarded_execute(address, state, origin_el as u64) },
        state,
    )
}

pub fn guarded_read_acquire(address: u64) -> Result<GuardedResult, GuardError> {
    guarded_ordered_with_state(exception::runtime_state_address(), address, 0, 0)
}

pub fn guarded_write_release(address: u64, value: u64) -> Result<GuardedResult, GuardError> {
    guarded_ordered_with_state(exception::runtime_state_address(), address, value, 1)
}

pub fn guarded_atomic_swap(address: u64, value: u64) -> Result<GuardedResult, GuardError> {
    guarded_ordered_with_state(exception::runtime_state_address(), address, value, 2)
}

pub fn guarded_exclusive_add(address: u64, value: u64) -> Result<GuardedResult, GuardError> {
    guarded_ordered_with_state(exception::runtime_state_address(), address, value, 3)
}

#[doc(hidden)]
pub fn guarded_ordered_with_state(
    state: u64,
    address: u64,
    value: u64,
    operation: u64,
) -> Result<GuardedResult, GuardError> {
    guarded_ordered_with_state_at_el(state, address, value, operation, registers::current_el())
}

#[doc(hidden)]
pub fn guarded_ordered_with_state_at_el(
    state: u64,
    address: u64,
    value: u64,
    operation: u64,
    origin_el: u8,
) -> Result<GuardedResult, GuardError> {
    if operation > 3 || origin_el > 3 {
        return Err(GuardError::UnexpectedState);
    }
    // SAFETY: The owning adapter supplies a live mapped exception state; the
    // assembly encloses the selected ordered/atomic access in recovery.
    decode_assembly_result(
        unsafe { vmsa_guarded_ordered(address, value, operation, state, origin_el as u64) },
        state,
    )
}

pub fn guarded_read_pair(address: u64) -> Result<GuardedPairResult, GuardError> {
    guarded_pair(address, 0, 0, false)
}

pub fn guarded_write_pair(
    address: u64,
    first: u64,
    second: u64,
) -> Result<GuardedPairResult, GuardError> {
    guarded_pair(address, first, second, true)
}

fn guarded_pair(
    address: u64,
    first: u64,
    second: u64,
    write: bool,
) -> Result<GuardedPairResult, GuardError> {
    guarded_pair_with_state(
        exception::runtime_state_address(),
        address,
        first,
        second,
        write,
    )
}

#[doc(hidden)]
pub fn guarded_pair_with_state(
    state: u64,
    address: u64,
    first: u64,
    second: u64,
    write: bool,
) -> Result<GuardedPairResult, GuardError> {
    guarded_pair_with_state_at_el(
        state,
        address,
        first,
        second,
        write,
        registers::current_el(),
    )
}

#[doc(hidden)]
pub fn guarded_pair_with_state_at_el(
    state: u64,
    address: u64,
    first: u64,
    second: u64,
    write: bool,
    origin_el: u8,
) -> Result<GuardedPairResult, GuardError> {
    if origin_el > 3 {
        return Err(GuardError::UnexpectedState);
    }
    let mut values = [0u64; 2];
    // SAFETY: The assembly follows AAPCS64, writes exactly two u64 values to
    // `values` after a completed access, and encloses the LDP/STP in recovery.
    let status = unsafe {
        vmsa_guarded_pair(
            address,
            first,
            second,
            write as u64,
            &mut values,
            state,
            origin_el as u64,
        )
    };
    match status {
        0 => Ok(GuardedPairResult::Completed {
            first: values[0],
            second: values[1],
        }),
        1 => exception::take_fault(state)
            .map(GuardedPairResult::Fault)
            .ok_or(GuardError::UnexpectedState),
        2 => Err(GuardError::Busy),
        _ => Err(GuardError::UnexpectedState),
    }
}

fn decode_assembly_result(
    result: AssemblyAccessResult,
    state: u64,
) -> Result<GuardedResult, GuardError> {
    match result.status {
        0 => Ok(GuardedResult::Completed(result.value)),
        1 => exception::take_fault(state)
            .map(GuardedResult::Fault)
            .ok_or(GuardError::UnexpectedState),
        2 => Err(GuardError::Busy),
        _ => Err(GuardError::UnexpectedState),
    }
}
