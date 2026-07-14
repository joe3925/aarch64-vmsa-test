#![no_std]

use core::arch::asm;
use vmsa_test_abi::LowerElMailbox;
use vmsa_test_architecture::transition::LowerElReturnConduit;
use vmsa_test_architecture::{
    AccessWidth, GuardedPairResult, GuardedResult, guarded_execute_with_state,
    guarded_ordered_with_state, guarded_pair_with_state, guarded_read_with_state,
    guarded_write_with_state,
};
use vmsa_test_harness::adapter::LowerElTarget;

#[unsafe(no_mangle)]
/// Processes one mailbox command at lower EL and returns through the selected conduit.
///
/// # Safety
///
/// `mailbox` must be writable, aligned, and live until the owning EL regains control.
pub unsafe extern "C" fn vmsa_lower_el_entry(mailbox: *mut LowerElMailbox) -> ! {
    if mailbox.is_null()
        || !mailbox
            .addr()
            .is_multiple_of(core::mem::align_of::<LowerElMailbox>())
    {
        wait_forever()
    }
    // SAFETY: Nullness and alignment were checked; the owning adapter provides
    // a writable page that remains live until this entry returns.
    let mailbox = unsafe { &mut *mailbox };
    let Some(return_conduit) = LowerElReturnConduit::from_raw(mailbox.return_conduit) else {
        mailbox.status = 2;
        wait_forever()
    };
    if !mailbox.fields_valid() {
        mailbox.status = 2;
        return_to_owner(return_conduit, LowerElTarget::El1)
    }
    let target = match mailbox.target {
        0 => LowerElTarget::El1,
        1 => LowerElTarget::El0,
        2 => LowerElTarget::El2El0,
        _ => {
            mailbox.status = 2;
            wait_forever()
        }
    };
    if matches!(mailbox.operation, 9 | 10) {
        let result = guarded_pair_with_state(
            mailbox.exception_state,
            mailbox.address,
            mailbox.value,
            mailbox.second_value,
            mailbox.operation == 10,
        );
        match result {
            Ok(GuardedPairResult::Completed { first, second }) => {
                mailbox.status = 3;
                mailbox.result = first;
                mailbox.second_result = second;
            }
            Ok(GuardedPairResult::Fault(fault)) => record_fault(mailbox, fault),
            Err(_) => mailbox.status = 2,
        }
        return_to_owner(return_conduit, target)
    }
    let result = match mailbox.operation {
        0 => {
            let Some(width) = width(mailbox.width) else {
                mailbox.status = 2;
                return_to_owner(return_conduit, target)
            };
            guarded_read_with_state(mailbox.exception_state, mailbox.address, width)
        }
        1 => {
            let Some(width) = width(mailbox.width) else {
                mailbox.status = 2;
                return_to_owner(return_conduit, target)
            };
            guarded_write_with_state(
                mailbox.exception_state,
                mailbox.address,
                width,
                mailbox.value,
            )
        }
        2 => guarded_execute_with_state(mailbox.exception_state, mailbox.address),
        3 => {
            mailbox.status = 0;
            return_to_owner(return_conduit, target)
        }
        4 => {
            if target == LowerElTarget::El2El0 {
                mailbox.status = 0;
                return_to_owner(return_conduit, target)
            }
            let access = if mailbox.value == 0 {
                vmsa_test_architecture::translation::TranslationAccess::Read
            } else {
                vmsa_test_architecture::translation::TranslationAccess::Write
            };
            match vmsa_test_architecture::translation::current_stage1(mailbox.address, access) {
                Some(par) => {
                    mailbox.status = 0;
                    mailbox.result = par;
                }
                None => mailbox.status = 2,
            }
            return_to_owner(return_conduit, target)
        }
        5 => guarded_ordered_with_state(mailbox.exception_state, mailbox.address, 0, 0),
        6 => guarded_ordered_with_state(mailbox.exception_state, mailbox.address, mailbox.value, 1),
        7 => guarded_ordered_with_state(mailbox.exception_state, mailbox.address, mailbox.value, 2),
        8 => guarded_ordered_with_state(mailbox.exception_state, mailbox.address, mailbox.value, 3),
        _ => {
            mailbox.status = 2;
            return_to_owner(return_conduit, target)
        }
    };

    match result {
        Ok(GuardedResult::Completed(value)) => {
            mailbox.status = 0;
            mailbox.result = value;
        }
        Ok(GuardedResult::Fault(fault)) => {
            record_fault(mailbox, fault);
        }
        Err(_) => mailbox.status = 2,
    }

    return_to_owner(return_conduit, target)
}

fn record_fault(mailbox: &mut LowerElMailbox, fault: vmsa_test_architecture::exception::RawFault) {
    mailbox.status = 1;
    mailbox.esr = fault.esr;
    mailbox.far = fault.far;
    mailbox.hpfar_valid = fault.hpfar.is_some() as u64;
    mailbox.hpfar = fault.hpfar.map_or(0, |value| value);
    mailbox.elr = fault.elr;
    mailbox.spsr = fault.spsr;
}

pub fn entry_address() -> u64 {
    vmsa_lower_el_entry as *const () as u64
}

fn width(value: u64) -> Option<AccessWidth> {
    match value {
        0 => Some(AccessWidth::Byte),
        1 => Some(AccessWidth::Half),
        2 => Some(AccessWidth::Word),
        3 => Some(AccessWidth::Double),
        _ => None,
    }
}

fn return_to_owner(conduit: LowerElReturnConduit, target: LowerElTarget) -> ! {
    if matches!(target, LowerElTarget::El0 | LowerElTarget::El2El0) {
        // SAFETY: The EL1 vector installed by the owner converts this SVC into
        // the selected EL2 return conduit without exposing it to test logic.
        unsafe { asm!("svc #0", options(noreturn)) }
    }
    match conduit {
        LowerElReturnConduit::Hvc => {
            // SAFETY: The owning EL2 adapter expects EC 0x16 for this transition.
            unsafe { asm!("hvc #0", options(noreturn)) }
        }
        LowerElReturnConduit::Smc => {
            // SAFETY: The owning EL2 adapter routes EL1 SMC to EL2 and expects EC 0x17.
            unsafe { asm!("smc #0", options(noreturn)) }
        }
    }
}

fn wait_forever() -> ! {
    loop {
        // SAFETY: WFE only changes the processor's wait state.
        unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) }
    }
}
