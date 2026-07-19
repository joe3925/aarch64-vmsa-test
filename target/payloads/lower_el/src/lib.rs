#![no_std]

use core::arch::asm;
use vmsa_test_abi::LowerElMailbox;
use vmsa_test_architecture::transition::{LowerElReturnConduit, LowerElTarget};
use vmsa_test_architecture::{
    AccessWidth, GuardedPairResult, GuardedResult, guarded_execute_with_state_at_el,
    guarded_ordered_with_state_at_el, guarded_pair_with_state_at_el, guarded_read_with_state_at_el,
    guarded_write_with_state_at_el,
};

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
        invalid_entry()
    }
    // SAFETY: Nullness and alignment were checked; the owning adapter provides
    // a writable page that remains live until this entry returns.
    let mailbox = unsafe { &mut *mailbox };
    let Some(return_conduit) = LowerElReturnConduit::from_raw(mailbox.return_conduit) else {
        invalid_entry()
    };
    let Some(target) = LowerElTarget::from_raw(mailbox.target) else {
        invalid_entry()
    };
    if !mailbox.fields_valid() {
        mailbox.status = 2;
        return_to_owner(return_conduit, target)
    }
    let origin_el = u8::from(target == LowerElTarget::El1);
    if mailbox.operation == 11 {
        if target != LowerElTarget::El1 {
            mailbox.status = 2;
            return_to_owner(return_conduit, target)
        }
        let sctlr: u64;
        // SAFETY: This command executes at EL1 and hands the disabled regime
        // directly back to the owning EL2 adapter without another EL1 access.
        unsafe {
            asm!(
                "mrs {saved}, SCTLR_EL1",
                "bic x9, {saved}, #1",
                "bic x9, x9, #4",
                "bic x9, x9, #0x1000",
                "dsb sy",
                "msr SCTLR_EL1, x9",
                "isb",
                saved = out(reg) sctlr,
                out("x9") _,
                options(nostack, preserves_flags)
            )
        };
        mailbox.status = 0;
        mailbox.result = sctlr;
        return_to_owner(return_conduit, target)
    }
    if matches!(mailbox.operation, 9 | 10) {
        let result = guarded_pair_with_state_at_el(
            mailbox.exception_state,
            mailbox.address,
            mailbox.value,
            mailbox.second_value,
            mailbox.operation == 10,
            origin_el,
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
            guarded_read_with_state_at_el(
                mailbox.exception_state,
                mailbox.address,
                width,
                origin_el,
            )
        }
        1 => {
            let Some(width) = width(mailbox.width) else {
                mailbox.status = 2;
                return_to_owner(return_conduit, target)
            };
            guarded_write_with_state_at_el(
                mailbox.exception_state,
                mailbox.address,
                width,
                mailbox.value,
                origin_el,
            )
        }
        2 => guarded_execute_with_state_at_el(mailbox.exception_state, mailbox.address, origin_el),
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
        5 => guarded_ordered_with_state_at_el(
            mailbox.exception_state,
            mailbox.address,
            0,
            0,
            origin_el,
        ),
        6 => guarded_ordered_with_state_at_el(
            mailbox.exception_state,
            mailbox.address,
            mailbox.value,
            1,
            origin_el,
        ),
        7 => guarded_ordered_with_state_at_el(
            mailbox.exception_state,
            mailbox.address,
            mailbox.value,
            2,
            origin_el,
        ),
        8 => guarded_ordered_with_state_at_el(
            mailbox.exception_state,
            mailbox.address,
            mailbox.value,
            3,
            origin_el,
        ),
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

fn invalid_entry() -> ! {
    // A missing or undecodable mailbox leaves no trustworthy return conduit.
    // Trap into the owner's active lower-EL recovery instead of consulting
    // privileged transition globals from an EL0-accessible payload mapping.
    unsafe { asm!("brk #0", options(noreturn)) }
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
