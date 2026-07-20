use core::arch::asm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationAccess {
    Read,
    Write,
}

pub fn current_stage1(address: u64, access: TranslationAccess) -> Option<u64> {
    let par: u64;
    // SAFETY: AT only updates PAR_EL1. The caller serializes translation state,
    // and ISB makes the resulting PAR_EL1 value observable before it is read.
    unsafe {
        match (crate::registers::current_el(), access) {
            (1, TranslationAccess::Read) => asm!(
                "at s1e1r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            (1, TranslationAccess::Write) => asm!(
                "at s1e1w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            (2, TranslationAccess::Read) => asm!(
                "at s1e2r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            (2, TranslationAccess::Write) => asm!(
                "at s1e2w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            (3, TranslationAccess::Read) => asm!(
                "at s1e3r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            (3, TranslationAccess::Write) => asm!(
                "at s1e3w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            _ => return None,
        }
    }
    Some(par)
}

pub fn combined_stage1_stage2(address: u64, access: TranslationAccess) -> Option<u64> {
    if crate::registers::current_el() != 2 {
        return None;
    }
    let par: u64;
    // SAFETY: AT S12E1* is defined at EL2 and only updates PAR_EL1.
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s12e1r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s12e1w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
        }
    }
    Some(par)
}

pub fn lower_stage1(address: u64, access: TranslationAccess) -> Option<u64> {
    if crate::registers::current_el() != 2 {
        return None;
    }
    let par: u64;
    // SAFETY: AT S1E1* is defined at EL2 and only updates PAR_EL1.
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e1r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e1w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
        }
    }
    Some(par)
}

pub fn lower_el0_stage1(address: u64, access: TranslationAccess) -> Option<u64> {
    if crate::registers::current_el() != 2 {
        return None;
    }
    let par: u64;
    // SAFETY: EL2 owns HCR_EL2 for this bounded query. AT S1E0* queries the
    // inactive EL1&0 regime; EL0 never executes the privileged instruction.
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e0r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e0w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                result = lateout(reg) par,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                options(nostack, preserves_flags),
            ),
        }
    }
    Some(par)
}

/// Queries the active EL2&0 stage-1 regime while the caller owns HCR_EL2.
///
/// Unlike [`lower_el0_stage1`], this helper deliberately leaves HCR_EL2
/// untouched. It is used immediately after the bounded EL2&0 transition
/// returns and before the transition restores its saved architectural state.
pub fn active_host_el0_stage1(address: u64, access: TranslationAccess) -> Option<u64> {
    if crate::registers::current_el() != 2 {
        return None;
    }
    let par: u64;
    // SAFETY: AT S1E0* is defined at EL2 and only updates PAR_EL1. The bounded
    // transition exclusively owns the active EL2&0 regime until recovery.
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                "at s1e0r, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                "at s1e0w, {address}",
                "isb",
                "mrs {result}, PAR_EL1",
                address = in(reg) address,
                result = lateout(reg) par,
                options(nostack, preserves_flags),
            ),
        }
    }
    Some(par)
}

/// Queries the inactive EL1 stage-1 regime and reads the complete D128 PAR.
///
/// The returned pair is `(low, high)`, matching `MRRS Xt, Xt2, PAR_EL1`.
pub fn lower_stage1_d128(address: u64, access: TranslationAccess) -> Option<(u64, u64)> {
    if crate::registers::current_el() != 2 {
        return None;
    }
    let low: u64;
    let high: u64;
    // SAFETY: AT updates only PAR_EL1. The adapter serializes ownership of the
    // EL1 regime, and MRRS captures both halves required by FEAT_D128.
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                ".arch_extension d128",
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e1r, {address}",
                "isb",
                "mrrs x2, x3, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                out("x2") low,
                out("x3") high,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                ".arch_extension d128",
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "bic {guest_hcr}, {guest_hcr}, #1",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s1e1w, {address}",
                "isb",
                "mrrs x2, x3, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                out("x2") low,
                out("x3") high,
                options(nostack, preserves_flags),
            ),
        }
    }
    Some((low, high))
}
pub fn combined_stage1_stage2_d128(address: u64, access: TranslationAccess) -> Option<(u64, u64)> {
    if crate::registers::current_el() != 2 {
        return None;
    }

    let low: u64;
    let high: u64;
    unsafe {
        match access {
            TranslationAccess::Read => asm!(
                ".arch_extension d128",
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s12e1r, {address}",
                "isb",
                "mrrs x2, x3, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                out("x2") low,
                out("x3") high,
                options(nostack, preserves_flags),
            ),
            TranslationAccess::Write => asm!(
                ".arch_extension d128",
                "mrs {saved_hcr}, HCR_EL2",
                "bic {guest_hcr}, {saved_hcr}, #0x08000000",
                "bic {guest_hcr}, {guest_hcr}, #0x400000000",
                "msr HCR_EL2, {guest_hcr}",
                "isb",
                "at s12e1w, {address}",
                "isb",
                "mrrs x2, x3, PAR_EL1",
                "msr HCR_EL2, {saved_hcr}",
                "isb",
                address = in(reg) address,
                saved_hcr = out(reg) _,
                guest_hcr = out(reg) _,
                out("x2") low,
                out("x3") high,
                options(nostack, preserves_flags),
            ),
        }
    }

    Some((low, high))
}
