use core::arch::asm;

#[inline]
pub fn dsb_ish() {
    // SAFETY: A barrier has no memory operand and preserves architectural registers.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) }
}

#[inline]
pub fn dsb_ishst() {
    // SAFETY: A barrier has no memory operand and preserves architectural registers.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) }
}

#[inline]
pub fn isb() {
    // SAFETY: An instruction barrier has no memory operand and preserves registers.
    unsafe { asm!("isb", options(nostack, preserves_flags)) }
}

#[inline]
pub fn invalidate_stage1_all() {
    dsb_ishst();
    // SAFETY: The active firmware adapter is responsible for invoking this only
    // at an EL where VMALLE1 is defined and after preserving the old regime.
    unsafe { asm!("tlbi vmalle1", options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

#[inline]
pub fn invalidate_stage2_all() {
    dsb_ishst();
    // SAFETY: The active firmware adapter is responsible for invoking this at EL2.
    unsafe { asm!("tlbi vmalls12e1is", options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

#[inline]
pub fn invalidate_stage2_all_local() {
    dsb_ishst();
    // SAFETY: The active EL2 adapter owns the local stage-2 regime.
    unsafe { asm!("tlbi vmalls12e1", options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

#[inline]
pub fn invalidate_current_stage1_all() -> bool {
    dsb_ishst();
    // SAFETY: Each operation targets the stage-1 regime owned by the current
    // exception level. Callers serialize translation-table mutation.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi vmalle1is", options(nostack, preserves_flags)),
            2 => asm!("tlbi alle2is", options(nostack, preserves_flags)),
            3 => asm!("tlbi alle3is", options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_current_stage1_address(address: u64, asid: u16) -> bool {
    let operand = (u64::from(asid) << 48) | ((address >> 12) & 0x0000_0fff_ffff_ffff);
    dsb_ishst();
    // SAFETY: The operation targets the current EL's stage-1 regime. The
    // supplied ASID is ignored by regimes that do not implement ASIDs.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi vae1is, {0}", in(reg) operand, options(nostack, preserves_flags)),
            2 => asm!("tlbi vae2is, {0}", in(reg) operand, options(nostack, preserves_flags)),
            3 => asm!("tlbi vae3is, {0}", in(reg) operand, options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_current_stage1_asid(asid: u16) -> bool {
    let operand = u64::from(asid) << 48;
    dsb_ishst();
    // SAFETY: ASIDE1 selects an EL1 stage-1 ASID. The architecture has no
    // ASIDE2/ASIDE3 operation, so those current-EL regimes reject this request.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi aside1is, {0}", in(reg) operand, options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_current_stage1_all_local() -> bool {
    dsb_ishst();
    // SAFETY: Each mnemonic targets the local current-EL stage-1 regime.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi vmalle1", options(nostack, preserves_flags)),
            2 => asm!("tlbi alle2", options(nostack, preserves_flags)),
            3 => asm!("tlbi alle3", options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_current_stage1_address_local(address: u64, asid: u16) -> bool {
    let operand = (u64::from(asid) << 48) | ((address >> 12) & 0x0000_0fff_ffff_ffff);
    dsb_ishst();
    // SAFETY: Each mnemonic targets the local current-EL stage-1 regime.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi vae1, {0}", in(reg) operand, options(nostack, preserves_flags)),
            2 => asm!("tlbi vae2, {0}", in(reg) operand, options(nostack, preserves_flags)),
            3 => asm!("tlbi vae3, {0}", in(reg) operand, options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_current_stage1_asid_local(asid: u16) -> bool {
    let operand = u64::from(asid) << 48;
    dsb_ishst();
    // SAFETY: The non-IS forms invalidate only the executing PE's matching
    // current-EL stage-1 context.
    unsafe {
        match crate::registers::current_el() {
            1 => asm!("tlbi aside1, {0}", in(reg) operand, options(nostack, preserves_flags)),
            _ => return false,
        }
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_el1_stage1_all() {
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the inactive EL1 translation regime.
    unsafe { asm!("tlbi vmalle1is", options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_el1_stage1_address(address: u64, asid: u16) {
    let operand = (u64::from(asid) << 48) | ((address >> 12) & 0x0000_0fff_ffff_ffff);
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the selected EL1 ASID and table mutation.
    unsafe { asm!("tlbi vae1is, {0}", in(reg) operand, options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_el1_stage1_asid(asid: u16) {
    let operand = u64::from(asid) << 48;
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the inactive EL1 ASID being invalidated.
    unsafe { asm!("tlbi aside1is, {0}", in(reg) operand, options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_el1_stage1_all_local() {
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the inactive local EL1 translation regime.
    unsafe { asm!("tlbi vmalle1", options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_el1_stage1_address_local(address: u64, asid: u16) {
    let operand = (u64::from(asid) << 48) | ((address >> 12) & 0x0000_0fff_ffff_ffff);
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the selected local EL1 ASID.
    unsafe { asm!("tlbi vae1, {0}", in(reg) operand, options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_el1_stage1_asid_local(asid: u16) {
    let operand = u64::from(asid) << 48;
    dsb_ishst();
    // SAFETY: The EL2 adapter owns the inactive local EL1 ASID.
    unsafe { asm!("tlbi aside1, {0}", in(reg) operand, options(nostack, preserves_flags)) }
    dsb_ish();
    isb();
}

pub fn invalidate_stage2_address(ipa: u64) -> bool {
    if crate::registers::current_el() != 2 {
        return false;
    }
    let operand = (ipa >> 12) & 0x0000_0fff_ffff_ffff;
    // SAFETY: The EL2 adapter owns HCR_EL2 and the active VMID. Clearing TGE
    // while issuing the operations selects the EL1 guest regime when E2H is
    // enabled; HCR is restored before the assembly block can touch the stack.
    unsafe {
        asm!(
            "mrs {saved_hcr}, HCR_EL2",
            "bic {guest_hcr}, {saved_hcr}, #0x08000000",
            "msr HCR_EL2, {guest_hcr}",
            "isb",
            "dsb ishst",
            "tlbi ipas2e1is, {operand}",
            "dsb ish",
            // Combined stage-1/stage-2 entries for the current VMID can retain
            // the invalidated stage-2 result until the stage-1 entries are
            // invalidated as required by the architectural stage-2 sequence.
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "msr HCR_EL2, {saved_hcr}",
            "isb",
            operand = in(reg) operand,
            saved_hcr = lateout(reg) _,
            guest_hcr = lateout(reg) _,
            options(nostack, preserves_flags)
        )
    }
    true
}

pub fn invalidate_stage2_address_local(ipa: u64) -> bool {
    if crate::registers::current_el() != 2 {
        return false;
    }
    let operand = (ipa >> 12) & 0x0000_0fff_ffff_ffff;
    // SAFETY: The EL2 adapter owns HCR and restores it before using the stack.
    unsafe {
        asm!(
            "mrs {saved_hcr}, HCR_EL2",
            "bic {guest_hcr}, {saved_hcr}, #0x08000000",
            "msr HCR_EL2, {guest_hcr}",
            "isb",
            "dsb ishst",
            "tlbi ipas2e1, {operand}",
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            "msr HCR_EL2, {saved_hcr}",
            "isb",
            operand = in(reg) operand,
            saved_hcr = lateout(reg) _,
            guest_hcr = lateout(reg) _,
            options(nostack, preserves_flags)
        )
    }
    true
}

pub fn synchronize_instruction_range(start: u64, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable at every AArch64 exception level used here.
    unsafe { asm!("mrs {0}, CTR_EL0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    let data_line = 4u64 << ((ctr >> 16) & 0xf);
    let instruction_line = 4u64 << (ctr & 0xf);
    let Some(end) = start.checked_add(bytes as u64) else {
        return false;
    };
    let mut address = start & !(data_line - 1);
    while address < end {
        // SAFETY: DC CVAU accepts any VA; faults are not expected for the live
        // writable test allocation supplied by the harness.
        unsafe { asm!("dc cvau, {0}", in(reg) address, options(nostack, preserves_flags)) };
        address += data_line;
    }
    dsb_ish();
    address = start & !(instruction_line - 1);
    while address < end {
        // SAFETY: IC IVAU targets the same live test allocation just cleaned.
        unsafe { asm!("ic ivau, {0}", in(reg) address, options(nostack, preserves_flags)) };
        address += instruction_line;
    }
    dsb_ish();
    isb();
    true
}

pub fn invalidate_data_cache_range(start: u64, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable in every supported execution context.
    unsafe { asm!("mrs {0}, CTR_EL0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    let line = 4u64 << ((ctr >> 16) & 0xf);
    let Some(end) = start.checked_add(bytes as u64) else {
        return false;
    };
    let mut address = start & !(line - 1);
    while address < end {
        // SAFETY: The adapter supplies a live firmware-shared record range.
        unsafe { asm!("dc ivac, {0}", in(reg) address, options(nostack, preserves_flags)) };
        address += line;
    }
    dsb_ish();
    true
}

pub fn clean_data_cache_range(start: u64, bytes: usize) -> bool {
    maintain_data_cache_range(start, bytes, DataCacheOperation::Clean)
}

pub fn clean_invalidate_data_cache_range(start: u64, bytes: usize) -> bool {
    maintain_data_cache_range(start, bytes, DataCacheOperation::CleanInvalidate)
}

#[derive(Clone, Copy)]
enum DataCacheOperation {
    Clean,
    CleanInvalidate,
}

fn maintain_data_cache_range(start: u64, bytes: usize, operation: DataCacheOperation) -> bool {
    if bytes == 0 {
        return true;
    }
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable in every supported execution context.
    unsafe { asm!("mrs {0}, CTR_EL0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    let line = 4u64 << ((ctr >> 16) & 0xf);
    let Some(end) = start.checked_add(bytes as u64) else {
        return false;
    };
    let mut address = start & !(line - 1);
    while address < end {
        // SAFETY: The harness constrains the range to live, owned test memory.
        unsafe {
            match operation {
                DataCacheOperation::Clean => {
                    asm!("dc cvac, {0}", in(reg) address, options(nostack, preserves_flags))
                }
                DataCacheOperation::CleanInvalidate => {
                    asm!("dc civac, {0}", in(reg) address, options(nostack, preserves_flags))
                }
            }
        };
        address += line;
    }
    dsb_ish();
    true
}
