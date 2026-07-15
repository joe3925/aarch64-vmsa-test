use core::arch::asm;

macro_rules! read_register {
    ($name:ident, $register:literal) => {
        #[inline]
        pub fn $name() -> u64 {
            let value: u64;
            // SAFETY: Reading this system register has no memory side effects.
            unsafe { asm!(concat!("mrs {}, ", $register), out(reg) value, options(nomem, nostack, preserves_flags)) }
            value
        }
    };
}

read_register!(current_el_raw, "CurrentEL");
read_register!(id_aa64mmfr0_el1, "ID_AA64MMFR0_EL1");
read_register!(id_aa64mmfr1_el1, "ID_AA64MMFR1_EL1");
read_register!(id_aa64mmfr2_el1, "ID_AA64MMFR2_EL1");
read_register!(id_aa64mmfr3_el1, "ID_AA64MMFR3_EL1");
read_register!(id_aa64pfr0_el1, "ID_AA64PFR0_EL1");
read_register!(id_aa64pfr1_el1, "ID_AA64PFR1_EL1");

pub fn current_el() -> u8 {
    ((current_el_raw() >> 2) & 0x3) as u8
}

pub fn stack_pointer() -> u64 {
    let value: u64;
    // SAFETY: Copying SP into a general-purpose register has no side effects.
    unsafe { asm!("mov {0}, sp", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

pub fn current_stage1_uses_asid() -> bool {
    match current_el() {
        1 => true,
        2 => {
            let hcr: u64;
            // SAFETY: HCR_EL2 is readable at EL2 and this query has no side effects.
            unsafe {
                asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
            }
            hcr & (1 << 34) != 0
        }
        _ => false,
    }
}

pub fn read_exception_state() -> (u64, u64, Option<u64>, u64, u64) {
    let esr: u64;
    let far: u64;
    let elr: u64;
    let spsr: u64;
    let hpfar;
    // SAFETY: The selected registers correspond to the executing exception level.
    unsafe {
        match current_el() {
            1 => {
                asm!("mrs {0}, ESR_EL1", "mrs {1}, FAR_EL1", "mrs {2}, ELR_EL1", "mrs {3}, SPSR_EL1",
                    out(reg) esr, out(reg) far, out(reg) elr, out(reg) spsr, options(nomem, nostack, preserves_flags));
                hpfar = None;
            }
            2 => {
                let value: u64;
                asm!("mrs {0}, ESR_EL2", "mrs {1}, FAR_EL2", "mrs {2}, ELR_EL2", "mrs {3}, SPSR_EL2", "mrs {4}, HPFAR_EL2",
                    out(reg) esr, out(reg) far, out(reg) elr, out(reg) spsr, out(reg) value, options(nomem, nostack, preserves_flags));
                hpfar = Some(value);
            }
            3 => {
                asm!("mrs {0}, ESR_EL3", "mrs {1}, FAR_EL3", "mrs {2}, ELR_EL3", "mrs {3}, SPSR_EL3",
                    out(reg) esr, out(reg) far, out(reg) elr, out(reg) spsr, options(nomem, nostack, preserves_flags));
                hpfar = None;
            }
            _ => return (0, 0, None, 0, 0),
        }
    }
    (esr, far, hpfar, elr, spsr)
}

pub fn write_exception_return(elr: u64, spsr: Option<u64>) {
    // SAFETY: Exception-vector code calls this while handling an exception at
    // the current EL and supplies an aligned recovery PC.
    unsafe {
        match current_el() {
            1 => {
                asm!("msr ELR_EL1, {0}", in(reg) elr, options(nomem, nostack, preserves_flags));
                if let Some(value) = spsr {
                    asm!("msr SPSR_EL1, {0}", in(reg) value, options(nomem, nostack, preserves_flags));
                }
            }
            2 => {
                asm!("msr ELR_EL2, {0}", in(reg) elr, options(nomem, nostack, preserves_flags));
                if let Some(value) = spsr {
                    asm!("msr SPSR_EL2, {0}", in(reg) value, options(nomem, nostack, preserves_flags));
                }
            }
            3 => {
                asm!("msr ELR_EL3, {0}", in(reg) elr, options(nomem, nostack, preserves_flags));
                if let Some(value) = spsr {
                    asm!("msr SPSR_EL3, {0}", in(reg) value, options(nomem, nostack, preserves_flags));
                }
            }
            _ => {}
        }
    }
}

pub fn replace_vbar(address: u64) -> u64 {
    replace_vbar_for_el(current_el(), address)
}

pub(crate) fn current_vbar() -> u64 {
    let value: u64;
    unsafe {
        match current_el() {
            1 => {
                asm!("mrs {0}, VBAR_EL1", out(reg) value, options(nomem, nostack, preserves_flags))
            }
            2 => {
                asm!("mrs {0}, VBAR_EL2", out(reg) value, options(nomem, nostack, preserves_flags))
            }
            3 => {
                asm!("mrs {0}, VBAR_EL3", out(reg) value, options(nomem, nostack, preserves_flags))
            }
            _ => return 0,
        }
    }
    value
}

pub(crate) fn replace_vbar_for_el(el: u8, address: u64) -> u64 {
    let old: u64;
    // SAFETY: Callers select their current EL or an EL1 register while
    // executing at EL1/EL2, and payload entry validates vector alignment.
    unsafe {
        match el {
            1 => {
                let owner_el = current_el();
                let hcr = if owner_el == 2 {
                    let value: u64;
                    asm!("mrs {0}, HCR_EL2", out(reg) value, options(nomem, nostack, preserves_flags));
                    value
                } else {
                    0
                };
                if owner_el == 2 && hcr & (1 << 34) != 0 {
                    asm!(
                        ".arch armv8.5-a",
                        "mrs {0}, VBAR_EL12",
                        "msr VBAR_EL12, {1}",
                        out(reg) old,
                        in(reg) address,
                        options(nostack, preserves_flags)
                    )
                } else {
                    asm!("mrs {0}, VBAR_EL1", "msr VBAR_EL1, {1}", out(reg) old, in(reg) address, options(nostack, preserves_flags))
                }
            }
            2 => {
                asm!("mrs {0}, VBAR_EL2", "msr VBAR_EL2, {1}", out(reg) old, in(reg) address, options(nostack, preserves_flags))
            }
            3 => {
                asm!("mrs {0}, VBAR_EL3", "msr VBAR_EL3, {1}", out(reg) old, in(reg) address, options(nostack, preserves_flags))
            }
            _ => return 0,
        }
        asm!("isb", options(nostack, preserves_flags));
    }
    old
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1State {
    pub ttbr0: u64,
    pub tcr: u64,
    pub mair: u64,
    pub sctlr: u64,
    pub el: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2State {
    pub vttbr: u64,
    pub vtcr: u64,
    pub hcr: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D128Stage2State {
    pub vttbr_low: u64,
    pub vttbr_high: u64,
    pub vtcr: u64,
    pub hcr: u64,
    pub s2pir: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeometryStage1State {
    pub stage1: Stage1State,
    pub tcr2: u64,
    transition_stack: Option<TransitionStack>,
    previous_vbar: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionStack {
    pub physical_top: u64,
    pub virtual_top: u64,
    pub recovery_root: u64,
    pub recovery_tcr: u64,
    pub recovery_mair: u64,
    pub recovery_vector: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D128Stage1State {
    pub stage1: Stage1State,
    pub mair2: u64,
    pub ttbr0_high: u64,
    pub tcr2: u64,
    pub pir: u64,
    pub pire0: u64,
    pub hcrx: Option<u64>,
    transition_stack: Option<TransitionStack>,
    previous_vbar: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1MemoryRegisters {
    pub mair: u64,
    pub mair2: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D128ControlState {
    pub ttbr0_low: u64,
    pub ttbr0_high: u64,
    pub tcr: u64,
    pub mair: u64,
    pub mair2: u64,
    pub sctlr: u64,
    pub tcr2: u64,
    pub pir: u64,
    pub pire0: u64,
    pub hcrx: u64,
}

pub fn current_el1_d128_controls() -> Option<D128ControlState> {
    if current_el() != 2 {
        return None;
    }
    let ttbr0_low: u64;
    let ttbr0_high: u64;
    let tcr: u64;
    let mair: u64;
    let mair2: u64;
    let sctlr: u64;
    let tcr2: u64;
    let pir: u64;
    let pire0: u64;
    let hcrx: u64;
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrrs x2, x3, TTBR0_EL1",
            "mrs {tcr}, TCR_EL1",
            "mrs {mair}, MAIR_EL1",
            "mrs {mair2}, S3_0_C10_C3_1",
            "mrs {sctlr}, SCTLR_EL1",
            "mrs {tcr2}, S3_0_C2_C0_3",
            "mrs {pir}, S3_0_C10_C2_3",
            "mrs {pire0}, S3_0_C10_C2_2",
            "mrs {hcrx}, S3_4_C1_C2_2",
            tcr = out(reg) tcr,
            mair = out(reg) mair,
            mair2 = out(reg) mair2,
            sctlr = out(reg) sctlr,
            tcr2 = out(reg) tcr2,
            pir = out(reg) pir,
            pire0 = out(reg) pire0,
            hcrx = out(reg) hcrx,
            out("x2") ttbr0_low,
            out("x3") ttbr0_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    Some(D128ControlState {
        ttbr0_low,
        ttbr0_high,
        tcr,
        mair,
        mair2,
        sctlr,
        tcr2,
        pir,
        pire0,
        hcrx,
    })
}

/// Replaces the inactive EL1 permission-indirection registers and invalidates
/// translations that might have cached their interpretation.
///
/// # Safety
///
/// The caller must exclusively own the inactive EL1 translation regime.
pub unsafe fn set_el1_permission_indirection(pir: u64, pire0: u64) -> bool {
    if current_el() != 2 {
        return false;
    }
    unsafe {
        asm!(
            "msr S3_0_C10_C2_3, {pir}",
            "msr S3_0_C10_C2_2, {pire0}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            pir = in(reg) pir,
            pire0 = in(reg) pire0,
            options(nostack, preserves_flags)
        );
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1Stage1State {
    sctlr: u64,
    vhe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareUpdateState {
    el: u8,
    tcr: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowerHardwareUpdateState {
    tcr_el1: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2HardwareUpdateState {
    vtcr_el2: u64,
}

/// Enables stage-2 hardware access-flag and optional dirty-state updates.
///
/// # Safety
///
/// The caller must exclusively own the EL2 stage-2 translation state until
/// the returned state is restored.
pub unsafe fn enable_stage2_hardware_updates(dirty: bool) -> Option<Stage2HardwareUpdateState> {
    if current_el() != 2 {
        return None;
    }
    let vtcr_el2: u64;
    // SAFETY: The EL2 adapter owns VTCR_EL2 and changes only HA/HD while
    // retaining the installed stage-2 geometry and descriptor format.
    unsafe {
        asm!("mrs {0}, VTCR_EL2", out(reg) vtcr_el2, options(nomem, nostack, preserves_flags));
        let updated = ((vtcr_el2 | (1 << 21)) & !(1 << 22)) | ((dirty as u64) << 22);
        asm!("msr VTCR_EL2, {0}", "isb", in(reg) updated, options(nostack, preserves_flags));
    }
    Some(Stage2HardwareUpdateState { vtcr_el2 })
}

/// Restores a stage-2 hardware-update state.
///
/// # Safety
///
/// `state` must come from the paired enable operation on this PE.
pub unsafe fn restore_stage2_hardware_updates(state: Stage2HardwareUpdateState) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: The paired guard still owns VTCR_EL2.
    unsafe {
        asm!("msr VTCR_EL2, {0}", "isb", in(reg) state.vtcr_el2, options(nostack, preserves_flags));
    }
    true
}

/// Enables hardware access-flag and optional dirty-state updates in the
/// inactive EL1 translation regime owned by the EL2 harness.
///
/// # Safety
///
/// The caller must exclusively own EL1 translation state until restoration.
pub unsafe fn enable_lower_el1_hardware_updates(dirty: bool) -> Option<LowerHardwareUpdateState> {
    if current_el() != 2 {
        return None;
    }
    let tcr_el1: u64;
    // SAFETY: The EL2 adapter owns the inactive EL1 register bank and changes
    // only the architectural HA/HD bits while retaining its installed geometry.
    unsafe {
        asm!("mrs {0}, TCR_EL1", out(reg) tcr_el1, options(nomem, nostack, preserves_flags));
        let updated = (tcr_el1 | (1 << 39)) | ((dirty as u64) << 40);
        asm!("msr TCR_EL1, {0}", "isb", in(reg) updated, options(nostack, preserves_flags));
    }
    Some(LowerHardwareUpdateState { tcr_el1 })
}

/// Restores an inactive EL1 hardware-update state.
///
/// # Safety
///
/// `state` must come from the paired enable operation on this PE.
pub unsafe fn restore_lower_el1_hardware_updates(state: LowerHardwareUpdateState) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: The paired guard still owns the inactive EL1 register bank.
    unsafe {
        asm!("msr TCR_EL1, {0}", "isb", in(reg) state.tcr_el1, options(nostack, preserves_flags));
    }
    true
}

/// Enables hardware access-flag and optional dirty-state updates for the
/// current translation regime.
///
/// # Safety
///
/// The caller must exclusively own the current translation regime until the
/// returned state is restored.
pub unsafe fn enable_hardware_updates(dirty: bool) -> Option<HardwareUpdateState> {
    let el = current_el();
    let tcr: u64;
    let mut vhe = false;
    // SAFETY: The owning adapter serializes the TCR update and retains a valid
    // translation geometry; only HA and HD are changed.
    unsafe {
        match el {
            2 => {
                let hcr: u64;
                asm!(
                    "mrs {0}, TCR_EL2",
                    "mrs {1}, HCR_EL2",
                    out(reg) tcr,
                    out(reg) hcr,
                    options(nomem, nostack, preserves_flags)
                );
                vhe = hcr & (1 << 34) != 0;
            }
            3 => asm!("mrs {0}, TCR_EL3", out(reg) tcr, options(nomem, nostack, preserves_flags)),
            _ => return None,
        }
        let (ha_bit, hd_bit) = if vhe { (39, 40) } else { (21, 22) };
        let updated = (tcr | (1 << ha_bit)) | ((dirty as u64) << hd_bit);
        match el {
            2 => {
                asm!("msr TCR_EL2, {0}", "isb", in(reg) updated, options(nostack, preserves_flags))
            }
            3 => {
                asm!("msr TCR_EL3, {0}", "isb", in(reg) updated, options(nostack, preserves_flags))
            }
            _ => return None,
        }
    }
    Some(HardwareUpdateState { el, tcr })
}

/// Restores a state returned by [`enable_hardware_updates`].
///
/// # Safety
///
/// No other owner may have modified the current TCR since installation.
pub unsafe fn restore_hardware_updates(state: HardwareUpdateState) -> bool {
    if current_el() != state.el {
        return false;
    }
    // SAFETY: State was captured from this EL's TCR by the paired installer.
    unsafe {
        match state.el {
            2 => {
                asm!("msr TCR_EL2, {0}", "isb", in(reg) state.tcr, options(nostack, preserves_flags))
            }
            3 => {
                asm!("msr TCR_EL3, {0}", "isb", in(reg) state.tcr, options(nostack, preserves_flags))
            }
            _ => return false,
        }
    }
    true
}

pub fn current_stage1_state() -> Option<Stage1State> {
    let ttbr0: u64;
    let tcr: u64;
    let mair: u64;
    let sctlr: u64;
    let el = current_el();
    // SAFETY: The selected registers are readable at their owning EL.
    unsafe {
        match el {
            2 => asm!(
                "mrs {0}, TTBR0_EL2", "mrs {1}, TCR_EL2", "mrs {2}, MAIR_EL2", "mrs {3}, SCTLR_EL2",
                out(reg) ttbr0, out(reg) tcr, out(reg) mair, out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            ),
            3 => asm!(
                "mrs {0}, TTBR0_EL3", "mrs {1}, TCR_EL3", "mrs {2}, MAIR_EL3", "mrs {3}, SCTLR_EL3",
                out(reg) ttbr0, out(reg) tcr, out(reg) mair, out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            ),
            _ => return None,
        }
    }
    Some(Stage1State {
        ttbr0,
        tcr,
        mair,
        sctlr,
        el,
    })
}

pub fn current_stage2_state() -> Option<Stage2State> {
    if current_el() != 2 {
        return None;
    }
    let vttbr: u64;
    let vtcr: u64;
    let hcr: u64;
    // SAFETY: These registers are readable by their owning EL2 adapter.
    unsafe {
        asm!(
            "mrs {0}, VTTBR_EL2",
            "mrs {1}, VTCR_EL2",
            "mrs {2}, HCR_EL2",
            out(reg) vttbr,
            out(reg) vtcr,
            out(reg) hcr,
            options(nomem, nostack, preserves_flags)
        );
    }
    Some(Stage2State { vttbr, vtcr, hcr })
}

pub fn current_stage2_d128_state() -> Option<D128Stage2State> {
    if current_el() != 2 {
        return None;
    }
    let vttbr_low: u64;
    let vttbr_high: u64;
    let vtcr: u64;
    let hcr: u64;
    let s2pir: u64;
    // SAFETY: The owning EL2 adapter uses this only when FEAT_D128/S2PIE are
    // advertised and enabled for the active stage-2 regime.
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrrs x2, x3, VTTBR_EL2",
            "mrs {vtcr}, VTCR_EL2",
            "mrs {hcr}, HCR_EL2",
            "mrs {s2pir}, S3_4_C10_C2_5",
            lateout("x2") vttbr_low,
            lateout("x3") vttbr_high,
            vtcr = out(reg) vtcr,
            hcr = out(reg) hcr,
            s2pir = out(reg) s2pir,
            options(nomem, nostack, preserves_flags)
        );
    }
    Some(D128Stage2State {
        vttbr_low,
        vttbr_high,
        vtcr,
        hcr,
        s2pir,
    })
}

pub fn current_el1_stage1_state() -> Option<Stage1State> {
    if current_el() != 2 {
        return None;
    }
    let (ttbr0, tcr, mair, sctlr): (u64, u64, u64, u64);
    let hcr: u64;
    // SAFETY: EL12 aliases access the inactive guest EL1 register bank at EL2.
    unsafe {
        asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
        if hcr & (1 << 34) != 0 {
            asm!(
                ".arch armv8.5-a",
                "mrs {0}, TTBR0_EL12",
                "mrs {1}, TCR_EL12",
                "mrs {2}, MAIR_EL12",
                "mrs {3}, SCTLR_EL12",
                out(reg) ttbr0,
                out(reg) tcr,
                out(reg) mair,
                out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            );
        } else {
            asm!(
                "mrs {0}, TTBR0_EL1",
                "mrs {1}, TCR_EL1",
                "mrs {2}, MAIR_EL1",
                "mrs {3}, SCTLR_EL1",
                out(reg) ttbr0,
                out(reg) tcr,
                out(reg) mair,
                out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    Some(Stage1State {
        ttbr0,
        tcr,
        mair,
        sctlr,
        el: 1,
    })
}

/// Disables EL1 stage-1 translation and returns the prior SCTLR_EL1 value.
///
/// # Safety
///
/// The caller must execute at EL2, exclusively own the EL1 execution context,
/// and restore the returned state before another EL1 context can run.
pub unsafe fn disable_el1_stage1() -> Option<El1Stage1State> {
    if current_el() != 2 {
        return None;
    }
    let hcr: u64;
    let sctlr: u64;
    // SAFETY: The EL2 lower-EL transition owns EL1 architectural state until
    // the matching restore and no EL1 code is executing while this is changed.
    unsafe {
        asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
        if hcr & (1 << 34) != 0 {
            asm!(
                ".arch armv8.5-a",
                "mrs {0}, SCTLR_EL12",
                out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            );
        } else {
            asm!(
                "mrs {0}, SCTLR_EL1",
                out(reg) sctlr,
                options(nomem, nostack, preserves_flags)
            );
        }
        let disabled = sctlr & !1;
        if hcr & (1 << 34) != 0 {
            asm!(
                ".arch armv8.5-a",
                "dsb sy",
                "msr SCTLR_EL12, {0}",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                in(reg) disabled,
                options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "dsb sy",
                "msr SCTLR_EL1, {0}",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                in(reg) disabled,
                options(nostack, preserves_flags)
            );
        }
    }
    Some(El1Stage1State {
        sctlr,
        vhe: hcr & (1 << 34) != 0,
    })
}

/// Restores an EL1 stage-1 state returned by [`disable_el1_stage1`].
///
/// # Safety
///
/// The state must originate from the same PE, with no intervening owner of
/// SCTLR_EL1 or the EL1 translation context.
pub unsafe fn restore_disabled_el1_stage1(state: El1Stage1State) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: The state was captured by disable_el1_stage1 on this PE.
    unsafe {
        if state.vhe {
            asm!(
                ".arch armv8.5-a",
                "dsb sy",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                "msr SCTLR_EL12, {0}",
                "isb",
                in(reg) state.sctlr,
                options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "dsb sy",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                "msr SCTLR_EL1, {0}",
                "isb",
                in(reg) state.sctlr,
                options(nostack, preserves_flags)
            );
        }
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1SmcRoutingState {
    hcr: u64,
}

/// Routes SMC instructions executed at EL1 to EL2 and returns the prior HCR_EL2.
///
/// # Safety
///
/// The caller must execute at EL2, exclusively own HCR_EL2 for the duration of
/// the lower-EL transition, and restore the returned state afterward.
pub unsafe fn route_el1_smc_to_el2() -> Option<El1SmcRoutingState> {
    if current_el() != 2 {
        return None;
    }
    let hcr: u64;
    // SAFETY: The EL2 transition owns HCR_EL2 until the matching restore.
    unsafe {
        asm!(
            "mrs {0}, HCR_EL2",
            out(reg) hcr,
            options(nomem, nostack, preserves_flags)
        );
        let routed = hcr | (1 << 19);
        asm!(
            "msr HCR_EL2, {0}",
            "isb",
            in(reg) routed,
            options(nostack, preserves_flags)
        );
    }
    Some(El1SmcRoutingState { hcr })
}

/// Restores HCR_EL2 after [`route_el1_smc_to_el2`].
///
/// # Safety
///
/// The state must originate from the same PE, with no intervening owner of
/// HCR_EL2.
pub unsafe fn restore_el1_smc_routing(state: El1SmcRoutingState) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: The state was captured by route_el1_smc_to_el2 on this PE.
    unsafe {
        asm!(
            "msr HCR_EL2, {0}",
            "isb",
            in(reg) state.hcr,
            options(nostack, preserves_flags)
        );
    }
    true
}

/// Installs a current-EL stage-1 regime and returns the complete prior state.
///
/// # Safety
///
/// `ttbr0` must address a live translation table compatible with `tcr`; the
/// caller must own the current translation regime and prevent concurrent use.
pub unsafe fn install_stage1(ttbr0: u64, tcr: u64, mair: u64) -> Option<Stage1State> {
    let el = current_el();
    let (old_ttbr0, old_tcr, old_mair, old_sctlr): (u64, u64, u64, u64);
    // SAFETY: The adapter has reserved the new tables, preserved the previous
    // regime, and invokes this with interrupts controlled by firmware.
    unsafe {
        match el {
            2 => asm!(
                "mrs {0}, TTBR0_EL2", "mrs {1}, TCR_EL2", "mrs {2}, MAIR_EL2", "mrs {3}, SCTLR_EL2",
                out(reg) old_ttbr0, out(reg) old_tcr, out(reg) old_mair, out(reg) old_sctlr,
                options(nostack, preserves_flags)
            ),
            3 => asm!(
                "mrs {0}, TTBR0_EL3", "mrs {1}, TCR_EL3", "mrs {2}, MAIR_EL3", "mrs {3}, SCTLR_EL3",
                out(reg) old_ttbr0, out(reg) old_tcr, out(reg) old_mair, out(reg) old_sctlr,
                options(nostack, preserves_flags)
            ),
            _ => return None,
        }
        asm!("dsb ishst", options(nostack, preserves_flags));
        let new_sctlr = if old_sctlr & 1 == 0 {
            0x0000_0000_30d0_1805
        } else {
            old_sctlr | 1
        };
        match el {
            2 => asm!(
                "msr TTBR0_EL2, {0}", "msr TCR_EL2, {1}", "msr MAIR_EL2, {2}",
                "msr SCTLR_EL2, {3}",
                in(reg) ttbr0, in(reg) tcr, in(reg) mair, in(reg) new_sctlr,
                options(nostack, preserves_flags)
            ),
            3 => asm!(
                "msr TTBR0_EL3, {0}", "msr TCR_EL3, {1}", "msr MAIR_EL3, {2}",
                "msr SCTLR_EL3, {3}",
                in(reg) ttbr0, in(reg) tcr, in(reg) mair, in(reg) new_sctlr,
                options(nostack, preserves_flags)
            ),
            _ => return None,
        }
        match el {
            2 => asm!(
                "isb",
                "tlbi alle2is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            ),
            3 => asm!(
                "isb",
                "tlbi alle3is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            ),
            _ => return None,
        }
    }
    Some(Stage1State {
        ttbr0: old_ttbr0,
        tcr: old_tcr,
        mair: old_mair,
        sctlr: old_sctlr,
        el,
    })
}

/// Installs a changed EL2 stage-1 geometry with translation disabled during
/// the TCR/TTBR transition.
///
/// # Safety
///
/// The caller must ensure the executing code, stack, and vector path are
/// identity-addressable while SCTLR_EL2.M is clear and exclusively own EL2
/// translation state until restoration.
pub unsafe fn install_el2_stage1_geometry(
    ttbr0: u64,
    tcr: u64,
    mair: u64,
    transition_stack: Option<TransitionStack>,
) -> Option<GeometryStage1State> {
    if current_el() != 2 {
        return None;
    }
    let old_ttbr0: u64;
    let old_tcr: u64;
    let old_mair: u64;
    let old_sctlr: u64;
    let old_tcr2: u64;
    let old_vbar: u64;
    let (
        stack_physical,
        stack_virtual,
        recovery_root,
        recovery_tcr,
        recovery_mair,
        recovery_vector,
    ) = transition_stack
        .map(|stack| {
            (
                stack.physical_top,
                stack.virtual_top,
                stack.recovery_root,
                stack.recovery_tcr,
                stack.recovery_mair,
                stack.recovery_vector,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0));
    if (stack_physical == 0) != (stack_virtual == 0)
        || stack_physical & 0xf != 0
        || stack_virtual & 0xf != 0
        || (stack_physical != 0
            && (recovery_root == 0
                || recovery_root & 0xfff != 0
                || recovery_tcr == 0
                || recovery_vector == 0
                || recovery_vector & 0x7ff != 0))
    {
        return None;
    }
    // SAFETY: The entire MMU-off interval is one nostack assembly block and
    // the caller guarantees identity addressing throughout it.
    unsafe {
        asm!(
            "mov {old_sp}, sp",
            "mrs {old_ttbr0}, TTBR0_EL2",
            "mrs {old_tcr}, TCR_EL2",
            "mrs {old_mair}, MAIR_EL2",
            "mrs {old_sctlr}, SCTLR_EL2",
            "mrs {old_tcr2}, S3_4_C2_C0_3",
            "mrs {old_vbar}, VBAR_EL2",
            "msr VBAR_EL2, {recovery_vector}",
            "isb",
            "movz x12, #0",
            "movk x12, #0x1c0a, lsl #16",
            "mov w13, #0x30",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "bic x9, {old_sctlr}, #1",
            "orr x10, {old_sctlr}, #1",
            "bic x10, x10, #0x80000",
            "mov x11, #0x33",
            "bic x11, {old_tcr2}, x11",
            "msr SCTLR_EL2, x9",
            "isb",
            "cbz {stack_physical}, 10f",
            "mov sp, {stack_physical}",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            // Enter an independently owned, conventional 4 KiB identity
            // translation before touching the candidate geometry.
            "msr S3_4_C2_C0_3, x11",
            "msr TTBR0_EL2, {recovery_root}",
            "msr TCR_EL2, {recovery_tcr}",
            "msr MAIR_EL2, {recovery_mair}",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, x10",
            "isb",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "mrs x9, SCTLR_EL2",
            "bic x9, x9, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "10:",
            "mov w13, #0x31",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr S3_4_C2_C0_3, x11",
            "msr TTBR0_EL2, {ttbr0}",
            "msr TCR_EL2, {tcr}",
            "msr MAIR_EL2, {mair}",
            "isb",
            "mov w13, #0x32",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "adr x14, 9f",
            "at s1e2r, x14",
            "isb",
            "mrs x14, PAR_EL1",
            "tbnz x14, #0, 8f",
            "mov w13, #0x50",
            "b 7f",
            "8:",
            "mov w13, #0x46",
            "7:",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "mov w13, #0x33",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "msr SCTLR_EL2, x10",
            "isb",
            "cbz {stack_virtual}, 11f",
            "mov sp, {stack_virtual}",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "mov sp, {old_sp}",
            "11:",
            "9:",
            "mov w13, #0x34",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            old_ttbr0 = out(reg) old_ttbr0,
            old_tcr = out(reg) old_tcr,
            old_mair = out(reg) old_mair,
            old_sctlr = out(reg) old_sctlr,
            old_tcr2 = out(reg) old_tcr2,
            old_vbar = out(reg) old_vbar,
            old_sp = out(reg) _,
            ttbr0 = in(reg) ttbr0,
            tcr = in(reg) tcr,
            mair = in(reg) mair,
            stack_physical = in(reg) stack_physical,
            stack_virtual = in(reg) stack_virtual,
            recovery_root = in(reg) recovery_root,
            recovery_tcr = in(reg) recovery_tcr,
            recovery_mair = in(reg) recovery_mair,
            recovery_vector = in(reg) recovery_vector,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            options()
        );
    }
    Some(GeometryStage1State {
        stage1: Stage1State {
            ttbr0: old_ttbr0,
            tcr: old_tcr,
            mair: old_mair,
            sctlr: old_sctlr,
            el: 2,
        },
        tcr2: old_tcr2,
        transition_stack,
        previous_vbar: old_vbar,
    })
}

/// Restores state captured by [`install_el2_stage1_geometry`].
///
/// # Safety
///
/// The paired install's identity-addressing and exclusivity invariants must
/// remain valid until this function completes.
pub unsafe fn restore_el2_stage1_geometry(state: GeometryStage1State) -> bool {
    if current_el() != 2 || state.stage1.el != 2 {
        return false;
    }
    let stack_physical = state.transition_stack.map_or(0, |stack| stack.physical_top);
    let recovery_root = state
        .transition_stack
        .map_or(0, |stack| stack.recovery_root);
    let recovery_tcr = state.transition_stack.map_or(0, |stack| stack.recovery_tcr);
    let recovery_mair = state
        .transition_stack
        .map_or(0, |stack| stack.recovery_mair);
    let recovery_tcr2 = state.tcr2 & !0x33;
    // SAFETY: The MMU-off interval uses only the independently owned physical
    // transition stack and returns to the exact saved translation state.
    unsafe {
        asm!(
            "mov {old_sp}, sp",
            "mrs x9, SCTLR_EL2",
            "orr x10, x9, #1",
            "bic x10, x10, #0x80000",
            "bic x9, x9, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "cbz {stack_physical}, 10f",
            "mov sp, {stack_physical}",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "msr S3_4_C2_C0_3, {recovery_tcr2}",
            "msr TTBR0_EL2, {recovery_root}",
            "msr TCR_EL2, {recovery_tcr}",
            "msr MAIR_EL2, {recovery_mair}",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, x10",
            "isb",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "bic x9, x10, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "10:",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr S3_4_C2_C0_3, {tcr2}",
            "msr TTBR0_EL2, {ttbr0}",
            "msr TCR_EL2, {tcr}",
            "msr MAIR_EL2, {mair}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, {saved_sctlr}",
            "isb",
            "msr VBAR_EL2, {previous_vbar}",
            "isb",
            "cbz {stack_physical}, 11f",
            "mov sp, {old_sp}",
            "11:",
            ttbr0 = in(reg) state.stage1.ttbr0,
            tcr = in(reg) state.stage1.tcr,
            mair = in(reg) state.stage1.mair,
            saved_sctlr = in(reg) state.stage1.sctlr,
            tcr2 = in(reg) state.tcr2,
            stack_physical = in(reg) stack_physical,
            recovery_root = in(reg) recovery_root,
            recovery_tcr = in(reg) recovery_tcr,
            recovery_mair = in(reg) recovery_mair,
            recovery_tcr2 = in(reg) recovery_tcr2,
            previous_vbar = in(reg) state.previous_vbar,
            old_sp = out(reg) _,
            out("x9") _,
            out("x10") _,
            options()
        );
    }
    true
}

/// Installs an EL2 stage-1 D128 translation using the architectural 128-bit
/// TTBR transfer and permission-indirection registers.
///
/// # Safety
///
/// The caller must provide identity mappings for the executing code, stack,
/// vectors, and recovery state, and exclusively own every affected register
/// until [`restore_el2_stage1_d128`] completes.
pub unsafe fn install_el2_stage1_d128(
    ttbr0_low: u64,
    ttbr0_high: u64,
    tcr: u64,
    memory: Stage1MemoryRegisters,
    pir: u64,
    pire0: u64,
    transition_stack: Option<TransitionStack>,
) -> Option<D128Stage1State> {
    if current_el() != 2 {
        return None;
    }
    let old_ttbr0_low: u64;
    let old_ttbr0_high: u64;
    let old_tcr: u64;
    let old_mair: u64;
    let old_mair2: u64;
    let old_sctlr: u64;
    let old_tcr2: u64;
    let old_pir: u64;
    let old_pire0: u64;
    let old_vbar: u64;
    let (
        stack_physical,
        stack_virtual,
        recovery_root,
        recovery_tcr,
        recovery_mair,
        recovery_vector,
    ) = transition_stack
        .map(|stack| {
            (
                stack.physical_top,
                stack.virtual_top,
                stack.recovery_root,
                stack.recovery_tcr,
                stack.recovery_mair,
                stack.recovery_vector,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0));
    if (stack_physical == 0) != (stack_virtual == 0)
        || stack_physical & 0xf != 0
        || stack_virtual & 0xf != 0
        || (stack_physical != 0
            && (recovery_root == 0
                || recovery_root & 0xfff != 0
                || recovery_tcr == 0
                || recovery_vector == 0
                || recovery_vector & 0x7ff != 0))
    {
        return None;
    }
    unsafe {
        asm!(
            "mrs {old_mair2}, S3_4_C10_C3_1",
            old_mair2 = out(reg) old_mair2,
            options(nomem, nostack, preserves_flags)
        );
    }
    let old_hcrx: u64;
    unsafe {
        asm!(
            "mrs {old}, S3_4_C1_C2_2",
            "orr x9, {old}, #0x20000",
            "orr x9, x9, #0x4000",
            "msr S3_4_C1_C2_2, x9",
            "isb",
            old = out(reg) old_hcrx,
            out("x9") _,
            options(nostack, preserves_flags)
        );
    }
    // SAFETY: The MMU-off interval switches to independently owned stack
    // backing. Fixed adjacent registers are used because MSRR/MRRS require an
    // even/odd architectural register pair.
    unsafe {
        asm!(
            ".arch_extension d128",
            "mov x8, sp",
            "movz x12, #0",
            "movk x12, #0x1c0a, lsl #16",
            "mov w13, #0x41",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "mrrs x2, x3, TTBR0_EL2",
            "mov w13, #0x42",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "mrs {old_tcr}, TCR_EL2",
            "mrs {old_mair}, MAIR_EL2",
            "mrs {old_sctlr}, SCTLR_EL2",
            "mrs {old_tcr2}, S3_4_C2_C0_3",
            "mrs {old_pir}, S3_4_C10_C2_3",
            "mrs {old_pire0}, S3_4_C10_C2_2",
            "mrs {old_vbar}, VBAR_EL2",
            "msr VBAR_EL2, x22",
            "isb",
            "mov w13, #0x43",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "bic x9, {old_sctlr}, #1",
            "orr x10, {old_sctlr}, #1",
            "bic x10, x10, #0x80000",
            // TCR2_EL2.D128 (bit 5) selects 128-bit descriptors and PIE
            // (bit 1) enables the permission indices carried by those leaves.
            "orr x11, {old_tcr2}, #0x30",
            "orr x11, x11, #0x3",
            "msr SCTLR_EL2, x9",
            "isb",
            "cbz x16, 10f",
            "mov sp, x16",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            // Prove the invariant conventional recovery translation before
            // installing the candidate D128 register set.
            "mov x15, #0x33",
            "bic x15, {old_tcr2}, x15",
            "msr S3_4_C2_C0_3, x15",
            "msr TTBR0_EL2, x18",
            "msr TCR_EL2, x21",
            "msr MAIR_EL2, x20",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, x10",
            "isb",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "mrs x9, SCTLR_EL2",
            "bic x9, x9, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "10:",
            "mov w13, #0x44",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr S3_4_C2_C0_3, x11",
            "mov w13, #0x45",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "msr TCR_EL2, {tcr}",
            "msr MAIR_EL2, {mair}",
            "msr S3_4_C10_C3_1, x23",
            "msr S3_4_C10_C2_3, {pir}",
            "msr S3_4_C10_C2_2, {pire0}",
            "mov w13, #0x46",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "mov x0, {ttbr0_low}",
            "mov x1, {ttbr0_high}",
            "msrr TTBR0_EL2, x0, x1",
            "mov w13, #0x47",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "isb",
            "mov w13, #0x49",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "tlbi alle2is",
            "mov w13, #0x4a",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "dsb ish",
            "mov w13, #0x4b",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "isb",
            "mov w13, #0x4c",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "adr x14, 9f",
            "mov x15, x14",
            "at s1e2r, x14",
            "isb",
            "mrs x14, PAR_EL1",
            "tbnz x14, #0, 8f",
            "mov w13, #0x50",
            "b 7f",
            "8:",
            "mov w13, #0x46",
            "7:",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "mov w13, #0x59",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "tbnz x14, #0, 6f",
            "eor x15, x15, x14",
            "lsl x15, x15, #12",
            "lsr x15, x15, #24",
            "cbnz x15, 5f",
            "mov w13, #0x51",
            "b 4f",
            "5:",
            "mov w13, #0x57",
            "b 4f",
            "6:",
            "mov w13, #0x58",
            "4:",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            "msr SCTLR_EL2, x10",
            "isb",
            "cbz x17, 11f",
            "mov sp, x17",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "mov sp, x8",
            "11:",
            "9:",
            "mov w13, #0x48",
            "str w13, [x12]",
            "mov w13, #0xa",
            "str w13, [x12]",
            old_tcr = out(reg) old_tcr,
            old_mair = out(reg) old_mair,
            old_sctlr = out(reg) old_sctlr,
            old_tcr2 = out(reg) old_tcr2,
            old_pir = out(reg) old_pir,
            old_pire0 = out(reg) old_pire0,
            old_vbar = out(reg) old_vbar,
            ttbr0_low = in(reg) ttbr0_low,
            ttbr0_high = in(reg) ttbr0_high,
            tcr = in(reg) tcr,
            mair = in(reg) memory.mair,
            in("x23") memory.mair2,
            pir = in(reg) pir,
            pire0 = in(reg) pire0,
            in("x16") stack_physical,
            in("x17") stack_virtual,
            in("x18") recovery_root,
            in("x21") recovery_tcr,
            in("x20") recovery_mair,
            in("x22") recovery_vector,
            out("x0") _,
            out("x1") _,
            out("x2") old_ttbr0_low,
            out("x3") old_ttbr0_high,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            options()
        );
    }
    Some(D128Stage1State {
        stage1: Stage1State {
            ttbr0: old_ttbr0_low,
            tcr: old_tcr,
            mair: old_mair,
            sctlr: old_sctlr,
            el: 2,
        },
        mair2: old_mair2,
        ttbr0_high: old_ttbr0_high,
        tcr2: old_tcr2,
        pir: old_pir,
        pire0: old_pire0,
        hcrx: Some(old_hcrx),
        transition_stack,
        previous_vbar: old_vbar,
    })
}

/// Restores every register captured by [`install_el2_stage1_d128`].
///
/// # Safety
///
/// The paired install's identity-mapping and exclusive-ownership invariants
/// must remain valid until this function returns.
pub unsafe fn restore_el2_stage1_d128(state: D128Stage1State) -> bool {
    if current_el() != 2 || state.stage1.el != 2 || state.hcrx.is_none() {
        return false;
    }
    let stack_physical = state.transition_stack.map_or(0, |stack| stack.physical_top);
    let recovery_root = state
        .transition_stack
        .map_or(0, |stack| stack.recovery_root);
    let recovery_tcr = state.transition_stack.map_or(0, |stack| stack.recovery_tcr);
    let recovery_mair = state
        .transition_stack
        .map_or(0, |stack| stack.recovery_mair);
    let recovery_tcr2 = state.tcr2 & !0x33;
    let hcrx = state.hcrx.unwrap_or(0);
    unsafe {
        asm!(
            ".arch_extension d128",
            "mov x8, sp",
            "mrs x9, SCTLR_EL2",
            "orr x10, x9, #1",
            "bic x10, x10, #0x80000",
            "bic x9, x9, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "cbz x16, 10f",
            "mov sp, x16",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "msr S3_4_C2_C0_3, x11",
            "msr TTBR0_EL2, x17",
            "msr TCR_EL2, x18",
            "msr MAIR_EL2, x21",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, x10",
            "isb",
            "str xzr, [sp, #-16]!",
            "ldr x9, [sp], #16",
            "bic x9, x10, #1",
            "msr SCTLR_EL2, x9",
            "isb",
            "10:",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr S3_4_C10_C2_3, {pir}",
            "msr S3_4_C10_C2_2, {pire0}",
            "mov x0, {ttbr0_low}",
            "mov x1, {ttbr0_high}",
            "msrr TTBR0_EL2, x0, x1",
            "msr TCR_EL2, {tcr}",
            "msr MAIR_EL2, {mair}",
            "msr S3_4_C10_C3_1, x23",
            "msr S3_4_C2_C0_3, {tcr2}",
            "msr S3_4_C1_C2_2, {hcrx}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL2, {sctlr}",
            "isb",
            "msr VBAR_EL2, {previous_vbar}",
            "isb",
            "cbz x16, 11f",
            "mov sp, x8",
            "11:",
            ttbr0_low = in(reg) state.stage1.ttbr0,
            ttbr0_high = in(reg) state.ttbr0_high,
            tcr = in(reg) state.stage1.tcr,
            mair = in(reg) state.stage1.mair,
            in("x23") state.mair2,
            sctlr = in(reg) state.stage1.sctlr,
            tcr2 = in(reg) state.tcr2,
            pir = in(reg) state.pir,
            pire0 = in(reg) state.pire0,
            hcrx = in(reg) hcrx,
            previous_vbar = in(reg) state.previous_vbar,
            in("x16") stack_physical,
            in("x17") recovery_root,
            in("x18") recovery_tcr,
            in("x21") recovery_mair,
            in("x11") recovery_tcr2,
            out("x0") _,
            out("x1") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            options()
        );
    }
    true
}

/// Installs a D128 stage-1 translation in the inactive EL1 register bank.
///
/// # Safety
///
/// The caller must execute at EL2, exclusively own the EL1 context and all
/// supplied tables, and retain that ownership until
/// [`restore_el1_stage1_d128`] completes.
pub unsafe fn install_el1_stage1_d128(
    ttbr0_low: u64,
    ttbr0_high: u64,
    tcr: u64,
    memory: Stage1MemoryRegisters,
    pir: u64,
    pire0: u64,
) -> Option<D128Stage1State> {
    if current_el() != 2 {
        return None;
    }
    let hcr: u64;
    // D128 is installed into the guest EL1 bank. EL12 D128 aliases require a
    // distinct host-regime implementation and must not be conflated here.
    unsafe { asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags)) };
    if hcr & (1 << 34) != 0 {
        return None;
    }
    let old_ttbr0_low: u64;
    let old_ttbr0_high: u64;
    let old_tcr: u64;
    let old_mair: u64;
    let old_mair2: u64;
    let old_sctlr: u64;
    let old_tcr2: u64;
    let old_pir: u64;
    let old_pire0: u64;
    let old_hcrx: u64;
    unsafe {
        asm!(
            "mrs {old}, S3_4_C1_C2_2",
            "orr x9, {old}, #0x20000",
            "orr x9, x9, #0x4000",
            "msr S3_4_C1_C2_2, x9",
            "isb",
            old = out(reg) old_hcrx,
            out("x9") _,
            options(nostack, preserves_flags)
        );
    }
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrrs x2, x3, TTBR0_EL1",
            "mrs {old_tcr}, TCR_EL1",
            "mrs {old_mair}, MAIR_EL1",
            "mrs {old_mair2}, S3_0_C10_C3_1",
            "mrs {old_sctlr}, SCTLR_EL1",
            "mrs {old_tcr2}, S3_0_C2_C0_3",
            "mrs {old_pir}, S3_0_C10_C2_3",
            "mrs {old_pire0}, S3_0_C10_C2_2",
            "bic x9, {old_sctlr}, #1",
            "orr x10, {old_sctlr}, #1",
            "bic x10, x10, #0x80000",
            "orr x11, {old_tcr2}, #0x30",
            "orr x11, x11, #0x3",
            "msr SCTLR_EL1, x9",
            "isb",
            "msr S3_0_C2_C0_3, x11",
            "msr TCR_EL1, {tcr}",
            "msr MAIR_EL1, {mair}",
            "msr S3_0_C10_C3_1, {mair2}",
            "msr S3_0_C10_C2_3, {pir}",
            "msr S3_0_C10_C2_2, {pire0}",
            "mov x0, {ttbr0_low}",
            "mov x1, {ttbr0_high}",
            "msrr TTBR0_EL1, x0, x1",
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL1, x10",
            "isb",
            old_tcr = out(reg) old_tcr,
            old_mair = out(reg) old_mair,
            old_mair2 = out(reg) old_mair2,
            old_sctlr = out(reg) old_sctlr,
            old_tcr2 = out(reg) old_tcr2,
            old_pir = out(reg) old_pir,
            old_pire0 = out(reg) old_pire0,
            ttbr0_low = in(reg) ttbr0_low,
            ttbr0_high = in(reg) ttbr0_high,
            tcr = in(reg) tcr,
            mair = in(reg) memory.mair,
            mair2 = in(reg) memory.mair2,
            pir = in(reg) pir,
            pire0 = in(reg) pire0,
            out("x0") _,
            out("x1") _,
            out("x2") old_ttbr0_low,
            out("x3") old_ttbr0_high,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            options(nostack, preserves_flags)
        );
    }
    Some(D128Stage1State {
        stage1: Stage1State {
            ttbr0: old_ttbr0_low,
            tcr: old_tcr,
            mair: old_mair,
            sctlr: old_sctlr,
            el: 1,
        },
        mair2: old_mair2,
        ttbr0_high: old_ttbr0_high,
        tcr2: old_tcr2,
        pir: old_pir,
        pire0: old_pire0,
        hcrx: Some(old_hcrx),
        transition_stack: None,
        previous_vbar: 0,
    })
}

/// Restores state captured by [`install_el1_stage1_d128`].
///
/// # Safety
///
/// The state and exclusive EL1 ownership must originate from the paired
/// installer on this PE.
pub unsafe fn restore_el1_stage1_d128(state: D128Stage1State) -> bool {
    if current_el() != 2 || state.stage1.el != 1 {
        return false;
    }
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrs x9, SCTLR_EL1",
            "bic x9, x9, #1",
            "msr SCTLR_EL1, x9",
            "isb",
            "msr S3_0_C10_C2_3, {pir}",
            "msr S3_0_C10_C2_2, {pire0}",
            "mov x0, {ttbr0_low}",
            "mov x1, {ttbr0_high}",
            "msrr TTBR0_EL1, x0, x1",
            "msr TCR_EL1, {tcr}",
            "msr MAIR_EL1, {mair}",
            "msr S3_0_C10_C3_1, {mair2}",
            "msr S3_0_C2_C0_3, {tcr2}",
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL1, {sctlr}",
            "isb",
            ttbr0_low = in(reg) state.stage1.ttbr0,
            ttbr0_high = in(reg) state.ttbr0_high,
            tcr = in(reg) state.stage1.tcr,
            mair = in(reg) state.stage1.mair,
            mair2 = in(reg) state.mair2,
            tcr2 = in(reg) state.tcr2,
            pir = in(reg) state.pir,
            pire0 = in(reg) state.pire0,
            sctlr = in(reg) state.stage1.sctlr,
            out("x0") _,
            out("x1") _,
            out("x9") _,
            options(nostack, preserves_flags)
        );
        if let Some(hcrx) = state.hcrx {
            asm!(
                "msr S3_4_C1_C2_2, {0}",
                "isb",
                in(reg) hcrx,
                options(nostack, preserves_flags)
            );
        }
    }
    true
}

/// Restores a stage-1 state returned by [`install_stage1`].
///
/// # Safety
///
/// The state must originate from the same PE and exception level, with no
/// intervening owner of the translation regime.
pub unsafe fn restore_stage1(state: Stage1State) -> bool {
    if current_el() != state.el {
        return false;
    }
    // SAFETY: State was captured at the same EL by install_stage1.
    unsafe {
        asm!("dsb ishst", options(nostack, preserves_flags));
        match state.el {
            2 => {
                asm!("msr SCTLR_EL2, {0}", "msr TTBR0_EL2, {1}", "msr TCR_EL2, {2}", "msr MAIR_EL2, {3}",
                in(reg) state.sctlr, in(reg) state.ttbr0, in(reg) state.tcr, in(reg) state.mair, options(nostack, preserves_flags))
            }
            3 => {
                asm!("msr SCTLR_EL3, {0}", "msr TTBR0_EL3, {1}", "msr TCR_EL3, {2}", "msr MAIR_EL3, {3}",
                in(reg) state.sctlr, in(reg) state.ttbr0, in(reg) state.tcr, in(reg) state.mair, options(nostack, preserves_flags))
            }
            _ => return false,
        }
        match state.el {
            2 => asm!(
                "isb",
                "tlbi alle2is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            ),
            3 => asm!(
                "isb",
                "tlbi alle3is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            ),
            _ => return false,
        }
    }
    true
}

/// Installs the EL1 stage-1 regime while executing at EL2.
///
/// # Safety
///
/// `ttbr0` must address a live table compatible with `tcr`. The caller must
/// exclusively own the EL1 context until [`restore_el1_stage1`] completes.
pub unsafe fn install_el1_stage1(ttbr0: u64, tcr: u64, mair: u64) -> Option<Stage1State> {
    if current_el() != 2 {
        return None;
    }
    let (old_ttbr0, old_tcr, old_mair, old_sctlr): (u64, u64, u64, u64);
    let hcr: u64;
    // SAFETY: EL12 aliases select the guest EL1 register bank under VHE and
    // ordinary EL1 registers otherwise; no EL1 code executes during mutation.
    unsafe {
        asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
        if hcr & (1 << 34) != 0 {
            asm!(
            ".arch armv8.5-a",
            "mrs {0}, TTBR0_EL12",
            "mrs {1}, TCR_EL12",
            "mrs {2}, MAIR_EL12",
            "mrs {3}, SCTLR_EL12",
            out(reg) old_ttbr0,
            out(reg) old_tcr,
            out(reg) old_mair,
            out(reg) old_sctlr,
            options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "mrs {0}, TTBR0_EL1",
                "mrs {1}, TCR_EL1",
                "mrs {2}, MAIR_EL1",
                "mrs {3}, SCTLR_EL1",
                out(reg) old_ttbr0,
                out(reg) old_tcr,
                out(reg) old_mair,
                out(reg) old_sctlr,
                options(nostack, preserves_flags)
            );
        }
        let new_sctlr = if old_sctlr & 1 == 0 {
            0x0000_0000_30d0_1805
        } else {
            old_sctlr | 1
        };
        if hcr & (1 << 34) != 0 {
            asm!(
            ".arch armv8.5-a",
            "dsb ishst",
            "msr TTBR0_EL12, {0}",
            "msr TCR_EL12, {1}",
            "msr MAIR_EL12, {2}",
            "msr SCTLR_EL12, {3}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            in(reg) ttbr0,
            in(reg) tcr,
            in(reg) mair,
            in(reg) new_sctlr,
            options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "dsb ishst",
                "msr TTBR0_EL1, {0}",
                "msr TCR_EL1, {1}",
                "msr MAIR_EL1, {2}",
                "msr SCTLR_EL1, {3}",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                in(reg) ttbr0,
                in(reg) tcr,
                in(reg) mair,
                in(reg) new_sctlr,
                options(nostack, preserves_flags)
            );
        }
    }
    Some(Stage1State {
        ttbr0: old_ttbr0,
        tcr: old_tcr,
        mair: old_mair,
        sctlr: old_sctlr,
        el: 1,
    })
}

/// Restores a state returned by [`install_el1_stage1`].
///
/// # Safety
///
/// The state must originate on this PE with no intervening EL1 owner.
pub unsafe fn restore_el1_stage1(state: Stage1State) -> bool {
    if current_el() != 2 || state.el != 1 {
        return false;
    }
    // SAFETY: The state was captured from the EL12 aliases on this PE.
    unsafe {
        let hcr: u64;
        asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
        if hcr & (1 << 34) != 0 {
            asm!(
            ".arch armv8.5-a",
            "dsb ishst",
            "msr SCTLR_EL12, {0}",
            "msr TTBR0_EL12, {1}",
            "msr TCR_EL12, {2}",
            "msr MAIR_EL12, {3}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            in(reg) state.sctlr,
            in(reg) state.ttbr0,
            in(reg) state.tcr,
            in(reg) state.mair,
            options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "dsb ishst",
                "msr SCTLR_EL1, {0}",
                "msr TTBR0_EL1, {1}",
                "msr TCR_EL1, {2}",
                "msr MAIR_EL1, {3}",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                in(reg) state.sctlr,
                in(reg) state.ttbr0,
                in(reg) state.tcr,
                in(reg) state.mair,
                options(nostack, preserves_flags)
            );
        }
    }
    true
}

/// Replaces the active EL1 TTBR0 without invalidating cached translations.
///
/// # Safety
///
/// The caller must own the inactive EL1 context, and `ttbr0` must select a
/// valid root whose ASID does not alias incompatible cached translations.
pub unsafe fn switch_el1_ttbr0(ttbr0: u64) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: The adapter owns the inactive EL1 context and serializes switches.
    unsafe {
        let hcr: u64;
        asm!("mrs {0}, HCR_EL2", out(reg) hcr, options(nomem, nostack, preserves_flags));
        if hcr & (1 << 34) != 0 {
            asm!(
                ".arch armv8.5-a",
                "dsb ishst",
                "msr TTBR0_EL12, {0}",
                "isb",
                in(reg) ttbr0,
                options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "dsb ishst",
                "msr TTBR0_EL1, {0}",
                "isb",
                in(reg) ttbr0,
                options(nostack, preserves_flags)
            );
        }
    }
    current_el1_stage1_state().is_some_and(|state| state.ttbr0 == ttbr0)
}

/// Installs an EL2 stage-2 regime and returns the complete prior state.
///
/// # Safety
///
/// `vttbr` must address a live stage-2 root compatible with `vtcr`; the caller
/// must exclusively own HCR_EL2, VTCR_EL2, and VTTBR_EL2 until restoration.
pub unsafe fn install_stage2(vttbr: u64, vtcr: u64) -> Option<Stage2State> {
    if current_el() != 2 {
        return None;
    }
    let old_vttbr: u64;
    let old_vtcr: u64;
    let old_hcr: u64;
    // SAFETY: The EL2 adapter has preserved ownership of the stage-2 regime.
    unsafe {
        asm!("mrs {0}, VTTBR_EL2", "mrs {1}, VTCR_EL2", "mrs {2}, HCR_EL2",
            out(reg) old_vttbr, out(reg) old_vtcr, out(reg) old_hcr, options(nostack, preserves_flags));
        let new_hcr = old_hcr | 1;
        asm!("dsb ishst", "msr VTTBR_EL2, {0}", "msr VTCR_EL2, {1}", "msr HCR_EL2, {2}",
            "isb", "tlbi vmalls12e1is", "dsb ish", "isb",
            in(reg) vttbr, in(reg) vtcr, in(reg) new_hcr, options(nostack, preserves_flags));
    }
    Some(Stage2State {
        vttbr: old_vttbr,
        vtcr: old_vtcr,
        hcr: old_hcr,
    })
}

/// Restores a stage-2 state returned by [`install_stage2`].
///
/// # Safety
///
/// The state must originate from the same PE at EL2, with no intervening owner
/// of HCR_EL2, VTCR_EL2, or VTTBR_EL2.
pub unsafe fn restore_stage2(state: Stage2State) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: State was captured at EL2 by install_stage2.
    unsafe {
        asm!("dsb ishst", "msr HCR_EL2, {0}", "msr VTTBR_EL2, {1}", "msr VTCR_EL2, {2}",
            "isb", "tlbi vmalls12e1is", "dsb ish", "isb",
            in(reg) state.hcr, in(reg) state.vttbr, in(reg) state.vtcr, options(nostack, preserves_flags));
    }
    true
}

/// Installs a D128 EL2 stage-2 regime and returns every affected prior value.
///
/// # Safety
///
/// `vttbr_low:vttbr_high` must identify a live D128 stage-2 root compatible
/// with `vtcr`. The caller must exclusively own HCR_EL2, VTCR_EL2,
/// VTTBR_EL2, and S2PIR_EL2 until [`restore_stage2_d128`] completes.
pub unsafe fn install_stage2_d128(
    vttbr_low: u64,
    vttbr_high: u64,
    vtcr: u64,
    s2pir: u64,
) -> Option<D128Stage2State> {
    if current_el() != 2 || vtcr & (1 << 38) == 0 || vtcr & (1 << 36) == 0 {
        return None;
    }
    let old_vttbr_low: u64;
    let old_vttbr_high: u64;
    let old_vtcr: u64;
    let old_hcr: u64;
    let old_s2pir: u64;
    // SAFETY: HCR_EL2.VM is cleared before changing the stage-2 geometry. The
    // fixed even/odd pairs satisfy MRRS/MSRR's register-pair requirement.
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrrs x2, x3, VTTBR_EL2",
            "mrs {old_vtcr}, VTCR_EL2",
            "mrs {old_hcr}, HCR_EL2",
            "mrs {old_s2pir}, S3_4_C10_C2_5",
            "bic x8, {old_hcr}, #1",
            "msr HCR_EL2, x8",
            "isb",
            "dsb ishst",
            "msr VTCR_EL2, {vtcr}",
            "msr S3_4_C10_C2_5, {s2pir}",
            "mov x0, {vttbr_low}",
            "mov x1, {vttbr_high}",
            "msrr VTTBR_EL2, x0, x1",
            "isb",
            "tlbi vmalls12e1is",
            "dsb ish",
            "orr x8, {old_hcr}, #1",
            "msr HCR_EL2, x8",
            "isb",
            old_vtcr = out(reg) old_vtcr,
            old_hcr = out(reg) old_hcr,
            old_s2pir = out(reg) old_s2pir,
            vtcr = in(reg) vtcr,
            s2pir = in(reg) s2pir,
            vttbr_low = in(reg) vttbr_low,
            vttbr_high = in(reg) vttbr_high,
            lateout("x2") old_vttbr_low,
            lateout("x3") old_vttbr_high,
            out("x0") _,
            out("x1") _,
            out("x8") _,
            options(nostack, preserves_flags)
        );
    }
    Some(D128Stage2State {
        vttbr_low: old_vttbr_low,
        vttbr_high: old_vttbr_high,
        vtcr: old_vtcr,
        hcr: old_hcr,
        s2pir: old_s2pir,
    })
}

/// Restores a D128 stage-2 state returned by [`install_stage2_d128`].
///
/// # Safety
///
/// The state must originate from the paired installer on this PE, with no
/// intervening owner of the affected stage-2 registers.
pub unsafe fn restore_stage2_d128(state: D128Stage2State) -> bool {
    if current_el() != 2 {
        return false;
    }
    // SAFETY: Disabling HCR_EL2.VM makes the D128-to-saved-geometry transition
    // independent of either table set. Full-width VTTBR state is restored.
    unsafe {
        asm!(
            ".arch_extension d128",
            "mrs x8, HCR_EL2",
            "bic x8, x8, #1",
            "msr HCR_EL2, x8",
            "isb",
            "dsb ishst",
            "msr VTCR_EL2, {vtcr}",
            "msr S3_4_C10_C2_5, {s2pir}",
            "mov x0, {vttbr_low}",
            "mov x1, {vttbr_high}",
            "msrr VTTBR_EL2, x0, x1",
            "isb",
            "tlbi vmalls12e1is",
            "dsb ish",
            "msr HCR_EL2, {hcr}",
            "isb",
            vtcr = in(reg) state.vtcr,
            s2pir = in(reg) state.s2pir,
            vttbr_low = in(reg) state.vttbr_low,
            vttbr_high = in(reg) state.vttbr_high,
            hcr = in(reg) state.hcr,
            out("x0") _,
            out("x1") _,
            out("x8") _,
            options(nostack, preserves_flags)
        );
    }
    true
}
