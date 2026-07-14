use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::access::{AccessRequest, AccessResult};
use crate::environment::{Environment, TranslationRegimeEnvironment};
use crate::lower_el::LowerElRequest;
use crate::memory::{MemoryScope, TestMemory};
use crate::translation::{
    HardwareManagedStage1Regime, InstalledTranslation, TestFormat, TestGranule, TestRegime,
    TestRegimeFor,
};
use crate::{
    AddressBits, Capabilities, HarnessError, LookupLevel, Page, RootTableMemory, TestMapper,
    TranslationSetup,
};
use vmsa_test_architecture::AccessWidth;

struct CleanupState(UnsafeCell<bool>);

#[derive(Clone, Copy)]
struct WalkerProbeFormat;

#[derive(Clone, Copy)]
struct WalkerProbeLayout;

impl aarch64_vmsa::descriptor::DescriptorFormat for WalkerProbeFormat {
    type Raw = u64;
    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const OUTPUT_ADDRESS_BITS: u8 = 64;
    const BASE_LOWEST_ROOT_LEVEL: aarch64_vmsa::address::Level = aarch64_vmsa::address::Level::L0;
    const EXTENDED_LOWEST_ROOT_LEVEL: aarch64_vmsa::address::Level =
        aarch64_vmsa::address::Level::new(-20);
    const REQUIRED_FEATURES: aarch64_vmsa::arch::FeatureRequirements =
        aarch64_vmsa::arch::FeatureRequirements::NONE;

    fn invalid() -> Self::Raw {
        0
    }

    fn supports_leaf_level<G: aarch64_vmsa::address::TranslationGranule>(
        _: aarch64_vmsa::address::Level,
    ) -> bool {
        true
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr.read_volatile() }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe { ptr.write_volatile(raw) }
    }
}

impl
    aarch64_vmsa::descriptor::HasLayout<
        aarch64_vmsa::translation::Stage1,
        aarch64_vmsa::address::Granule4KiB,
    > for WalkerProbeFormat
{
    type Layout = WalkerProbeLayout;
}

impl
    aarch64_vmsa::descriptor::DescriptorLayout<
        WalkerProbeFormat,
        aarch64_vmsa::translation::Stage1,
        aarch64_vmsa::address::Granule4KiB,
    > for WalkerProbeLayout
{
    type LeafFields = ();
    type TableFields = ();
    const ADDRESS_FIELD_MASK: u128 = u64::MAX as u128;

    fn kind(raw: u64, _: aarch64_vmsa::address::Level) -> aarch64_vmsa::descriptor::DescriptorKind {
        match raw {
            1 => aarch64_vmsa::descriptor::DescriptorKind::Table,
            2 => aarch64_vmsa::descriptor::DescriptorKind::Block,
            _ => aarch64_vmsa::descriptor::DescriptorKind::Invalid,
        }
    }

    fn decode_leaf_fields(_: u64, _: aarch64_vmsa::address::Level) {}
    fn decode_table_fields(_: u64, _: aarch64_vmsa::address::Level) {}

    fn leaf_descriptor(
        _: aarch64_vmsa::address::PhysAddr,
        _: aarch64_vmsa::address::Level,
        _: (),
    ) -> Result<u64, aarch64_vmsa::descriptor::DescriptorError> {
        Ok(2)
    }

    fn table_descriptor(
        _: aarch64_vmsa::address::PhysAddr,
        _: aarch64_vmsa::table::TableTransition<
            WalkerProbeFormat,
            aarch64_vmsa::address::Granule4KiB,
        >,
        _: (),
    ) -> Result<u64, aarch64_vmsa::descriptor::DescriptorError> {
        Ok(1)
    }

    fn output_address(_: u64, _: aarch64_vmsa::address::Level) -> aarch64_vmsa::address::PhysAddr {
        aarch64_vmsa::address::PhysAddr(u64::MAX)
    }

    fn next_table(
        _: u64,
        level: aarch64_vmsa::address::Level,
    ) -> Option<aarch64_vmsa::descriptor::NextTableDescriptor> {
        Some(aarch64_vmsa::descriptor::NextTableDescriptor {
            address: aarch64_vmsa::address::PhysAddr(1),
            level: level.next(),
            stride_count: 1,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalkerProbeAccessError {
    Rejected,
}

struct WalkerProbeAccess {
    base: NonNull<u64>,
    shape: aarch64_vmsa::table::TableShape<WalkerProbeFormat, aarch64_vmsa::address::Granule4KiB>,
    reject: bool,
}

unsafe impl aarch64_vmsa::table::TableAccess<WalkerProbeFormat, aarch64_vmsa::address::Granule4KiB>
    for WalkerProbeAccess
{
    type Error = WalkerProbeAccessError;

    fn table_at<'a>(
        &'a self,
        _: aarch64_vmsa::table::TableAccessLocation<
            WalkerProbeFormat,
            aarch64_vmsa::address::Granule4KiB,
        >,
    ) -> Result<
        aarch64_vmsa::table::TranslationTable<
            'a,
            WalkerProbeFormat,
            aarch64_vmsa::address::Granule4KiB,
        >,
        Self::Error,
    > {
        if self.reject {
            return Err(WalkerProbeAccessError::Rejected);
        }
        // SAFETY: Every probe keeps its arena-owned 4 KiB root alive. Probe
        // shapes have at most 512 entries, and out-of-range cases fail before
        // a descriptor pointer is formed.
        Ok(unsafe { aarch64_vmsa::table::TranslationTable::from_ptr(self.base, self.shape) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessFailurePoint {
    Map,
    Remap,
    Protect,
    Unmap,
    Invalidation,
    Barrier,
    Tlbi,
    TranslationInstallation,
    PartialCombinedInstallation,
    LowerElEntry,
    LowerElAction,
    LowerElReturn,
    SecondaryPeStartup,
    SecondaryPeRendezvous,
    SecondaryPeAction,
    SecondaryPeTimeout,
    SecondaryPeStop,
    GranuleDelegation,
    RealmCreation,
    RecCreation,
    RecEntry,
    RealmMap,
    RealmMutation,
    RealmDestruction,
    GranuleUndelegation,
    FirmwareCallback,
    TranslationRestoration,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMaintenanceOperation {
    InstructionCoherency { address: u64, bytes: usize },
    CleanData { address: u64, bytes: usize },
    CleanInvalidateData { address: u64, bytes: usize },
    InvalidateData { address: u64, bytes: usize },
    TranslationTableVisibility,
    MultiPeVisibility,
}

#[derive(Clone, Copy)]
struct HarnessFailureInjection {
    point: Option<HarnessFailurePoint>,
    remaining_successes: usize,
}

struct HarnessFailureState(UnsafeCell<HarnessFailureInjection>);

impl HarnessFailureState {
    fn inject(&self, point: HarnessFailurePoint, remaining_successes: usize) {
        // SAFETY: A TestContext and every guard derived from it are single-threaded.
        unsafe {
            *self.0.get() = HarnessFailureInjection {
                point: Some(point),
                remaining_successes,
            };
        }
    }

    fn clear(&self) {
        // SAFETY: Same single-threaded context ownership as `inject`.
        unsafe {
            *self.0.get() = HarnessFailureInjection {
                point: None,
                remaining_successes: 0,
            };
        }
    }

    fn check(&self, point: HarnessFailurePoint) -> Result<(), HarnessError> {
        // SAFETY: Same single-threaded context ownership as `inject`.
        let state = unsafe { &mut *self.0.get() };
        if state.point != Some(point) {
            return Ok(());
        }
        if state.remaining_successes != 0 {
            state.remaining_successes -= 1;
            return Ok(());
        }
        state.point = None;
        Err(HarnessError::InjectedFailure)
    }
}

pub struct TestContext<'a, E: Environment> {
    environment: NonNull<E>,
    memory_scope: MemoryScope,
    cleanup: CleanupState,
    failures: HarnessFailureState,
    _ownership: PhantomData<&'a mut E>,
}

/// Owned memory that remains invariant while a candidate current-EL
/// translation is installed.
///
/// The addresses and backing pages are deliberately private: test logic can
/// retain and validate the sandbox but cannot use it as a raw memory escape.
pub struct TransitionSandbox {
    recovery_root: RootTableMemory,
    stack: Page,
    mailbox: Page,
    stack_address: u64,
    mailbox_address: u64,
    marker: u64,
    granule: crate::Granule,
}

impl TransitionSandbox {
    fn transition_stack(&self) -> crate::translation::TransitionStack {
        let recovery_tcr = crate::vmsa64_el2_stage1_controls(
            crate::Granule::Size4KiB,
            AddressBits::new(48).expect("48-bit recovery input geometry is valid"),
            AddressBits::new(48).expect("48-bit recovery output geometry is valid"),
        )
        .expect("4 KiB EL2 recovery controls are valid")
        .bits();
        crate::translation::TransitionStack {
            physical_top: self.stack.phys_addr() + self.granule.bytes(),
            virtual_top: self.stack_address + self.granule.bytes(),
            granule: self.granule,
            recovery_root: self.recovery_root.phys_addr(),
            recovery_tcr,
            recovery_mair: 0x0000_ff44,
            recovery_vector: vmsa_test_architecture::exception::recovery_vector_address(),
        }
    }
}

impl<'a, E: Environment> TestContext<'a, E> {
    pub(crate) fn new(environment: &'a mut E, memory_scope: MemoryScope) -> Self {
        Self {
            environment: NonNull::from(environment),
            memory_scope,
            cleanup: CleanupState(UnsafeCell::new(false)),
            failures: HarnessFailureState(UnsafeCell::new(HarnessFailureInjection {
                point: None,
                remaining_successes: 0,
            })),
            _ownership: PhantomData,
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        self.environment().capabilities()
    }
    pub fn native_pas(&self) -> crate::PhysicalAddressSpace {
        self.environment().memory_pas()
    }
    pub fn verify_invalid_adapter_transition_rejected(&self) -> bool {
        self.with_environment(Environment::verify_invalid_transition_rejected)
    }
    pub fn verify_common_abi_rejection(&self) -> bool {
        self.environment().verify_common_abi_rejection()
    }
    pub fn verify_fault_normalization(&self) -> bool {
        crate::fault::normalization_self_check()
    }
    pub fn translate_current_stage1(
        &self,
        address: u64,
        access: crate::TranslationQueryAccess,
    ) -> crate::TranslationQueryResult {
        let access = match access {
            crate::TranslationQueryAccess::Read => {
                vmsa_test_architecture::translation::TranslationAccess::Read
            }
            crate::TranslationQueryAccess::Write => {
                vmsa_test_architecture::translation::TranslationAccess::Write
            }
        };
        vmsa_test_architecture::translation::current_stage1(address, access)
            .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                crate::TranslationQueryResult::from_par(address, par)
            })
    }

    pub fn translate_combined_stage1_stage2(
        &self,
        address: u64,
        access: crate::TranslationQueryAccess,
    ) -> crate::TranslationQueryResult {
        let access = match access {
            crate::TranslationQueryAccess::Read => {
                vmsa_test_architecture::translation::TranslationAccess::Read
            }
            crate::TranslationQueryAccess::Write => {
                vmsa_test_architecture::translation::TranslationAccess::Write
            }
        };
        vmsa_test_architecture::translation::combined_stage1_stage2(address, access)
            .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                crate::TranslationQueryResult::from_par(address, par)
            })
    }

    pub fn translate_lower_stage1(
        &self,
        address: u64,
        access: crate::TranslationQueryAccess,
    ) -> crate::TranslationQueryResult {
        match self.lower_el(LowerElRequest::translate(
            address,
            access == crate::TranslationQueryAccess::Write,
        )) {
            AccessResult::Completed { value: par } => {
                crate::TranslationQueryResult::from_par(address, par)
            }
            _ => crate::TranslationQueryResult::Unsupported,
        }
    }
    pub fn allocate_page(&self) -> Result<Page, HarnessError> {
        self.allocate_page_in(self.native_pas())
    }
    pub fn allocate_page_in(&self, pas: crate::PhysicalAddressSpace) -> Result<Page, HarnessError> {
        if pas != self.native_pas() {
            return Err(HarnessError::InvalidState);
        }
        self.with_environment(|environment| environment.memory().allocate_page())
            .map_err(|_| HarnessError::Memory)
    }
    pub fn allocate_contiguous(&self, pages: usize) -> Result<Page, HarnessError> {
        self.allocate_contiguous_in(self.native_pas(), pages)
    }
    pub fn allocate_granule(&self, granule: crate::Granule) -> Result<Page, HarnessError> {
        let pages = (granule.bytes() / 4096) as usize;
        self.with_environment(|environment| {
            environment
                .memory()
                .allocate_aligned_pages(pages, granule.bytes() as usize)
        })
        .map_err(|_| HarnessError::Memory)
    }
    pub fn allocate_contiguous_in(
        &self,
        pas: crate::PhysicalAddressSpace,
        pages: usize,
    ) -> Result<Page, HarnessError> {
        if pas != self.native_pas() {
            return Err(HarnessError::InvalidState);
        }
        self.with_environment(|environment| environment.memory().allocate_pages(pages))
            .map_err(|_| HarnessError::Memory)
    }
    pub fn allocate_root(&self) -> Result<RootTableMemory, HarnessError> {
        self.allocate_root_in(self.native_pas(), crate::Granule::Size4KiB)
    }
    pub fn allocate_root_in(
        &self,
        pas: crate::PhysicalAddressSpace,
        granule: crate::Granule,
    ) -> Result<RootTableMemory, HarnessError> {
        if pas != self.native_pas() {
            return Err(HarnessError::InvalidState);
        }
        let bytes = granule.bytes() as usize;
        self.with_environment(|environment| environment.memory().allocate_root(bytes, bytes))
            .map_err(|_| HarnessError::Memory)
    }
    pub fn allocate_root_16k(&self) -> Result<RootTableMemory, HarnessError> {
        self.allocate_root_in(self.native_pas(), crate::Granule::Size16KiB)
    }
    pub fn allocate_root_64k(&self) -> Result<RootTableMemory, HarnessError> {
        self.allocate_root_in(self.native_pas(), crate::Granule::Size64KiB)
    }

    pub fn verify_translation_table_read_write(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{TableError, TableShape, TranslationTableMut};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(pointer) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        let shape = TableShape::<Vmsa64, Granule4KiB>::root(Level::L0);
        // SAFETY: `root` owns a live, aligned 4 KiB VMSA64 table for the whole
        // lifetime of this bounded verification method.
        let mut table = unsafe { TranslationTableMut::from_ptr(pointer, shape) };
        let entries = table.entries();
        let last = entries - 1;
        let value = 0xfeed_face_cafe_beefu64;
        if table.level() != Level::L0
            || table.stride_count().raw() != 1
            || table.shape() != shape
            || table.base() != pointer
            || entries != 512
            || table.index_bits() != 9
            || table.index_mask() != 0x1ff
            || table.level_shift() != 39
            || table.index_for_va(VirtAddr((last as u64) << 39)) != Some(last)
            || table.read(last) != Some(0)
            || table.entry_ptr(last).is_none()
            || table.entry_ptr(entries).is_some()
            || table.read(entries).is_some()
            || table.write(entries, value)
                != Err(TableError::EntryIndexOutOfRange {
                    index: entries,
                    entries,
                })
            || table.write(last, value).is_err()
            || table.read(last) != Some(value)
            || table.as_table().read(last) != Some(value)
        {
            return false;
        }
        // SAFETY: `last` is in bounds of the live root allocation.
        unsafe { pointer.as_ptr().add(last).read_volatile() == value }
    }

    pub fn verify_walker_access_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(Level::L0),
            reject: true,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr,
            Level::L0,
            access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(0)) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::Access(WalkerProbeAccessError::Rejected))
        )
    }

    pub fn verify_walker_access_location_error(&self) -> bool {
        use aarch64_vmsa::address::Level;
        use aarch64_vmsa::table::AccessError;
        use aarch64_vmsa::translation::walk::WalkError;

        let source = AccessError::InvalidTableLevel {
            root_level: Level::L0,
            level: Level::new(4),
            final_level: Level::L3,
        };
        WalkError::<WalkerProbeAccessError>::from(source) == WalkError::AccessLocation(source)
    }

    pub fn verify_walker_cursor_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkCursorError, WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        let root_level = Level::new(-20);
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(root_level),
            reject: false,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr, root_level, access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(0)) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::Cursor(WalkCursorError::InvalidLevel { level }))
                if level == root_level
        )
    }

    pub fn verify_walker_invalid_table_address_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{TableAddressError, TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        // SAFETY: index zero is inside the live root allocation.
        unsafe { base.as_ptr().write_volatile(1) };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(Level::L0),
            reject: false,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr,
            Level::L0,
            access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(0)) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::InvalidTableAddress(
                TableAddressError::Unaligned {
                    addr: PhysAddr(1),
                    align: 4096,
                }
            ))
        )
    }

    pub fn verify_walker_entry_index_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{NextTable, TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(Level::L3),
            reject: false,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr,
            Level::NEG1,
            access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(512 << 12)) else {
            return false;
        };
        let Ok(zero) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(0)) else {
            return false;
        };
        let Ok(next) = NextTable::<WalkerProbeFormat, Granule4KiB>::new(zero, Level::L3, 4) else {
            return false;
        };
        let Ok(cursor) = cursor.next_table(0, next) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::EntryIndexOutOfRange {
                index: 512,
                entries: 512,
            })
        )
    }

    pub fn verify_walker_final_table_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        // SAFETY: index zero is inside the live root allocation.
        unsafe { base.as_ptr().write_volatile(1) };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(Level::L3),
            reject: false,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr,
            Level::L3,
            access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(0)) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::TableDescriptorAtFinalLevel { level: Level::L3 })
        )
    }

    pub fn verify_walker_output_overflow_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr};
        use aarch64_vmsa::table::{TablePhysAddr, TableShape};
        use aarch64_vmsa::translation::Stage1Walk;
        use aarch64_vmsa::translation::walk::{WalkError, WalkInputAddr, Walker};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Some(base) = NonNull::new(root.virtual_address().cast::<u64>()) else {
            return false;
        };
        // SAFETY: index zero is inside the live root allocation.
        unsafe { base.as_ptr().write_volatile(2) };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let access = WalkerProbeAccess {
            base,
            shape: TableShape::root(Level::L1),
            reject: false,
        };
        let Ok(walker) = Walker::<WalkerProbeFormat, Stage1Walk, Granule4KiB, _>::new(
            root_addr,
            Level::L1,
            access,
        ) else {
            return false;
        };
        let Ok(cursor) = walker.cursor(WalkInputAddr::new(1)) else {
            return false;
        };
        matches!(
            walker.step(cursor),
            Err(WalkError::OutputAddressOverflow {
                base: PhysAddr(u64::MAX),
                offset: 1,
            })
        )
    }

    pub fn verify_recursive_index_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{AccessError, RecursiveTableAccess, TablePhysAddr};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        // SAFETY: This rejection probe cannot construct an access object: the
        // recursive index is checked before any mapping assumption is used.
        matches!(
            unsafe {
                RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(
                    512,
                    VirtAddr(0x1000),
                    root_addr,
                    Level::L0,
                )
            },
            Err(AccessError::RecursiveIndexOutOfRange {
                index: 512,
                entries: 512,
            })
        )
    }

    pub fn verify_recursive_base_errors(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{AccessError, RecursiveTableAccess, TablePhysAddr};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        // SAFETY: Each malformed base is rejected by constructor validation;
        // none of these calls yields an access object or dereferences a VA.
        let zero = unsafe {
            RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(1, VirtAddr(0), root_addr, Level::L0)
        };
        let unaligned = unsafe {
            RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(1, VirtAddr(1), root_addr, Level::L0)
        };
        let wrong_index = unsafe {
            RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(
                1,
                VirtAddr(2 << 39 | 2 << 30 | 2 << 21 | 2 << 12),
                root_addr,
                Level::L0,
            )
        };
        matches!(
            zero,
            Err(AccessError::InvalidRecursiveBase { base: VirtAddr(0) })
        ) && matches!(
            unaligned,
            Err(AccessError::InvalidRecursiveBase { base: VirtAddr(1) })
        ) && matches!(
            wrong_index,
            Err(AccessError::InvalidRecursiveBase { base })
                if base == VirtAddr(2 << 39 | 2 << 30 | 2 << 21 | 2 << 12)
        )
    }

    pub fn verify_recursive_level_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{AccessError, RecursiveTableAccess, TablePhysAddr};

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        // SAFETY: The level is rejected before the recursive mapping is used.
        matches!(
            unsafe {
                RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(
                    1,
                    VirtAddr(0x1000),
                    root_addr,
                    Level::new(4),
                )
            },
            Err(AccessError::RecursiveLevelMismatch)
        )
    }

    pub fn verify_recursive_path_errors(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{AccessError, TableShape, TableWalkPath};

        let parent = TableShape::<Vmsa64, Granule4KiB>::root(Level::L0);
        let child = TableShape::<Vmsa64, Granule4KiB>::root(Level::L1);
        let mut index_path = TableWalkPath::<Vmsa64, Granule4KiB>::root();
        let index_error = index_path.push(Level::L0, parent, child, 512);

        let mut terminal_path = TableWalkPath::<Vmsa64, Granule4KiB>::root();
        if terminal_path.push(Level::L0, parent, child, 0).is_err() {
            return false;
        }
        let terminal_error = terminal_path.push(Level::L0, parent, child, 0);
        index_error
            == Err(AccessError::TablePathIndexOutOfRange {
                index: 512,
                entries: 512,
            })
            && terminal_error
                == Err(AccessError::TablePathTerminalLevelMismatch {
                    expected: Level::L0,
                    actual: Level::L1,
                })
    }

    pub fn verify_recursive_overflow_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule64KiB, Level, PhysAddr, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{
            AccessError, NextTable, RecursiveTableAccess, TableAccess, TableCursor, TablePhysAddr,
        };

        let Ok(root) = self.allocate_root_64k() else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule64KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let recursive_base = (1 << 55) | (1 << 42) | (1 << 29) | (1 << 16);
        // SAFETY: The repeated index geometry is valid. The deliberately wide
        // path below returns AddressOverflow before producing or dereferencing
        // a recursive virtual pointer.
        let Ok(access) = (unsafe {
            RecursiveTableAccess::<Vmsa64, Granule64KiB>::new(
                1,
                VirtAddr(recursive_base),
                root_addr,
                Level::L0,
            )
        }) else {
            return false;
        };
        let Ok(zero) = TablePhysAddr::<Granule64KiB>::new(PhysAddr(0)) else {
            return false;
        };
        let cursor = TableCursor::<Vmsa64, Granule64KiB>::root(root_addr, Level::L0);
        let Ok(cursor) = cursor.next_table(
            0,
            NextTable::new(zero, Level::L1, 4).expect("zero satisfies the wide alignment"),
        ) else {
            return false;
        };
        let Ok(cursor) = cursor.next_table(
            0,
            NextTable::new(zero, Level::L2, 1).expect("zero satisfies table alignment"),
        ) else {
            return false;
        };
        let Ok(location) = cursor.location() else {
            return false;
        };
        matches!(access.table_at(location), Err(AccessError::AddressOverflow))
    }

    pub fn verify_recursive_null_mapping_error(&self) -> bool {
        use aarch64_vmsa::address::{Granule4KiB, Level, PhysAddr, VirtAddr};
        use aarch64_vmsa::descriptor::Vmsa64;
        use aarch64_vmsa::table::{
            AccessError, NextTable, RecursiveTableAccess, TableAccess, TableCursor, TablePhysAddr,
        };

        let Ok(root) = self.allocate_root() else {
            return false;
        };
        let Ok(root_addr) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(root.phys_addr())) else {
            return false;
        };
        let recursive_base = (1 << 39) | (1 << 30) | (1 << 21) | (1 << 12);
        // SAFETY: The repeated index geometry is valid. The path below clears
        // every populated VA field and returns NullMapping before a table is
        // created or any recursive virtual address is dereferenced.
        let Ok(access) = (unsafe {
            RecursiveTableAccess::<Vmsa64, Granule4KiB>::new(
                1,
                VirtAddr(recursive_base),
                root_addr,
                Level::L0,
            )
        }) else {
            return false;
        };
        let Ok(zero) = TablePhysAddr::<Granule4KiB>::new(PhysAddr(0)) else {
            return false;
        };
        let cursor = TableCursor::<Vmsa64, Granule4KiB>::root(root_addr, Level::L0);
        let Ok(cursor) = cursor.next_table(
            0,
            NextTable::new(zero, Level::L1, 4).expect("zero satisfies the wide alignment"),
        ) else {
            return false;
        };
        let Ok(cursor) = cursor.next_table(
            0,
            NextTable::new(zero, Level::L2, 1).expect("zero satisfies table alignment"),
        ) else {
            return false;
        };
        let Ok(location) = cursor.location() else {
            return false;
        };
        matches!(access.table_at(location), Err(AccessError::NullMapping))
    }

    pub fn verify_arena_exhaustion_boundary(&self) -> bool {
        self.with_environment(|environment| {
            let memory = environment.memory();
            let pages = memory.maximum_contiguous_pages();
            pages != 0
                && memory.allocate_pages(pages).is_ok()
                && memory.allocate_page() == Err(crate::MemoryError::Exhausted)
        })
    }

    pub fn arena_allocation_count(&self) -> usize {
        self.with_environment(|environment| environment.memory().allocation_count())
    }

    pub fn with_table_allocation_failure<T>(
        &self,
        successful_allocations: usize,
        operation: impl FnOnce() -> T,
    ) -> Result<T, HarnessError> {
        self.with_memory_failure(
            crate::MemoryFailurePoint::TableFrame,
            successful_allocations,
            operation,
        )
    }

    pub fn with_memory_failure<T>(
        &self,
        point: crate::MemoryFailurePoint,
        successful_allocations: usize,
        operation: impl FnOnce() -> T,
    ) -> Result<T, HarnessError> {
        self.with_environment(|environment| {
            environment
                .memory()
                .inject_failure(point, successful_allocations)
        })
        .map_err(|_| HarnessError::Memory)?;
        let result = operation();
        self.with_environment(|environment| {
            environment.memory().clear_failure(point);
        });
        Ok(result)
    }

    pub fn with_harness_failure<T>(
        &self,
        point: HarnessFailurePoint,
        successful_operations: usize,
        operation: impl FnOnce() -> T,
    ) -> T {
        self.failures.inject(point, successful_operations);
        let result = operation();
        self.failures.clear();
        result
    }

    pub fn offline_mapper(
        &self,
        root: &mut RootTableMemory,
    ) -> Result<TestMapper<E::Regime>, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        self.offline_mapper_for::<E::Regime>(root)
    }

    pub fn offline_mapper_for<R>(
        &self,
        root: &mut RootTableMemory,
    ) -> Result<TestMapper<R>, HarnessError>
    where
        R: TestRegime + TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        self.offline_mapper_for_granule::<R, aarch64_vmsa::address::Granule4KiB>(root)
    }

    pub fn offline_mapper_16k(
        &self,
        root: &mut RootTableMemory,
    ) -> Result<TestMapper<E::Regime, aarch64_vmsa::address::Granule16KiB>, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule16KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule16KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule16KiB,
        >: Copy,
    {
        self.offline_mapper_for_granule::<E::Regime, aarch64_vmsa::address::Granule16KiB>(root)
    }

    pub fn offline_mapper_64k(
        &self,
        root: &mut RootTableMemory,
    ) -> Result<TestMapper<E::Regime, aarch64_vmsa::address::Granule64KiB>, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule64KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule64KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule64KiB,
        >: Copy,
    {
        self.offline_mapper_for_granule::<E::Regime, aarch64_vmsa::address::Granule64KiB>(root)
    }

    pub fn offline_mapper_for_granule<R, G>(
        &self,
        root: &mut RootTableMemory,
    ) -> Result<TestMapper<R, G>, HarnessError>
    where
        R: TestRegime + TestRegimeFor<G>,
        G: TestGranule,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    {
        let capabilities = self.capabilities();
        self.offline_mapper_for_format_with_geometry::<R, G, aarch64_vmsa::descriptor::Vmsa64>(
            root,
            G::DEFAULT_START_LEVEL,
            R::default_input_bits(capabilities),
            capabilities.pa_bits.min(48),
        )
    }

    pub fn offline_mapper_for_format_with_geometry<R, G, F>(
        &self,
        root: &mut RootTableMemory,
        start_level: aarch64_vmsa::address::Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<TestMapper<R, G, F>, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        G: TestGranule,
        F: aarch64_vmsa::descriptor::DescriptorFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
    {
        self.with_environment(|environment| {
            TestMapper::new(
                NonNull::from(environment.memory()),
                root,
                start_level,
                input_bits,
                output_bits,
            )
        })
    }

    pub fn validate_offline_mapper_geometry<R, G, F>(
        &self,
        root: &RootTableMemory,
        start_level: aarch64_vmsa::address::Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<(), crate::MapperConstructionError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        G: TestGranule,
        F: aarch64_vmsa::descriptor::DescriptorFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
    {
        self.with_environment(|environment| {
            TestMapper::<R, G, F>::validate_new(
                NonNull::from(environment.memory()),
                root,
                start_level,
                input_bits,
                output_bits,
            )
        })
    }

    pub fn validate_offline_mapper_geometry_at<R, G, F>(
        &self,
        root_address: u64,
        start_level: aarch64_vmsa::address::Level,
        input_bits: u8,
        output_bits: u8,
    ) -> Result<(), crate::MapperConstructionError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        G: TestGranule,
        F: aarch64_vmsa::descriptor::DescriptorFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
    {
        self.with_environment(|environment| {
            TestMapper::<R, G, F>::validate_new_at(
                NonNull::from(environment.memory()),
                root_address,
                start_level,
                input_bits,
                output_bits,
            )
        })
    }

    pub fn offline_mapper_lpa2_4k(
        &self,
        root: &mut RootTableMemory,
        start_level: LookupLevel,
        input_bits: AddressBits,
        output_bits: AddressBits,
    ) -> Result<
        TestMapper<
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >,
        HarnessError,
    >
    where
        E: TranslationRegimeEnvironment,
        aarch64_vmsa::descriptor::Vmsa64Lpa2: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
    {
        self.offline_mapper_for_format_with_geometry::<
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64Lpa2,
        >(
            root,
            aarch64_vmsa::address::Level::new(start_level.get()),
            input_bits.get(),
            output_bits.get(),
        )
    }

    pub fn offline_mapper_d128_4k(
        &self,
        root: &mut RootTableMemory,
        start_level: LookupLevel,
        input_bits: AddressBits,
        output_bits: AddressBits,
    ) -> Result<
        TestMapper<
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >,
        HarnessError,
    >
    where
        E: TranslationRegimeEnvironment,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
    {
        self.offline_mapper_for_format_with_geometry::<
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >(
            root,
            aarch64_vmsa::address::Level::new(start_level.get()),
            input_bits.get(),
            output_bits.get(),
        )
    }

    pub fn offline_mapper_with_geometry(
        &self,
        root: &mut RootTableMemory,
        start_level: LookupLevel,
        input_bits: AddressBits,
        output_bits: AddressBits,
    ) -> Result<TestMapper<E::Regime>, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        self.offline_mapper_for_format_with_geometry::<
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa64,
        >(
            root,
            aarch64_vmsa::address::Level::new(start_level.get()),
            input_bits.get(),
            output_bits.get(),
        )
    }

    pub fn prepare_transition_runtime<R, G, F>(
        &self,
        mapper: &mut TestMapper<R, G, F>,
        entry: u64,
    ) -> Result<TransitionSandbox, HarnessError>
    where
        R: TestRegimeFor<G>,
        R: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        G: TestGranule,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>>::Layout:
            aarch64_vmsa::descriptor::DescriptorLayout<
                    F,
                    aarch64_vmsa::regime::StageOf<R>,
                    G,
                    LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                    TableFields = aarch64_vmsa::regime::TableFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                >,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        const STACK_ADDRESS: u64 = 0x6b00_0000;
        const MAILBOX_ADDRESS: u64 = 0x6b10_0000;
        const MARKER: u64 = 0x5452_414e_5342_4f58;

        let pages = usize::try_from(G::SIZE / 4096).map_err(|_| HarnessError::Memory)?;
        let align = usize::try_from(G::SIZE).map_err(|_| HarnessError::Memory)?;
        let stack = self
            .with_environment(|environment| {
                environment.memory().allocate_aligned_pages(pages, align)
            })
            .map_err(|_| HarnessError::Memory)?;
        let mailbox = self
            .with_environment(|environment| {
                environment.memory().allocate_aligned_pages(pages, align)
            })
            .map_err(|_| HarnessError::Memory)?;
        match self.write_u64(mailbox.virtual_address() as u64, MARKER) {
            AccessResult::Completed { .. } => {}
            _ => return Err(HarnessError::InvalidState),
        }
        mapper
            .prepare_current_runtime(
                entry,
                self.environment().transition_runtime_data(),
                &[
                    (STACK_ADDRESS, stack.phys_addr()),
                    (MAILBOX_ADDRESS, mailbox.phys_addr()),
                    (stack.phys_addr(), stack.phys_addr()),
                    (mailbox.phys_addr(), mailbox.phys_addr()),
                ],
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::CandidateRuntime,
                )
            })?;
        mapper.prepare_transition_table_access().map_err(|_| {
            HarnessError::TransitionPreparation(
                crate::TransitionPreparationError::CandidateTableAccess,
            )
        })?;
        let mut recovery_root = self.allocate_root()?;
        {
            let mut recovery_mapper = self.offline_mapper_for_format_with_geometry::<
                R,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut recovery_root,
                aarch64_vmsa::address::Level::L0,
                48,
                48,
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::RecoveryMapper,
                )
            })?;
            recovery_mapper
                .prepare_current_runtime(
                    entry,
                    self.environment().transition_runtime_data(),
                    &[
                        (
                            stack.phys_addr() + G::SIZE - 4096,
                            stack.phys_addr() + G::SIZE - 4096,
                        ),
                        (mailbox.phys_addr(), mailbox.phys_addr()),
                    ],
                )
                .map_err(|_| {
                    HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::RecoveryRuntime,
                    )
                })?;
            for address in [
                entry,
                vmsa_test_architecture::exception::vector_address(),
                vmsa_test_architecture::exception::recovery_vector_address(),
                stack.phys_addr() + G::SIZE - 4096,
                mailbox.phys_addr(),
            ] {
                let page = address & !0xfff;
                if recovery_mapper
                    .translate(page)
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::RecoveryInspection,
                        )
                    })?
                    .map(|mapping| mapping.output)
                    != Some(page)
                {
                    return Err(HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::RecoveryIdentity,
                    ));
                }
            }
        }
        Ok(TransitionSandbox {
            recovery_root,
            stack,
            mailbox,
            stack_address: STACK_ADDRESS,
            mailbox_address: MAILBOX_ADDRESS,
            marker: MARKER,
            granule: G::GRANULE,
        })
    }

    pub fn prepare_d128_transition_runtime<R>(
        &self,
        mapper: &mut TestMapper<
            R,
            aarch64_vmsa::address::Granule4KiB,
            aarch64_vmsa::descriptor::Vmsa128,
        >,
        entry: u64,
    ) -> Result<TransitionSandbox, HarnessError>
    where
        R: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<R>,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<R>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            R,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        const STACK_ADDRESS: u64 = 0x6b00_0000;
        const MAILBOX_ADDRESS: u64 = 0x6b10_0000;
        const MARKER: u64 = 0x5452_414e_5342_4f58;
        const PAGE_SIZE: u64 = 4096;

        let stack = self
            .with_environment(|environment| environment.memory().allocate_aligned_pages(1, 4096))
            .map_err(|_| HarnessError::Memory)?;
        let mailbox = self
            .with_environment(|environment| environment.memory().allocate_aligned_pages(1, 4096))
            .map_err(|_| HarnessError::Memory)?;
        match self.write_u64(mailbox.virtual_address() as u64, MARKER) {
            AccessResult::Completed { .. } => {}
            _ => return Err(HarnessError::InvalidState),
        }
        mapper
            .prepare_current_runtime_d128(
                entry,
                self.environment().transition_runtime_data(),
                &[
                    (STACK_ADDRESS, stack.phys_addr()),
                    (MAILBOX_ADDRESS, mailbox.phys_addr()),
                    (stack.phys_addr(), stack.phys_addr()),
                    (mailbox.phys_addr(), mailbox.phys_addr()),
                ],
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::CandidateRuntime,
                )
            })?;
        mapper.prepare_transition_table_access_d128().map_err(|_| {
            HarnessError::TransitionPreparation(
                crate::TransitionPreparationError::CandidateTableAccess,
            )
        })?;
        let mut recovery_root = self.allocate_root()?;
        {
            let mut recovery_mapper = self.offline_mapper_for_format_with_geometry::<
                R,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut recovery_root,
                aarch64_vmsa::address::Level::L0,
                48,
                48,
            )
            .map_err(|_| {
                HarnessError::TransitionPreparation(
                    crate::TransitionPreparationError::RecoveryMapper,
                )
            })?;
            recovery_mapper
                .prepare_current_runtime(
                    entry,
                    self.environment().transition_runtime_data(),
                    &[
                        (stack.phys_addr(), stack.phys_addr()),
                        (mailbox.phys_addr(), mailbox.phys_addr()),
                    ],
                )
                .map_err(|_| {
                    HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::RecoveryRuntime,
                    )
                })?;
            for address in [
                entry,
                vmsa_test_architecture::exception::vector_address(),
                vmsa_test_architecture::exception::recovery_vector_address(),
                stack.phys_addr(),
                mailbox.phys_addr(),
            ] {
                let page = address & !(PAGE_SIZE - 1);
                if recovery_mapper
                    .translate(page)
                    .map_err(|_| {
                        HarnessError::TransitionPreparation(
                            crate::TransitionPreparationError::RecoveryInspection,
                        )
                    })?
                    .map(|mapping| mapping.output)
                    != Some(page)
                {
                    return Err(HarnessError::TransitionPreparation(
                        crate::TransitionPreparationError::RecoveryIdentity,
                    ));
                }
            }
        }
        Ok(TransitionSandbox {
            recovery_root,
            stack,
            mailbox,
            stack_address: STACK_ADDRESS,
            mailbox_address: MAILBOX_ADDRESS,
            marker: MARKER,
            granule: crate::Granule::Size4KiB,
        })
    }

    pub fn transition_sandbox_restored(&self, sandbox: &TransitionSandbox) -> bool {
        let mailbox_restored = matches!(
            self.read_u64(sandbox.mailbox.virtual_address() as u64),
            AccessResult::Completed { value } if value == sandbox.marker
        );
        let stack_restored = matches!(
            self.read_u64(sandbox.stack.virtual_address() as u64),
            AccessResult::Completed { value: 0 }
        );
        mailbox_restored
            && stack_restored
            && sandbox.recovery_root.phys_addr() & 0xfff == 0
            && vmsa_test_architecture::exception::primary_vectors_active()
    }

    pub fn install_owned(
        &self,
        root: RootTableMemory,
        setup: TranslationSetup,
    ) -> Result<LiveTranslation<'_, E>, HarnessError> {
        if root.phys_addr() != setup.root.get() {
            return Err(HarnessError::InvalidState);
        }
        self.install_inner(root, setup, false, None)
    }

    pub fn install_owned_in_sandbox(
        &self,
        root: RootTableMemory,
        setup: TranslationSetup,
        sandbox: &TransitionSandbox,
    ) -> Result<LiveTranslation<'_, E>, HarnessError> {
        if root.phys_addr() != setup.root.get() || setup.granule != sandbox.granule {
            return Err(HarnessError::InvalidState);
        }
        self.install_inner(root, setup, false, Some(sandbox.transition_stack()))
    }

    fn install_inner(
        &self,
        root: RootTableMemory,
        setup: TranslationSetup,
        lower: bool,
        transition_stack: Option<crate::translation::TransitionStack>,
    ) -> Result<LiveTranslation<'_, E>, HarnessError> {
        if root.phys_addr() & (setup.granule.bytes() - 1) != 0
            || match setup.stage {
                crate::TranslationStage::Stage1 => setup.vmid.is_some(),
                crate::TranslationStage::Stage2 => setup.asid.is_some(),
            }
        {
            return Err(HarnessError::InvalidState);
        }
        if setup.stage == crate::TranslationStage::Stage1
            && !setup.controls.preserves_current()
            && setup.start_level
                != crate::translation::stage1_start_level(
                    setup.format,
                    setup.granule,
                    setup.input_bits,
                )
        {
            return Err(HarnessError::InvalidState);
        }
        self.failures
            .check(HarnessFailurePoint::TranslationInstallation)?;
        let memory = self.with_environment(|environment| NonNull::from(environment.memory()));
        let installed = self
            .with_environment(|environment| {
                if lower {
                    environment.install_lower_translation(setup)
                } else {
                    environment.install_translation(setup, transition_stack)
                }
            })
            .map_err(|error| HarnessError::EnvironmentDetail(E::error_code(&error)))?;
        let setup = installed.setup();
        Ok(LiveTranslation {
            environment: self.environment,
            memory,
            roots: [Some(root), None, None],
            setup,
            installed: Some(installed),
            lower,
            cleanup: &self.cleanup,
            failures: &self.failures,
            _lifetime: PhantomData,
        })
    }

    pub fn install_lower_owned(
        &self,
        root: RootTableMemory,
        setup: TranslationSetup,
    ) -> Result<LiveTranslation<'_, E>, HarnessError> {
        if root.phys_addr() != setup.root.get() {
            return Err(HarnessError::InvalidState);
        }
        self.install_inner(root, setup, true, None)
    }

    pub fn install_combined_owned(
        &self,
        stage1_root: RootTableMemory,
        stage1: TranslationSetup,
        stage2_root: RootTableMemory,
        stage2: TranslationSetup,
    ) -> Result<CombinedTranslation<'_, E>, HarnessError> {
        if stage1.stage != crate::TranslationStage::Stage1
            || stage2.stage != crate::TranslationStage::Stage2
        {
            return Err(HarnessError::InvalidState);
        }
        let stage1 = self.install_lower_owned(stage1_root, stage1)?;
        if let Err(error) = self
            .failures
            .check(HarnessFailurePoint::PartialCombinedInstallation)
        {
            stage1.restore()?;
            return Err(error);
        }
        let stage2 = match self.install_owned(stage2_root, stage2) {
            Ok(translation) => translation,
            Err(error) => {
                stage1.restore()?;
                return Err(error);
            }
        };
        Ok(CombinedTranslation {
            stage2: Some(stage2),
            stage1: Some(stage1),
        })
    }

    pub fn read_u64(&self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Double)
    }
    pub fn secondary_pe_session(&self) -> Result<SecondaryPeSession<'_, E>, HarnessError> {
        self.failures
            .check(HarnessFailurePoint::SecondaryPeStartup)?;
        self.with_environment(Environment::begin_secondary_session)
            .map_err(|_| HarnessError::Environment)?;
        if let Err(error) = self
            .failures
            .check(HarnessFailurePoint::SecondaryPeRendezvous)
        {
            if self
                .with_environment(Environment::end_secondary_session)
                .is_err()
            {
                // SAFETY: CleanupState is single-threaded and owned by this context.
                unsafe { *self.cleanup.0.get() = true };
                return Err(HarnessError::Cleanup);
            }
            return Err(error);
        }
        Ok(SecondaryPeSession {
            environment: self.environment,
            state: SecondaryPeSessionState::Rendezvous,
            cleanup: &self.cleanup,
            failures: &self.failures,
            _lifetime: PhantomData,
        })
    }
    pub fn execution(
        &self,
        context: crate::ExecutionContext,
    ) -> Result<ExecutionSession<'_, E>, HarnessError> {
        let secondary = if context == crate::ExecutionContext::SecondaryPe {
            Some(self.secondary_pe_session()?)
        } else {
            None
        };
        if context == crate::ExecutionContext::RealmRec
            && !self.environment().realm_rec_is_current()
        {
            return Err(HarnessError::Environment);
        }
        Ok(ExecutionSession {
            environment: self.environment,
            context,
            secondary,
            _lifetime: PhantomData,
        })
    }
    pub fn realm_rec_stage2(&self) -> Result<RealmRecStage2Translation<'_, E>, HarnessError> {
        self.failures
            .check(HarnessFailurePoint::GranuleDelegation)?;
        self.failures.check(HarnessFailurePoint::RealmCreation)?;
        self.failures.check(HarnessFailurePoint::RecCreation)?;
        let region = self.with_environment(Environment::begin_realm_stage2_session)?;
        if let Err(error) = self.failures.check(HarnessFailurePoint::RecEntry) {
            if self
                .with_environment(Environment::end_realm_stage2_session)
                .is_err()
            {
                // SAFETY: CleanupState is single-threaded and owned by this context.
                unsafe { *self.cleanup.0.get() = true };
                return Err(HarnessError::Cleanup);
            }
            return Err(error);
        }
        Ok(RealmRecStage2Translation {
            environment: self.environment,
            region,
            mapped: false,
            writable: false,
            finished: false,
            cleanup: &self.cleanup,
            failures: &self.failures,
            _lifetime: PhantomData,
        })
    }
    pub fn read_u32(&self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Word)
    }
    pub fn read_u16(&self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Half)
    }
    pub fn read_u8(&self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Byte)
    }
    pub fn read(&self, address: u64, width: AccessWidth) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::read(address, width))
        })
    }
    pub fn write_u64(&self, address: u64, value: u64) -> AccessResult {
        self.write(address, AccessWidth::Double, value)
    }
    pub fn write_u32(&self, address: u64, value: u32) -> AccessResult {
        self.write(address, AccessWidth::Word, u64::from(value))
    }
    pub fn write_u16(&self, address: u64, value: u16) -> AccessResult {
        self.write(address, AccessWidth::Half, u64::from(value))
    }
    pub fn write_u8(&self, address: u64, value: u8) -> AccessResult {
        self.write(address, AccessWidth::Byte, u64::from(value))
    }
    pub fn write(&self, address: u64, width: AccessWidth, value: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::write(address, width, value))
        })
    }
    pub fn execute(&self, address: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::execute(address))
        })
    }
    pub fn read_acquire_u64(&self, address: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::read_acquire(address))
        })
    }
    pub fn write_release_u64(&self, address: u64, value: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::write_release(address, value))
        })
    }
    pub fn atomic_swap_u64(&self, address: u64, value: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::atomic_swap(address, value))
        })
    }
    pub fn exclusive_add_u64(&self, address: u64, value: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::exclusive_add(address, value))
        })
    }
    pub fn read_pair_u64(&self, address: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::read_pair(address))
        })
    }
    pub fn write_pair_u64(&self, address: u64, first: u64, second: u64) -> AccessResult {
        self.with_environment(|environment| {
            environment.perform_access(AccessRequest::write_pair(address, first, second))
        })
    }
    pub fn synchronize_instruction_range(
        &self,
        address: u64,
        bytes: usize,
    ) -> Result<(), HarnessError> {
        self.maintain_cache(CacheMaintenanceOperation::InstructionCoherency { address, bytes })
    }

    pub fn maintain_cache(&self, operation: CacheMaintenanceOperation) -> Result<(), HarnessError> {
        self.failures.check(HarnessFailurePoint::Barrier)?;
        let completed = match operation {
            CacheMaintenanceOperation::InstructionCoherency { address, bytes } => {
                vmsa_test_architecture::barriers::synchronize_instruction_range(address, bytes)
            }
            CacheMaintenanceOperation::CleanData { address, bytes } => {
                vmsa_test_architecture::barriers::clean_data_cache_range(address, bytes)
            }
            CacheMaintenanceOperation::CleanInvalidateData { address, bytes } => {
                vmsa_test_architecture::barriers::clean_invalidate_data_cache_range(address, bytes)
            }
            CacheMaintenanceOperation::InvalidateData { address, bytes } => {
                vmsa_test_architecture::barriers::invalidate_data_cache_range(address, bytes)
            }
            CacheMaintenanceOperation::TranslationTableVisibility => {
                vmsa_test_architecture::barriers::dsb_ishst();
                true
            }
            CacheMaintenanceOperation::MultiPeVisibility => {
                vmsa_test_architecture::barriers::dsb_ish();
                true
            }
        };
        if completed {
            Ok(())
        } else {
            Err(HarnessError::InvalidState)
        }
    }
    pub fn enable_hardware_updates(
        &self,
        dirty: bool,
    ) -> Result<HardwareUpdateGuard<'_>, HarnessError> {
        // SAFETY: A test has exclusive ownership of its installed translation;
        // the returned guard restores TCR before the test context is released.
        let state = unsafe { vmsa_test_architecture::registers::enable_hardware_updates(dirty) }
            .ok_or(HarnessError::InvalidState)?;
        Ok(HardwareUpdateGuard {
            state: Some(state),
            cleanup: &self.cleanup,
        })
    }
    pub fn enable_lower_el1_hardware_updates(
        &self,
        dirty: bool,
    ) -> Result<LowerHardwareUpdateGuard<'_>, HarnessError> {
        // SAFETY: The test owns the inactive EL1 translation until both the
        // returned guard and its live lower translation have been restored.
        let state =
            unsafe { vmsa_test_architecture::registers::enable_lower_el1_hardware_updates(dirty) }
                .ok_or(HarnessError::InvalidState)?;
        Ok(LowerHardwareUpdateGuard {
            state: Some(state),
            cleanup: &self.cleanup,
        })
    }
    fn lower_el(&self, request: LowerElRequest) -> AccessResult {
        if let Err(error) = self.failures.check(HarnessFailurePoint::LowerElEntry) {
            return AccessResult::HarnessFailure(error);
        }
        if let Err(error) = self.failures.check(HarnessFailurePoint::LowerElAction) {
            return AccessResult::HarnessFailure(error);
        }
        let result = self.with_environment(|environment| environment.run_lower_el(request));
        if let Err(error) = self.failures.check(HarnessFailurePoint::LowerElReturn) {
            return AccessResult::HarnessFailure(error);
        }
        result
    }
    pub fn lower_read_u64(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Double))
    }
    pub fn lower_read_u32(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Word))
    }
    pub fn lower_read_u16(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Half))
    }
    pub fn lower_read_u8(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Byte))
    }
    pub fn lower_write_u64(&self, address: u64, value: u64) -> AccessResult {
        self.lower_el(LowerElRequest::write(address, AccessWidth::Double, value))
    }
    pub fn lower_write_u32(&self, address: u64, value: u32) -> AccessResult {
        self.lower_el(LowerElRequest::write(
            address,
            AccessWidth::Word,
            u64::from(value),
        ))
    }
    pub fn lower_write_u16(&self, address: u64, value: u16) -> AccessResult {
        self.lower_el(LowerElRequest::write(
            address,
            AccessWidth::Half,
            u64::from(value),
        ))
    }
    pub fn lower_write_u8(&self, address: u64, value: u8) -> AccessResult {
        self.lower_el(LowerElRequest::write(
            address,
            AccessWidth::Byte,
            u64::from(value),
        ))
    }
    pub fn lower_execute(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::execute(address))
    }
    pub fn el0_read_u64(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Double).at_el0())
    }
    pub fn el0_write_u64(&self, address: u64, value: u64) -> AccessResult {
        self.lower_el(LowerElRequest::write(address, AccessWidth::Double, value).at_el0())
    }
    pub fn el0_execute(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::execute(address).at_el0())
    }
    pub fn el2_el0_read_u64(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::read(address, AccessWidth::Double).at_el2_el0())
    }
    pub fn el2_el0_write_u64(&self, address: u64, value: u64) -> AccessResult {
        self.lower_el(LowerElRequest::write(address, AccessWidth::Double, value).at_el2_el0())
    }
    pub fn el2_el0_execute(&self, address: u64) -> AccessResult {
        self.lower_el(LowerElRequest::execute(address).at_el2_el0())
    }
    pub(crate) fn cleanup_failed(&self) -> bool {
        unsafe { *self.cleanup.0.get() }
    }
    pub(crate) const fn memory_scope(&self) -> MemoryScope {
        self.memory_scope
    }

    /// Exercises the same last-resort restoration hook used by the catalog
    /// runner after a test releases its normal ownership guard.
    pub fn emergency_restore_for_test(&self) {
        self.with_environment(Environment::emergency_restore);
    }

    fn environment(&self) -> &E {
        // SAFETY: TestContext owns the exclusive environment borrow for 'a.
        unsafe { self.environment.as_ref() }
    }
    fn with_environment<R>(&self, operation: impl FnOnce(&mut E) -> R) -> R {
        // SAFETY: Harness calls are single-threaded and non-reentrant. The
        // temporary mutable borrow is confined to this operation.
        operation(unsafe { &mut *self.environment.as_ptr() })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecondaryPeSessionState {
    Start,
    Rendezvous,
    IssueAction,
    Observe,
    Synchronize,
    Stop,
}

pub struct ExecutionSession<'a, E: Environment> {
    environment: NonNull<E>,
    context: crate::ExecutionContext,
    secondary: Option<SecondaryPeSession<'a, E>>,
    _lifetime: PhantomData<&'a E>,
}

impl<E: Environment> ExecutionSession<'_, E> {
    pub const fn context(&self) -> crate::ExecutionContext {
        self.context
    }

    pub fn read(&mut self, address: u64, width: AccessWidth) -> AccessResult {
        match self.context {
            crate::ExecutionContext::CurrentEl | crate::ExecutionContext::RealmRec => self
                .with_environment(|environment| {
                    environment.perform_access(AccessRequest::read(address, width))
                }),
            crate::ExecutionContext::El1 => self.lower(LowerElRequest::read(address, width)),
            crate::ExecutionContext::El0UnderEl1 => {
                self.lower(LowerElRequest::read(address, width).at_el0())
            }
            crate::ExecutionContext::El0UnderEl2 => {
                self.lower(LowerElRequest::read(address, width).at_el2_el0())
            }
            crate::ExecutionContext::SecondaryPe => self.secondary.as_mut().map_or(
                AccessResult::HarnessFailure(HarnessError::InvalidState),
                |session| session.perform(AccessRequest::read(address, width)),
            ),
        }
    }

    pub fn read_u64(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Double)
    }

    pub fn read_u32(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Word)
    }

    pub fn read_u16(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Half)
    }

    pub fn read_u8(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Byte)
    }

    pub fn write(&mut self, address: u64, width: AccessWidth, value: u64) -> AccessResult {
        let request = LowerElRequest::write(address, width, value);
        match self.context {
            crate::ExecutionContext::CurrentEl | crate::ExecutionContext::RealmRec => self
                .with_environment(|environment| {
                    environment.perform_access(AccessRequest::write(address, width, value))
                }),
            crate::ExecutionContext::El1 => self.lower(request),
            crate::ExecutionContext::El0UnderEl1 => self.lower(request.at_el0()),
            crate::ExecutionContext::El0UnderEl2 => self.lower(request.at_el2_el0()),
            crate::ExecutionContext::SecondaryPe => self.secondary.as_mut().map_or(
                AccessResult::HarnessFailure(HarnessError::InvalidState),
                |session| session.perform(AccessRequest::write(address, width, value)),
            ),
        }
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.write(address, AccessWidth::Double, value)
    }

    pub fn write_u32(&mut self, address: u64, value: u32) -> AccessResult {
        self.write(address, AccessWidth::Word, u64::from(value))
    }

    pub fn write_u16(&mut self, address: u64, value: u16) -> AccessResult {
        self.write(address, AccessWidth::Half, u64::from(value))
    }

    pub fn write_u8(&mut self, address: u64, value: u8) -> AccessResult {
        self.write(address, AccessWidth::Byte, u64::from(value))
    }

    pub fn read_acquire_u64(&mut self, address: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::read_acquire(address),
            LowerElRequest::read_acquire(address),
        )
    }

    pub fn write_release_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::write_release(address, value),
            LowerElRequest::write_release(address, value),
        )
    }

    pub fn atomic_swap_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::atomic_swap(address, value),
            LowerElRequest::atomic_swap(address, value),
        )
    }

    pub fn exclusive_add_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::exclusive_add(address, value),
            LowerElRequest::exclusive_add(address, value),
        )
    }

    pub fn read_pair_u64(&mut self, address: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::read_pair(address),
            LowerElRequest::read_pair(address),
        )
    }

    pub fn write_pair_u64(&mut self, address: u64, first: u64, second: u64) -> AccessResult {
        self.access_operation(
            AccessRequest::write_pair(address, first, second),
            LowerElRequest::write_pair(address, first, second),
        )
    }

    pub fn execute(&mut self, address: u64) -> AccessResult {
        let request = LowerElRequest::execute(address);
        match self.context {
            crate::ExecutionContext::CurrentEl | crate::ExecutionContext::RealmRec => self
                .with_environment(|environment| {
                    environment.perform_access(AccessRequest::execute(address))
                }),
            crate::ExecutionContext::El1 => self.lower(request),
            crate::ExecutionContext::El0UnderEl1 => self.lower(request.at_el0()),
            crate::ExecutionContext::El0UnderEl2 => self.lower(request.at_el2_el0()),
            crate::ExecutionContext::SecondaryPe => self.secondary.as_mut().map_or(
                AccessResult::HarnessFailure(HarnessError::InvalidState),
                |session| session.perform(AccessRequest::execute(address)),
            ),
        }
    }

    pub fn translate(
        &mut self,
        address: u64,
        access: crate::TranslationQueryAccess,
    ) -> crate::TranslationQueryResult {
        let architectural_access = match access {
            crate::TranslationQueryAccess::Read => {
                vmsa_test_architecture::translation::TranslationAccess::Read
            }
            crate::TranslationQueryAccess::Write => {
                vmsa_test_architecture::translation::TranslationAccess::Write
            }
        };
        match self.context {
            crate::ExecutionContext::CurrentEl | crate::ExecutionContext::RealmRec => {
                vmsa_test_architecture::translation::current_stage1(address, architectural_access)
                    .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                        crate::TranslationQueryResult::from_par(address, par)
                    })
            }
            crate::ExecutionContext::El1 => {
                vmsa_test_architecture::translation::lower_stage1(address, architectural_access)
                    .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                        crate::TranslationQueryResult::from_par(address, par)
                    })
            }
            crate::ExecutionContext::El0UnderEl1 => {
                vmsa_test_architecture::translation::lower_el0_stage1(address, architectural_access)
                    .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                        crate::TranslationQueryResult::from_par(address, par)
                    })
            }
            crate::ExecutionContext::El0UnderEl2 => {
                match self.lower(
                    LowerElRequest::translate(
                        address,
                        access == crate::TranslationQueryAccess::Write,
                    )
                    .at_el2_el0(),
                ) {
                    AccessResult::Completed { value: par } => {
                        crate::TranslationQueryResult::from_par(address, par)
                    }
                    _ => crate::TranslationQueryResult::Unsupported,
                }
            }
            crate::ExecutionContext::SecondaryPe => self.secondary.as_mut().map_or(
                crate::TranslationQueryResult::Unsupported,
                |session| match session.perform(AccessRequest::translate(
                    address,
                    access == crate::TranslationQueryAccess::Write,
                )) {
                    AccessResult::Completed { value: par } => {
                        crate::TranslationQueryResult::from_par(address, par)
                    }
                    _ => crate::TranslationQueryResult::Unsupported,
                },
            ),
        }
    }

    pub fn finish(mut self) -> Result<(), HarnessError> {
        if let Some(secondary) = self.secondary.take() {
            secondary.stop()?;
        }
        Ok(())
    }

    fn lower(&mut self, request: LowerElRequest) -> AccessResult {
        self.with_environment(|environment| environment.run_lower_el(request))
    }

    fn access_operation(&mut self, current: AccessRequest, lower: LowerElRequest) -> AccessResult {
        match self.context {
            crate::ExecutionContext::CurrentEl | crate::ExecutionContext::RealmRec => {
                self.with_environment(|environment| environment.perform_access(current))
            }
            crate::ExecutionContext::El1 => self.lower(lower),
            crate::ExecutionContext::El0UnderEl1 => self.lower(lower.at_el0()),
            crate::ExecutionContext::El0UnderEl2 => self.lower(lower.at_el2_el0()),
            crate::ExecutionContext::SecondaryPe => self.secondary.as_mut().map_or(
                AccessResult::HarnessFailure(HarnessError::InvalidState),
                |session| session.perform(current),
            ),
        }
    }

    fn with_environment<R>(&mut self, operation: impl FnOnce(&mut E) -> R) -> R {
        // SAFETY: The owning TestContext serializes execution-session operations.
        operation(unsafe { &mut *self.environment.as_ptr() })
    }
}

pub struct SecondaryPeSession<'a, E: Environment> {
    environment: NonNull<E>,
    state: SecondaryPeSessionState,
    cleanup: &'a CleanupState,
    failures: &'a HarnessFailureState,
    _lifetime: PhantomData<&'a E>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmStage2Region {
    pub ipa: u64,
    pub physical: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmStage2Mutation {
    MapUnprotected,
    UnmapUnprotected,
    ProtectReadOnly,
    ProtectReadWrite,
}

pub struct RealmRecStage2Translation<'a, E: Environment> {
    environment: NonNull<E>,
    region: RealmStage2Region,
    mapped: bool,
    writable: bool,
    finished: bool,
    cleanup: &'a CleanupState,
    failures: &'a HarnessFailureState,
    _lifetime: PhantomData<&'a E>,
}

impl<E: Environment> RealmRecStage2Translation<'_, E> {
    pub const fn input_address(&self) -> u64 {
        self.region.ipa
    }

    pub const fn output_address(&self) -> u64 {
        self.region.physical
    }

    pub fn map(&mut self) -> Result<(), HarnessError> {
        if self.mapped || self.finished {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::RealmMap)?;
        self.failures.check(HarnessFailurePoint::FirmwareCallback)?;
        self.with_environment(|environment| {
            environment.mutate_realm_stage2(RealmStage2Mutation::MapUnprotected)
        })?;
        self.mapped = true;
        self.writable = true;
        Ok(())
    }

    pub fn protect_read_only(&mut self) -> Result<(), HarnessError> {
        if !self.mapped || !self.writable || self.finished {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::RealmMutation)?;
        self.failures.check(HarnessFailurePoint::FirmwareCallback)?;
        self.with_environment(|environment| {
            environment.mutate_realm_stage2(RealmStage2Mutation::ProtectReadOnly)
        })?;
        self.writable = false;
        Ok(())
    }

    pub fn protect_read_write(&mut self) -> Result<(), HarnessError> {
        if !self.mapped || self.writable || self.finished {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::RealmMutation)?;
        self.failures.check(HarnessFailurePoint::FirmwareCallback)?;
        self.with_environment(|environment| {
            environment.mutate_realm_stage2(RealmStage2Mutation::ProtectReadWrite)
        })?;
        self.writable = true;
        Ok(())
    }

    pub fn unmap(&mut self) -> Result<(), HarnessError> {
        if !self.mapped || self.finished {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::RealmMutation)?;
        self.failures.check(HarnessFailurePoint::FirmwareCallback)?;
        self.with_environment(|environment| {
            environment.mutate_realm_stage2(RealmStage2Mutation::UnmapUnprotected)
        })?;
        self.mapped = false;
        self.writable = false;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), HarnessError> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), HarnessError> {
        if self.finished || self.mapped {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::RealmDestruction)?;
        self.failures
            .check(HarnessFailurePoint::GranuleUndelegation)?;
        self.failures.check(HarnessFailurePoint::Cleanup)?;
        self.with_environment(Environment::end_realm_stage2_session)?;
        self.finished = true;
        Ok(())
    }

    fn with_environment<R>(&mut self, operation: impl FnOnce(&mut E) -> R) -> R {
        // SAFETY: The owning TestContext serializes adapter access for this guard.
        operation(unsafe { &mut *self.environment.as_ptr() })
    }
}

impl<E: Environment> Drop for RealmRecStage2Translation<'_, E> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut failed = false;
        if self.mapped {
            failed = self
                .with_environment(|environment| {
                    environment.mutate_realm_stage2(RealmStage2Mutation::UnmapUnprotected)
                })
                .is_err();
            self.mapped = false;
            self.writable = false;
        }
        if self.finish_inner().is_err() {
            failed = true;
        }
        if failed {
            // SAFETY: CleanupState is single-threaded and owned by the live context.
            unsafe { *self.cleanup.0.get() = true };
        }
    }
}

impl<E: Environment> SecondaryPeSession<'_, E> {
    pub const fn state(&self) -> SecondaryPeSessionState {
        self.state
    }

    pub fn read_u64(&mut self, address: u64) -> AccessResult {
        self.perform(AccessRequest::read(address, AccessWidth::Double))
    }

    fn perform(&mut self, request: AccessRequest) -> AccessResult {
        if self.state != SecondaryPeSessionState::Rendezvous {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        }
        if let Err(error) = self.failures.check(HarnessFailurePoint::SecondaryPeAction) {
            return AccessResult::HarnessFailure(error);
        }
        self.state = SecondaryPeSessionState::IssueAction;
        if let Err(error) = self.failures.check(HarnessFailurePoint::SecondaryPeTimeout) {
            self.state = SecondaryPeSessionState::Rendezvous;
            return AccessResult::HarnessFailure(error);
        }
        // SAFETY: The owning context serializes adapter access for this session.
        let result = unsafe { &mut *self.environment.as_ptr() }.perform_secondary_access(request);
        self.state = SecondaryPeSessionState::Observe;
        vmsa_test_architecture::barriers::dsb_ish();
        self.state = SecondaryPeSessionState::Synchronize;
        self.state = SecondaryPeSessionState::Rendezvous;
        result
    }

    pub fn stop(mut self) -> Result<(), HarnessError> {
        self.failures.check(HarnessFailurePoint::SecondaryPeStop)?;
        self.failures.check(HarnessFailurePoint::Cleanup)?;
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), HarnessError> {
        if self.state == SecondaryPeSessionState::Stop {
            return Err(HarnessError::InvalidState);
        }
        // SAFETY: This session exclusively owns the secondary-active adapter state.
        unsafe { &mut *self.environment.as_ptr() }
            .end_secondary_session()
            .map_err(|_| HarnessError::Cleanup)?;
        self.state = SecondaryPeSessionState::Stop;
        Ok(())
    }
}

impl<E: Environment> Drop for SecondaryPeSession<'_, E> {
    fn drop(&mut self) {
        if self.state != SecondaryPeSessionState::Stop && self.stop_inner().is_err() {
            // SAFETY: CleanupState is single-threaded and owned by the live context.
            unsafe { *self.cleanup.0.get() = true };
        }
    }
}

pub struct HardwareUpdateGuard<'a> {
    state: Option<vmsa_test_architecture::registers::HardwareUpdateState>,
    cleanup: &'a CleanupState,
}

pub struct LowerHardwareUpdateGuard<'a> {
    state: Option<vmsa_test_architecture::registers::LowerHardwareUpdateState>,
    cleanup: &'a CleanupState,
}

impl Drop for LowerHardwareUpdateGuard<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            // SAFETY: This guard uniquely owns the inactive EL1 HA/HD state.
            let restored = unsafe {
                vmsa_test_architecture::registers::restore_lower_el1_hardware_updates(state)
            };
            if !restored {
                // SAFETY: The runner reads this single-threaded cleanup flag
                // only after all test-owned guards have been dropped.
                unsafe { *self.cleanup.0.get() = true };
            }
        }
    }
}

impl Drop for HardwareUpdateGuard<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            // SAFETY: This guard uniquely owns the state captured on the same PE.
            let restored =
                unsafe { vmsa_test_architecture::registers::restore_hardware_updates(state) };
            if !restored {
                // SAFETY: The runner reads this single-threaded cleanup flag
                // only after all test-owned guards have been dropped.
                unsafe { *self.cleanup.0.get() = true };
            }
        }
    }
}

pub struct LiveTranslation<'a, E: Environment> {
    environment: NonNull<E>,
    memory: NonNull<TestMemory>,
    roots: [Option<RootTableMemory>; 3],
    setup: TranslationSetup,
    installed: Option<InstalledTranslation>,
    lower: bool,
    cleanup: &'a CleanupState,
    failures: &'a HarnessFailureState,
    _lifetime: PhantomData<&'a E>,
}

impl<E> LiveTranslation<'_, E>
where
    E: TranslationRegimeEnvironment,
{
    pub fn map_hardware_managed<G>(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: crate::HardwareManagedAttributes,
    ) -> Result<(), HarnessError>
    where
        G: TestGranule,
        E::Regime: HardwareManagedStage1Regime<G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, E::Regime, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Map)?;
        self.with_mapper::<aarch64_vmsa::descriptor::Vmsa64, G, _>(|mapper| {
            mapper
                .map_leaf(
                    aarch64_vmsa::translation::WalkInputAddr::new(input),
                    aarch64_vmsa::address::PhysAddr(output),
                    aarch64_vmsa::address::Level::new(level.get()),
                    <E::Regime as HardwareManagedStage1Regime<G>>::raw_hardware_leaf(attributes)?,
                    <E::Regime as TestRegimeFor<G>>::raw_table()?,
                )
                .map(|_| ())
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn inspect_hardware_updates<G>(
        &mut self,
        input: u64,
    ) -> Result<crate::HardwareUpdateInspection, HarnessError>
    where
        G: TestGranule,
        E::Regime: HardwareManagedStage1Regime<G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, E::Regime, G>: Copy,
    {
        self.with_mapper::<aarch64_vmsa::descriptor::Vmsa64, G, _>(|mapper| {
            mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
                .map(|mapping| {
                    <E::Regime as HardwareManagedStage1Regime<G>>::inspect_hardware_fields(
                        mapping.fields(),
                    )
                })
                .ok_or(HarnessError::InvalidState)
        })
    }
    pub fn inspect<F, G>(
        &mut self,
        input: u64,
    ) -> Result<Option<crate::MappingInspection>, HarnessError>
    where
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, E::Regime, G>: Copy,
    {
        self.with_mapper::<F, G, _>(|mapper| {
            mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map(|mapping| {
                    mapping.map(|mapping| crate::MappingInspection {
                        output: mapping.output().0,
                        level: LookupLevel::new(mapping.level().as_i8())
                            .expect("mapper returned an architectural lookup level"),
                    })
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn inspect_walk<F, G>(&mut self, input: u64) -> Result<crate::WalkInspection, HarnessError>
    where
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, E::Regime, G>: Copy,
    {
        self.with_mapper::<F, G, _>(|mapper| {
            crate::translation::inspect_walk_with_access::<E::Regime, G, F, _>(
                mapper.root(),
                mapper.access(),
                input,
            )
        })
    }

    pub fn inspect_walk_for<R, F, G>(
        &mut self,
        input: u64,
    ) -> Result<crate::WalkInspection, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            crate::translation::inspect_walk_with_access::<R, G, F, _>(
                mapper.root(),
                mapper.access(),
                input,
            )
        })
    }

    pub fn inspect_for<R, F, G>(
        &mut self,
        input: u64,
    ) -> Result<Option<crate::MappingInspection>, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map(|mapping| {
                    mapping.map(|mapping| crate::MappingInspection {
                        output: mapping.output().0,
                        level: LookupLevel::new(mapping.level().as_i8())
                            .expect("mapper returned an architectural lookup level"),
                    })
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn inspect_semantic_for<R, F, G, Codec, Cfg>(
        &mut self,
        input: u64,
        config: &Cfg,
    ) -> Result<Option<Codec::SemanticLeaf>, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
        Codec: aarch64_vmsa::attrs::AttributeCodec<
                F,
                R,
                G,
                Cfg,
                RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
                RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            let mapping = mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?;
            mapping
                .map(|mapping| {
                    aarch64_vmsa::mapper::decode_semantic_leaf::<F, R, G, Codec, Cfg>(
                        config,
                        mapping.level(),
                        *mapping.fields(),
                    )
                    .map_err(|error| {
                        HarnessError::Attribute(crate::translation::normalize_attribute_error(
                            error,
                        ))
                    })
                })
                .transpose()
        })
    }

    pub fn map_semantic_for<R, F, G, Codec, Cfg>(
        &mut self,
        config: &Cfg,
        input: u64,
        output: u64,
        level: LookupLevel,
        leaf: Codec::SemanticLeaf,
        table: Codec::SemanticTable,
    ) -> Result<(), HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
        Codec: aarch64_vmsa::attrs::AttributeCodec<
                F,
                R,
                G,
                Cfg,
                RawLeaf = aarch64_vmsa::regime::LeafFieldsOf<F, R, G>,
                RawTable = aarch64_vmsa::regime::TableFieldsOf<F, R, G>,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Map)?;
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            aarch64_vmsa::mapper::map_semantic_leaf::<F, R, G, _, _, _, Codec, Cfg>(
                mapper,
                config,
                aarch64_vmsa::translation::WalkInputAddr::new(input),
                aarch64_vmsa::address::PhysAddr(output),
                aarch64_vmsa::address::Level::new(level.get()),
                leaf,
                table,
            )
            .map(|_| ())
            .map_err(|error| match error {
                aarch64_vmsa::mapper::SemanticMapperError::Attribute(error) => {
                    HarnessError::Attribute(crate::translation::normalize_attribute_error(error))
                }
                aarch64_vmsa::mapper::SemanticMapperError::Mapper(_) => HarnessError::InvalidState,
            })
        })
    }

    pub fn map<F, G>(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: crate::MappingAttributes,
    ) -> Result<(), HarnessError>
    where
        E::Regime: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            G,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::regime::StageOf<E::Regime>,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
    {
        self.failures.check(HarnessFailurePoint::Map)?;
        self.with_mapper::<F, G, _>(|mapper| {
            mapper
                .map_leaf(
                    aarch64_vmsa::translation::WalkInputAddr::new(input),
                    aarch64_vmsa::address::PhysAddr(output),
                    aarch64_vmsa::address::Level::new(level.get()),
                    <E::Regime as TestRegimeFor<G>>::raw_leaf(attributes)?,
                    <E::Regime as TestRegimeFor<G>>::raw_table()?,
                )
                .map(|_| ())
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn map_for<R, F, G>(
        &mut self,
        input: u64,
        output: u64,
        level: LookupLevel,
        attributes: crate::MappingAttributes,
    ) -> Result<(), HarnessError>
    where
        R: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>>::Layout:
            aarch64_vmsa::descriptor::DescriptorLayout<
                    F,
                    aarch64_vmsa::regime::StageOf<R>,
                    G,
                    LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                    TableFields = aarch64_vmsa::regime::TableFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                >,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    {
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            mapper
                .map_leaf(
                    aarch64_vmsa::translation::WalkInputAddr::new(input),
                    aarch64_vmsa::address::PhysAddr(output),
                    aarch64_vmsa::address::Level::new(level.get()),
                    <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                    <R as TestRegimeFor<G>>::raw_table()?,
                )
                .map(|_| ())
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn map_range<F, G>(
        &mut self,
        input: u64,
        output: u64,
        bytes: u64,
        level: LookupLevel,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MapRangeResult, HarnessError>
    where
        E::Regime: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            G,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::regime::StageOf<E::Regime>,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
    {
        self.failures.check(HarnessFailurePoint::Map)?;
        self.with_mapper::<F, G, _>(|mapper| {
            mapper
                .map_range(
                    aarch64_vmsa::translation::WalkInputAddr::new(input),
                    aarch64_vmsa::address::PhysAddr(output),
                    bytes,
                    aarch64_vmsa::address::Level::new(level.get()),
                    <E::Regime as TestRegimeFor<G>>::raw_leaf(attributes)?,
                    <E::Regime as TestRegimeFor<G>>::raw_table()?,
                )
                .map(|result| crate::MapRangeResult {
                    mappings_created: result.mappings_created(),
                    bytes_mapped: result.bytes_mapped(),
                    tables_allocated: result.tables_allocated(),
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn unmap<F, G>(&mut self, input: u64) -> Result<crate::MappingInspection, HarnessError>
    where
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, E::Regime, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Unmap)?;
        self.with_mapper::<F, G, _>(|mapper| {
            mapper
                .unmap(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map(|result| crate::MappingInspection {
                    output: result.old().output().0,
                    level: LookupLevel::new(result.old().level().as_i8())
                        .expect("mapper returned an architectural lookup level"),
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn unmap_for<R, F, G>(
        &mut self,
        input: u64,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, R, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Unmap)?;
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            mapper
                .unmap(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map(|result| crate::MappingInspection {
                    output: result.old().output().0,
                    level: LookupLevel::new(result.old().level().as_i8())
                        .expect("mapper returned an architectural lookup level"),
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn unmap_reclaim<F, G>(&mut self, input: u64) -> Result<crate::UnmapResult, HarnessError>
    where
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, E::Regime, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Unmap)?;
        self.with_mapper::<F, G, _>(|mapper| {
            mapper
                .unmap_reclaim(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map(|result| crate::UnmapResult {
                    mapping: crate::MappingInspection {
                        output: result.old().output().0,
                        level: LookupLevel::new(result.old().level().as_i8())
                            .expect("mapper returned an architectural lookup level"),
                    },
                    tables_freed: result.tables_freed(),
                    root_now_empty: result.root_now_empty(),
                })
                .map_err(|_| HarnessError::InvalidState)
        })
    }

    pub fn break_before_make<F, G>(
        &mut self,
        input: u64,
        output: Option<u64>,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E::Regime: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            G,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::regime::StageOf<E::Regime>,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
        aarch64_vmsa::regime::TableFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
    {
        self.failures.check(HarnessFailurePoint::Remap)?;
        self.failures.check(HarnessFailurePoint::Invalidation)?;
        self.with_mapper::<F, G, _>(|mapper| {
            crate::translation::replace_live_mapping(
                mapper,
                input,
                output,
                <E::Regime as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <E::Regime as TestRegimeFor<G>>::raw_table()?,
            )
        })
    }

    pub fn remap<F, G>(
        &mut self,
        input: u64,
        output: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E::Regime: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            G,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::regime::StageOf<E::Regime>,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
        aarch64_vmsa::regime::TableFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
    {
        self.break_before_make::<F, G>(input, Some(output), attributes)
    }

    pub fn break_before_make_for<R, F, G>(
        &mut self,
        input: u64,
        output: Option<u64>,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        R: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>>::Layout:
            aarch64_vmsa::descriptor::DescriptorLayout<
                    F,
                    aarch64_vmsa::regime::StageOf<R>,
                    G,
                    LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                    TableFields = aarch64_vmsa::regime::TableFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                >,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
        aarch64_vmsa::regime::TableFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Remap)?;
        self.failures.check(HarnessFailurePoint::Invalidation)?;
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            crate::translation::replace_live_mapping(
                mapper,
                input,
                output,
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
        })
    }

    pub fn remap_for<R, F, G>(
        &mut self,
        input: u64,
        output: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        R: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>>::Layout:
            aarch64_vmsa::descriptor::DescriptorLayout<
                    F,
                    aarch64_vmsa::regime::StageOf<R>,
                    G,
                    LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                    TableFields = aarch64_vmsa::regime::TableFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                >,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
        aarch64_vmsa::regime::TableFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    {
        self.break_before_make_for::<R, F, G>(input, Some(output), attributes)
    }

    pub fn protect<F, G>(
        &mut self,
        input: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E::Regime: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::regime::StageOf<E::Regime>,
            G,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                F,
                aarch64_vmsa::regime::StageOf<E::Regime>,
                G,
                LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
                TableFields = aarch64_vmsa::regime::TableFieldsOf<
                    aarch64_vmsa::descriptor::Vmsa64,
                    E::Regime,
                    G,
                >,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
        aarch64_vmsa::regime::TableFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            G,
        >: Copy,
    {
        self.failures.check(HarnessFailurePoint::Protect)?;
        self.with_mapper::<F, G, _>(|mapper| {
            crate::translation::replace_live_mapping(
                mapper,
                input,
                None,
                <E::Regime as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <E::Regime as TestRegimeFor<G>>::raw_table()?,
            )
        })
    }

    pub fn protect_for<R, F, G>(
        &mut self,
        input: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        R: TestRegimeFor<G>,
        G: TestGranule,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        aarch64_vmsa::descriptor::Vmsa64:
            aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        <F as aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>>::Layout:
            aarch64_vmsa::descriptor::DescriptorLayout<
                    F,
                    aarch64_vmsa::regime::StageOf<R>,
                    G,
                    LeafFields = aarch64_vmsa::regime::LeafFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                    TableFields = aarch64_vmsa::regime::TableFieldsOf<
                        aarch64_vmsa::descriptor::Vmsa64,
                        R,
                        G,
                    >,
                >,
        aarch64_vmsa::regime::LeafFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
        aarch64_vmsa::regime::TableFieldsOf<aarch64_vmsa::descriptor::Vmsa64, R, G>: Copy,
    {
        self.failures.check(HarnessFailurePoint::Protect)?;
        self.with_mapper_for::<R, F, G, _>(|mapper| {
            crate::translation::replace_live_mapping(
                mapper,
                input,
                None,
                <R as TestRegimeFor<G>>::raw_leaf(attributes)?,
                <R as TestRegimeFor<G>>::raw_table()?,
            )
        })
    }

    fn with_mapper<F, G, T>(
        &mut self,
        operation: impl FnOnce(
            &mut crate::translation::LiveTestMapper<F, E::Regime, G>,
        ) -> Result<T, HarnessError>,
    ) -> Result<T, HarnessError>
    where
        F: TestFormat
            + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<E::Regime>, G>,
        G: TestGranule,
        aarch64_vmsa::regime::LeafFieldsOf<F, E::Regime, G>: Copy,
    {
        if self.installed.is_none() {
            return Err(HarnessError::InvalidState);
        }
        let mut mapper = crate::translation::live_mapper::<F, E::Regime, G>(
            self.memory,
            self.setup,
            self.lower,
        )?;
        let result = operation(&mut mapper)?;
        if mapper.invalidation().failed() {
            return Err(HarnessError::InvalidState);
        }
        Ok(result)
    }

    fn with_mapper_for<R, F, G, T>(
        &mut self,
        operation: impl FnOnce(
            &mut crate::translation::LiveTestMapper<F, R, G>,
        ) -> Result<T, HarnessError>,
    ) -> Result<T, HarnessError>
    where
        R: aarch64_vmsa::regime::TranslationRegime,
        F: TestFormat + aarch64_vmsa::descriptor::HasLayout<aarch64_vmsa::regime::StageOf<R>, G>,
        G: TestGranule,
    {
        let mut mapper =
            crate::translation::live_mapper::<F, R, G>(self.memory, self.setup, self.lower)?;
        let result = operation(&mut mapper)?;
        if mapper.invalidation().failed() {
            return Err(HarnessError::InvalidState);
        }
        Ok(result)
    }

    fn with_recursive_mapper<T>(
        &mut self,
        recursive_index: usize,
        recursive_base: u64,
        operation: impl FnOnce(
            &mut crate::translation::RecursiveLiveTestMapper<E::Regime>,
        ) -> Result<T, HarnessError>,
    ) -> Result<T, HarnessError>
    where
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        if self.installed.is_none() || self.lower {
            return Err(HarnessError::InvalidState);
        }
        let mut mapper = crate::translation::recursive_live_mapper::<E::Regime>(
            self.memory,
            self.setup,
            recursive_index,
            recursive_base,
        )?;
        let result = operation(&mut mapper)?;
        if mapper.invalidation().failed() {
            return Err(HarnessError::InvalidState);
        }
        Ok(result)
    }

    pub fn map_recursive_4k(
        &mut self,
        recursive_index: usize,
        recursive_base: u64,
        input: u64,
        output: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E::Regime: TestRegimeFor<aarch64_vmsa::address::Granule4KiB>,
        aarch64_vmsa::descriptor::Vmsa64: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::regime::StageOf<E::Regime>,
                aarch64_vmsa::address::Granule4KiB,
            >,
        aarch64_vmsa::regime::LeafFieldsOf<
            aarch64_vmsa::descriptor::Vmsa64,
            E::Regime,
            aarch64_vmsa::address::Granule4KiB,
        >: Copy,
    {
        self.failures.check(HarnessFailurePoint::Map)?;
        self.with_recursive_mapper(recursive_index, recursive_base, |mapper| {
            mapper
                .map_leaf(
                    aarch64_vmsa::translation::WalkInputAddr::new(input),
                    aarch64_vmsa::address::PhysAddr(output),
                    aarch64_vmsa::address::Level::L3,
                    <E::Regime as TestRegimeFor<aarch64_vmsa::address::Granule4KiB>>::raw_leaf(
                        attributes,
                    )?,
                    <E::Regime as TestRegimeFor<aarch64_vmsa::address::Granule4KiB>>::raw_table()?,
                )
                .map_err(|_| HarnessError::InvalidState)?;
            mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
                .map(|mapping| crate::MappingInspection {
                    output: mapping.output().0,
                    level: LookupLevel::new(mapping.level().as_i8())
                        .expect("mapper returned an architectural lookup level"),
                })
                .ok_or(HarnessError::InvalidState)
        })
    }
}

impl<E: Environment> LiveTranslation<'_, E> {
    pub fn inspect_d128_hardware_updates_for<R>(
        &mut self,
        input: u64,
    ) -> Result<crate::D128HardwareUpdateInspection, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        R: aarch64_vmsa::regime::TranslationRegime,
        R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
                Stage = aarch64_vmsa::translation::Stage1,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::translation::Stage1,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
    {
        self.with_mapper_for::<
            R,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(|mapper| {
            mapper
                .translate(aarch64_vmsa::translation::WalkInputAddr::new(input))
                .map_err(|_| HarnessError::InvalidState)?
                .map(|mapping| crate::D128HardwareUpdateInspection {
                    access_flag: mapping.fields().access_flag,
                    dirty: !mapping.fields().not_dirty.bit(),
                })
                .ok_or(HarnessError::InvalidState)
        })
    }

    pub fn remap_d128_stage1_for<R>(
        &mut self,
        input: u64,
        output: u64,
        permissions: crate::D128MappingPermissions,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        R: aarch64_vmsa::regime::TranslationRegime,
        R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
                Stage = aarch64_vmsa::translation::Stage1,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::translation::Stage1,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
    {
        self.failures.check(HarnessFailurePoint::Remap)?;
        self.with_mapper_for::<
            R,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(|mapper| {
            crate::translation::replace_live_d128_stage1_mapping(
                mapper,
                input,
                Some(output),
                permissions,
            )
        })
    }

    pub fn protect_d128_stage1_for<R>(
        &mut self,
        input: u64,
        permissions: crate::D128MappingPermissions,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        R: aarch64_vmsa::regime::TranslationRegime,
        R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
                Stage = aarch64_vmsa::translation::Stage1,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::translation::Stage1,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::translation::Stage1,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage1TableAttrs,
            >,
    {
        self.failures.check(HarnessFailurePoint::Protect)?;
        self.with_mapper_for::<
            R,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(|mapper| {
            crate::translation::replace_live_d128_stage1_mapping(
                mapper,
                input,
                None,
                permissions,
            )
        })
    }

    pub fn remap_d128_stage2_for<R>(
        &mut self,
        input: u64,
        output: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        R: aarch64_vmsa::regime::TranslationRegime,
        R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
                Stage = aarch64_vmsa::translation::Stage2,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::translation::Stage2,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::translation::Stage2,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::translation::Stage2,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2TableAttrs,
            >,
    {
        self.failures.check(HarnessFailurePoint::Remap)?;
        self.with_mapper_for::<
            R,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(|mapper| {
            crate::translation::replace_live_d128_stage2_mapping(
                mapper,
                input,
                Some(output),
                attributes,
            )
        })
    }

    pub fn protect_d128_stage2_for<R>(
        &mut self,
        input: u64,
        attributes: crate::MappingAttributes,
    ) -> Result<crate::MappingInspection, HarnessError>
    where
        E: TranslationRegimeEnvironment,
        R: aarch64_vmsa::regime::TranslationRegime,
        R::WalkProfile: aarch64_vmsa::translation::TranslationWalkProfile<
                Stage = aarch64_vmsa::translation::Stage2,
            >,
        aarch64_vmsa::descriptor::Vmsa128: aarch64_vmsa::descriptor::HasLayout<
                aarch64_vmsa::translation::Stage2,
                aarch64_vmsa::address::Granule4KiB,
            >,
        <aarch64_vmsa::descriptor::Vmsa128 as aarch64_vmsa::descriptor::HasLayout<
            aarch64_vmsa::translation::Stage2,
            aarch64_vmsa::address::Granule4KiB,
        >>::Layout: aarch64_vmsa::descriptor::DescriptorLayout<
                aarch64_vmsa::descriptor::Vmsa128,
                aarch64_vmsa::translation::Stage2,
                aarch64_vmsa::address::Granule4KiB,
                LeafFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2LeafAttrs,
                TableFields = aarch64_vmsa::low_level::raw::RawVmsa128Stage2TableAttrs,
            >,
    {
        self.failures.check(HarnessFailurePoint::Protect)?;
        self.with_mapper_for::<
            R,
            aarch64_vmsa::descriptor::Vmsa128,
            aarch64_vmsa::address::Granule4KiB,
            _,
        >(|mapper| {
            crate::translation::replace_live_d128_stage2_mapping(
                mapper, input, None, attributes,
            )
        })
    }

    pub const fn setup(&self) -> TranslationSetup {
        self.setup
    }

    pub fn transition_sandbox_active(&self, sandbox: &TransitionSandbox) -> bool {
        if self.setup.granule != sandbox.granule
            || sandbox.stack_address & (sandbox.granule.bytes() - 1) != 0
            || sandbox.mailbox_address & (sandbox.granule.bytes() - 1) != 0
        {
            return false;
        }
        let mailbox_active = matches!(
            // SAFETY: The live translation and sandbox are tied to the same
            // single-threaded test context and this borrow ends with the access.
            unsafe { &mut *self.environment.as_ptr() }.perform_access(AccessRequest::read(
                sandbox.mailbox_address,
                AccessWidth::Double,
            )),
            AccessResult::Completed { value } if value == sandbox.marker
        );
        let stack_active = matches!(
            // SAFETY: Same serialized access and ownership argument as above.
            unsafe { &mut *self.environment.as_ptr() }.perform_access(AccessRequest::read(
                sandbox.stack_address,
                AccessWidth::Double,
            )),
            AccessResult::Completed { value: 0 }
        );
        mailbox_active
            && stack_active
            && vmsa_test_architecture::exception::recovery_vectors_active()
    }

    pub fn tlbi(&mut self, operation: crate::TlbiOperation) -> Result<(), HarnessError> {
        self.tlbi_scoped(crate::TlbiScope::InnerShareable, operation)
    }

    pub fn tlbi_scoped(
        &mut self,
        scope: crate::TlbiScope,
        operation: crate::TlbiOperation,
    ) -> Result<(), HarnessError> {
        if self.installed.is_none() {
            return Err(HarnessError::InvalidState);
        }
        self.failures.check(HarnessFailurePoint::Tlbi)?;
        crate::translation::explicit_tlbi(self.setup, self.lower, scope, operation)
    }

    pub fn initial_root(&self) -> Result<TranslationRootId, HarnessError> {
        if self.roots[0].is_none() {
            return Err(HarnessError::InvalidState);
        }
        Ok(TranslationRootId(0))
    }

    pub fn adopt_and_switch_lower_stage1_root(
        &mut self,
        root: RootTableMemory,
        asid: crate::Asid,
    ) -> Result<TranslationRootId, HarnessError> {
        let index = self
            .roots
            .iter()
            .position(Option::is_none)
            .ok_or(HarnessError::Memory)?;
        let id = TranslationRootId(index as u8);
        self.switch_lower_stage1_root_address(crate::PhysicalAddress::new(root.phys_addr()), asid)?;
        self.roots[index] = Some(root);
        Ok(id)
    }

    pub fn switch_lower_stage1_root(
        &mut self,
        root: TranslationRootId,
        asid: crate::Asid,
    ) -> Result<(), HarnessError> {
        let root = self
            .roots
            .get(root.0 as usize)
            .and_then(Option::as_ref)
            .ok_or(HarnessError::InvalidState)?;
        self.switch_lower_stage1_root_address(crate::PhysicalAddress::new(root.phys_addr()), asid)
    }

    fn switch_lower_stage1_root_address(
        &mut self,
        root: crate::PhysicalAddress,
        asid: crate::Asid,
    ) -> Result<(), HarnessError> {
        if !self.lower {
            return Err(HarnessError::InvalidState);
        }
        let installed = self.installed.ok_or(HarnessError::InvalidState)?;
        let updated = unsafe { self.environment.as_mut() }
            .switch_lower_stage1_root(installed, root, asid)
            .map_err(|_| HarnessError::Environment)?;
        self.setup = updated.setup();
        self.installed = Some(updated);
        Ok(())
    }

    pub fn restore(mut self) -> Result<(), HarnessError> {
        self.failures
            .check(HarnessFailurePoint::TranslationRestoration)?;
        let installed = self.installed.take().ok_or(HarnessError::InvalidState)?;
        // SAFETY: The live translation uniquely owns its installed adapter token.
        let result = unsafe { &mut *self.environment.as_ptr() }.restore_translation(installed);
        if result.is_err() {
            // SAFETY: CleanupState belongs to the live context and is written
            // only by owned restoration objects during single-threaded execution.
            unsafe { *self.cleanup.0.get() = true };
            return Err(HarnessError::Cleanup);
        }
        Ok(())
    }

    pub fn restore_owned(mut self) -> Result<RootTableMemory, HarnessError> {
        self.failures
            .check(HarnessFailurePoint::TranslationRestoration)?;
        if self.roots[0].is_none() || self.roots[1..].iter().any(Option::is_some) {
            return Err(HarnessError::InvalidState);
        }
        let installed = self.installed.take().ok_or(HarnessError::InvalidState)?;
        // SAFETY: The live translation uniquely owns its installed adapter token.
        if unsafe { &mut *self.environment.as_ptr() }
            .restore_translation(installed)
            .is_err()
        {
            // SAFETY: CleanupState is single-threaded and owned by this context.
            unsafe { *self.cleanup.0.get() = true };
            return Err(HarnessError::Cleanup);
        }
        self.roots[0].take().ok_or(HarnessError::InvalidState)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslationRootId(u8);

impl<E: Environment> Drop for LiveTranslation<'_, E> {
    fn drop(&mut self) {
        if let Some(installed) = self.installed.take() {
            // SAFETY: The context serializes adapter operations and outlives the guard.
            let result = unsafe { &mut *self.environment.as_ptr() }.restore_translation(installed);
            if result.is_err() {
                // SAFETY: CleanupState belongs to the live context and is only
                // written by translation guards during single-threaded execution.
                unsafe { *self.cleanup.0.get() = true };
            }
        }
    }
}

pub struct CombinedTranslation<'a, E: Environment> {
    stage2: Option<LiveTranslation<'a, E>>,
    stage1: Option<LiveTranslation<'a, E>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CombinedTlbiOperation {
    Stage1(crate::TlbiOperation),
    Stage2(crate::TlbiOperation),
    All,
}

impl<'a, E: Environment> CombinedTranslation<'a, E> {
    pub fn stage1_mut(&mut self) -> Result<&mut LiveTranslation<'a, E>, HarnessError> {
        self.stage1.as_mut().ok_or(HarnessError::InvalidState)
    }

    pub fn stage2_mut(&mut self) -> Result<&mut LiveTranslation<'a, E>, HarnessError> {
        self.stage2.as_mut().ok_or(HarnessError::InvalidState)
    }

    pub fn tlbi(
        &mut self,
        scope: crate::TlbiScope,
        operation: CombinedTlbiOperation,
    ) -> Result<(), HarnessError> {
        match operation {
            CombinedTlbiOperation::Stage1(operation) => {
                self.stage1_mut()?.tlbi_scoped(scope, operation)
            }
            CombinedTlbiOperation::Stage2(operation) => {
                self.stage2_mut()?.tlbi_scoped(scope, operation)
            }
            CombinedTlbiOperation::All => {
                // Stage-2 invalidation first removes cached combined results;
                // stage 1 then removes any independently cached first-stage entry.
                self.stage2_mut()?
                    .tlbi_scoped(scope, crate::TlbiOperation::All)?;
                self.stage1_mut()?
                    .tlbi_scoped(scope, crate::TlbiOperation::All)
            }
        }
    }

    fn access(&mut self, request: LowerElRequest) -> AccessResult {
        let Some(stage2) = self.stage2.as_mut() else {
            return AccessResult::HarnessFailure(HarnessError::InvalidState);
        };
        // SAFETY: CombinedTranslation owns both installed tokens and serializes
        // access through the same adapter used for their installation.
        unsafe { &mut *stage2.environment.as_ptr() }.run_lower_el(request)
    }

    pub fn read(&mut self, address: u64, width: AccessWidth) -> AccessResult {
        self.access(LowerElRequest::read(address, width))
    }

    pub fn read_u64(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Double)
    }

    pub fn read_u32(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Word)
    }

    pub fn read_u16(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Half)
    }

    pub fn read_u8(&mut self, address: u64) -> AccessResult {
        self.read(address, AccessWidth::Byte)
    }

    pub fn write(&mut self, address: u64, width: AccessWidth, value: u64) -> AccessResult {
        self.access(LowerElRequest::write(address, width, value))
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.write(address, AccessWidth::Double, value)
    }

    pub fn write_u32(&mut self, address: u64, value: u32) -> AccessResult {
        self.write(address, AccessWidth::Word, u64::from(value))
    }

    pub fn write_u16(&mut self, address: u64, value: u16) -> AccessResult {
        self.write(address, AccessWidth::Half, u64::from(value))
    }

    pub fn write_u8(&mut self, address: u64, value: u8) -> AccessResult {
        self.write(address, AccessWidth::Byte, u64::from(value))
    }

    pub fn read_acquire_u64(&mut self, address: u64) -> AccessResult {
        self.access(LowerElRequest::read_acquire(address))
    }

    pub fn write_release_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access(LowerElRequest::write_release(address, value))
    }

    pub fn atomic_swap_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access(LowerElRequest::atomic_swap(address, value))
    }

    pub fn exclusive_add_u64(&mut self, address: u64, value: u64) -> AccessResult {
        self.access(LowerElRequest::exclusive_add(address, value))
    }

    pub fn read_pair_u64(&mut self, address: u64) -> AccessResult {
        self.access(LowerElRequest::read_pair(address))
    }

    pub fn write_pair_u64(&mut self, address: u64, first: u64, second: u64) -> AccessResult {
        self.access(LowerElRequest::write_pair(address, first, second))
    }

    pub fn execute(&mut self, address: u64) -> AccessResult {
        self.access(LowerElRequest::execute(address))
    }

    pub fn translate(
        &mut self,
        address: u64,
        access: crate::TranslationQueryAccess,
    ) -> crate::TranslationQueryResult {
        let access = match access {
            crate::TranslationQueryAccess::Read => {
                vmsa_test_architecture::translation::TranslationAccess::Read
            }
            crate::TranslationQueryAccess::Write => {
                vmsa_test_architecture::translation::TranslationAccess::Write
            }
        };
        vmsa_test_architecture::translation::combined_stage1_stage2(address, access)
            .map_or(crate::TranslationQueryResult::Unsupported, |par| {
                crate::TranslationQueryResult::from_par(address, par)
            })
    }

    pub fn restore(mut self) -> Result<(), HarnessError> {
        if let Some(stage2) = self.stage2.take() {
            stage2.restore()?;
        }
        if let Some(stage1) = self.stage1.take() {
            stage1.restore()?;
        }
        Ok(())
    }
}

impl<E: Environment> Drop for CombinedTranslation<'_, E> {
    fn drop(&mut self) {
        if let Some(stage2) = self.stage2.take() {
            drop(stage2);
        }
        if let Some(stage1) = self.stage1.take() {
            drop(stage1);
        }
    }
}
