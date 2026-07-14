use aarch64_vmsa::address::{PhysAddr, TranslationGranule};
use aarch64_vmsa::table::{TableAllocLayout, TableFrameProvider, TablePhysAddr};
use core::ptr::NonNull;

const MAX_ALLOCATIONS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    InvalidRegion,
    Exhausted,
    ScopeAlreadyActive,
    NoActiveScope,
    ScopeMismatch,
    InvalidFree,
    TooManyAllocations,
    AddressInvalid,
    InjectedFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum MemoryFailurePoint {
    Page = 0,
    Contiguous = 1,
    Root = 2,
    TableFrame = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryScope {
    pub(crate) checkpoint: usize,
    generation: u64,
    allocation_checkpoint: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Page {
    physical: u64,
    virtual_address: NonNull<u8>,
    pages: usize,
}
impl Page {
    pub const fn phys_addr(self) -> u64 {
        self.physical
    }
    pub fn virtual_address(self) -> *mut u8 {
        self.virtual_address.as_ptr()
    }
    pub const fn pages(self) -> usize {
        self.pages
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RootTableMemory(Page);
impl RootTableMemory {
    pub const fn phys_addr(&self) -> u64 {
        self.0.phys_addr()
    }
    pub fn virtual_address(&self) -> *mut u8 {
        self.0.virtual_address()
    }
}

#[derive(Clone, Copy)]
struct Allocation {
    offset: usize,
    bytes: usize,
    align: usize,
    table: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct TableAllocationRegion {
    pub(crate) virtual_address: u64,
    pub(crate) physical_address: u64,
    pub(crate) bytes: usize,
}
const EMPTY_ALLOCATION: Allocation = Allocation {
    offset: 0,
    bytes: 0,
    align: 1,
    table: false,
};

pub struct TestMemory {
    virtual_base: NonNull<u8>,
    physical_base: u64,
    bytes: usize,
    cursor: usize,
    generation: u64,
    active_scope: bool,
    allocations: [Allocation; MAX_ALLOCATIONS],
    allocation_count: usize,
    failures: [Option<usize>; 4],
}

impl TestMemory {
    /// Creates an arena over memory reserved exclusively by firmware.
    ///
    /// # Safety
    ///
    /// The virtual interval must be writable, must correspond contiguously to
    /// `physical_base`, and must not overlap payload, firmware, or device memory.
    pub unsafe fn new(
        virtual_base: *mut u8,
        physical_base: u64,
        bytes: usize,
    ) -> Result<Self, MemoryError> {
        let virtual_base = NonNull::new(virtual_base).ok_or(MemoryError::InvalidRegion)?;
        if bytes < 4096
            || physical_base & 0xfff != 0
            || (virtual_base.as_ptr() as usize) & 0xfff != 0
        {
            return Err(MemoryError::InvalidRegion);
        }
        Ok(Self {
            virtual_base,
            physical_base,
            bytes,
            cursor: 0,
            generation: 0,
            active_scope: false,
            allocations: [EMPTY_ALLOCATION; MAX_ALLOCATIONS],
            allocation_count: 0,
            failures: [None; 4],
        })
    }

    pub fn begin_scope(&mut self) -> Result<MemoryScope, MemoryError> {
        if self.active_scope {
            return Err(MemoryError::ScopeAlreadyActive);
        }
        self.active_scope = true;
        self.generation = self.generation.wrapping_add(1);
        Ok(MemoryScope {
            checkpoint: self.cursor,
            generation: self.generation,
            allocation_checkpoint: self.allocation_count,
        })
    }

    pub fn reset(&mut self, scope: MemoryScope) -> Result<(), MemoryError> {
        if !self.active_scope {
            return Err(MemoryError::NoActiveScope);
        }
        if scope.generation != self.generation
            || scope.checkpoint > self.cursor
            || scope.allocation_checkpoint > self.allocation_count
        {
            return Err(MemoryError::ScopeMismatch);
        }
        let length = self.cursor - scope.checkpoint;
        // SAFETY: The scope's allocated interval is inside the reserved arena and
        // cannot overlap firmware memory by the constructor contract.
        unsafe {
            core::ptr::write_bytes(self.virtual_base.as_ptr().add(scope.checkpoint), 0, length)
        };
        self.cursor = scope.checkpoint;
        self.allocation_count = scope.allocation_checkpoint;
        self.active_scope = false;
        self.failures = [None; 4];
        Ok(())
    }

    pub fn allocate_page(&mut self) -> Result<Page, MemoryError> {
        self.allocate_pages_at(MemoryFailurePoint::Page, 1)
    }
    pub fn allocate_pages(&mut self, pages: usize) -> Result<Page, MemoryError> {
        self.allocate_pages_at(MemoryFailurePoint::Contiguous, pages)
    }
    #[doc(hidden)]
    pub fn allocate_aligned_pages(
        &mut self,
        pages: usize,
        align: usize,
    ) -> Result<Page, MemoryError> {
        let bytes = pages.checked_mul(4096).ok_or(MemoryError::Exhausted)?;
        self.allocate(MemoryFailurePoint::Contiguous, bytes, align, false)
            .map(|allocation| Page {
                physical: self.physical_base + allocation.offset as u64,
                virtual_address: self.pointer(allocation.offset),
                pages,
            })
    }
    fn allocate_pages_at(
        &mut self,
        point: MemoryFailurePoint,
        pages: usize,
    ) -> Result<Page, MemoryError> {
        let bytes = pages.checked_mul(4096).ok_or(MemoryError::Exhausted)?;
        self.allocate(point, bytes, 4096, false)
            .map(|allocation| Page {
                physical: self.physical_base + allocation.offset as u64,
                virtual_address: self.pointer(allocation.offset),
                pages,
            })
    }
    pub fn allocate_root(
        &mut self,
        bytes: usize,
        align: usize,
    ) -> Result<RootTableMemory, MemoryError> {
        self.allocate(MemoryFailurePoint::Root, bytes, align, true)
            .map(|allocation| {
                RootTableMemory(Page {
                    physical: self.physical_base + allocation.offset as u64,
                    virtual_address: self.pointer(allocation.offset),
                    pages: bytes.div_ceil(4096),
                })
            })
    }

    pub(crate) fn inject_failure(
        &mut self,
        point: MemoryFailurePoint,
        successful_allocations: usize,
    ) -> Result<(), MemoryError> {
        let slot = &mut self.failures[point as usize];
        if slot.is_some() {
            return Err(MemoryError::ScopeMismatch);
        }
        *slot = Some(successful_allocations);
        Ok(())
    }

    pub(crate) const fn physical_base(&self) -> u64 {
        self.physical_base
    }

    pub(crate) const fn byte_len(&self) -> usize {
        self.bytes
    }

    pub(crate) fn maximum_contiguous_pages(&self) -> usize {
        let Some(physical_cursor) = self.physical_base.checked_add(self.cursor as u64) else {
            return 0;
        };
        let adjustment = (4096 - (physical_cursor as usize & 4095)) & 4095;
        self.bytes
            .checked_sub(self.cursor)
            .and_then(|remaining| remaining.checked_sub(adjustment))
            .map_or(0, |remaining| remaining / 4096)
    }

    pub(crate) const fn allocation_count(&self) -> usize {
        self.allocation_count
    }

    pub(crate) fn table_allocation_region(&self, index: usize) -> Option<TableAllocationRegion> {
        let allocation = *self.allocations.get(index)?;
        if index >= self.allocation_count || !allocation.table {
            return None;
        }
        Some(TableAllocationRegion {
            virtual_address: self.pointer(allocation.offset).as_ptr() as u64,
            physical_address: self.physical_base + allocation.offset as u64,
            bytes: allocation.bytes,
        })
    }

    pub(crate) fn clear_failure(&mut self, point: MemoryFailurePoint) {
        self.failures[point as usize] = None;
    }

    fn allocate(
        &mut self,
        point: MemoryFailurePoint,
        bytes: usize,
        align: usize,
        table: bool,
    ) -> Result<Allocation, MemoryError> {
        if !self.active_scope {
            return Err(MemoryError::NoActiveScope);
        }
        if bytes == 0 || !align.is_power_of_two() {
            return Err(MemoryError::AddressInvalid);
        }
        if self.allocation_count == MAX_ALLOCATIONS {
            return Err(MemoryError::TooManyAllocations);
        }
        if let Some(remaining) = self.failures[point as usize].as_mut() {
            if *remaining == 0 {
                return Err(MemoryError::InjectedFailure);
            }
            *remaining -= 1;
        }
        let physical_cursor = self
            .physical_base
            .checked_add(self.cursor as u64)
            .ok_or(MemoryError::Exhausted)?;
        let adjustment = (align - (physical_cursor as usize & (align - 1))) & (align - 1);
        let offset = self
            .cursor
            .checked_add(adjustment)
            .ok_or(MemoryError::Exhausted)?;
        let end = offset.checked_add(bytes).ok_or(MemoryError::Exhausted)?;
        if end > self.bytes {
            return Err(MemoryError::Exhausted);
        }
        // SAFETY: Bounds were checked and the arena is exclusively borrowed.
        unsafe { core::ptr::write_bytes(self.virtual_base.as_ptr().add(offset), 0, bytes) };
        let allocation = Allocation {
            offset,
            bytes,
            align,
            table,
        };
        self.allocations[self.allocation_count] = allocation;
        self.allocation_count += 1;
        self.cursor = end;
        Ok(allocation)
    }

    fn pointer(&self, offset: usize) -> NonNull<u8> {
        // SAFETY: All callers pass a checked offset inside the arena.
        unsafe { NonNull::new_unchecked(self.virtual_base.as_ptr().add(offset)) }
    }

    pub(crate) fn physical_to_virtual_offset(&self) -> u64 {
        (self.virtual_base.as_ptr() as u64).wrapping_sub(self.physical_base)
    }
}

impl<G: TranslationGranule> TableFrameProvider<G> for TestMemory {
    type Error = MemoryError;
    type Frame = TablePhysAddr<G>;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<Self::Frame, Self::Error> {
        let allocation = self.allocate(
            MemoryFailurePoint::TableFrame,
            layout.bytes() as usize,
            layout.align() as usize,
            true,
        )?;
        TablePhysAddr::new(PhysAddr(self.physical_base + allocation.offset as u64))
            .map_err(|_| MemoryError::AddressInvalid)
    }

    /// # Safety
    ///
    /// `frame` must be the most recently allocated live table for this provider.
    unsafe fn free_table(
        &mut self,
        frame: TablePhysAddr<G>,
        layout: TableAllocLayout,
    ) -> Result<(), Self::Error> {
        if self.allocation_count == 0 {
            return Err(MemoryError::InvalidFree);
        }
        let allocation = self.allocations[self.allocation_count - 1];
        let expected = self.physical_base + allocation.offset as u64;
        if !allocation.table
            || frame.raw() != expected
            || allocation.bytes != layout.bytes() as usize
            || allocation.align != layout.align() as usize
        {
            return Err(MemoryError::InvalidFree);
        }
        // SAFETY: The exact most-recent table allocation was validated and no
        // safe reference to it is manufactured by TestMemory.
        unsafe {
            core::ptr::write_bytes(
                self.virtual_base.as_ptr().add(allocation.offset),
                0,
                allocation.bytes,
            )
        };
        self.cursor = allocation.offset;
        self.allocation_count -= 1;
        Ok(())
    }
}
