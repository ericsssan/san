#![feature(allocator_api)]
use std::alloc::{AllocError, Allocator, Layout};
use std::ptr::NonNull;

/// A bump allocator backed by a fixed buffer.
struct BumpAllocator {
    start: *mut u8,
    end: *mut u8,
    current: *mut u8,
}

// Bug: unsafe impl Allocator — must guarantee deallocate is only called with
// pointers from this allocator, with a compatible layout; grow/shrink must
// invalidate the old pointer on success; mixing allocator instances is UB.
unsafe impl Allocator for BumpAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let size = layout.size();
        let align = layout.align();
        let current = self.current as usize;
        let aligned = (current + align - 1) & !(align - 1);
        let new_current = aligned + size;
        if new_current > self.end as usize {
            return Err(AllocError);
        }
        unsafe {
            self.current.add(0); // pretend to bump; this is a stub
            let slice = std::ptr::slice_from_raw_parts_mut(aligned as *mut u8, size);
            Ok(NonNull::new_unchecked(slice))
        }
    }

    unsafe fn deallocate(&self, _ptr: NonNull<u8>, _layout: Layout) {
        // Bump allocators don't free individual allocations.
        // If called with a pointer not from this allocator, silent UB.
    }
}
