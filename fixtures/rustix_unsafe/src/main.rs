// Fixture for rustix_unsafe checker.
// Uses rustix::mm::mmap_anonymous and munmap to demonstrate the unsafe memory-mapping API.

use std::ffi::c_void;

fn main() {
    let len = 4096_usize;

    // Bug: mmap_anonymous creates a mapping without checking whether the address range
    // aliases existing Rust references; munmap will later invalidate all pointers/references
    // into the region without any compile-time safety net.
    let ptr: *mut c_void = unsafe {
        rustix::mm::mmap_anonymous(
            std::ptr::null_mut(),
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE,
        )
        .unwrap()
    };

    // Bug: munmap makes all references/pointers into [ptr, ptr+len) dangling.
    unsafe {
        rustix::mm::munmap(ptr, len).unwrap();
    }
}
