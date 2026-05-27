#[cfg(unix)]
fn main() {
    use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
    use std::num::NonZeroUsize;
    use std::os::fd::OwnedFd;

    let size = NonZeroUsize::new(4096).unwrap();

    // Bug: mmap — returned pointer must not alias any Rust reference; caller manages lifetime.
    let ptr = unsafe {
        mmap(
            None,
            size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
            None::<OwnedFd>,
            0,
        )
        .unwrap()
    };

    // Write to the mapping.
    unsafe { (ptr as *mut u8).write(42) };

    // Bug: munmap — all references into this range become dangling after the call.
    unsafe { munmap(ptr, size.get()).unwrap() };
}

#[cfg(not(unix))]
fn main() {}
