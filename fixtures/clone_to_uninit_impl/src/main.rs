#![feature(clone_to_uninit)]
use std::clone::CloneToUninit;

// A type that deliberately does NOT implement Clone (so we can add CloneToUninit manually).
// Types that implement Clone get it via the blanket impl<T: Clone> CloneToUninit for T.
struct RawHandle {
    fd: i32,
}

// Bug: unsafe impl CloneToUninit — must fully initialize dst; partial init + panic = UB.
unsafe impl CloneToUninit for RawHandle {
    unsafe fn clone_to_uninit(&self, dst: *mut u8) {
        unsafe { (dst as *mut RawHandle).write(RawHandle { fd: self.fd }) };
    }
}

fn main() {
    let src = RawHandle { fd: 3 };
    let mut dst = std::mem::MaybeUninit::<RawHandle>::uninit();
    unsafe { src.clone_to_uninit(dst.as_mut_ptr() as *mut u8) };
    let cloned = unsafe { dst.assume_init() };
    println!("fd = {}", cloned.fd);
}
