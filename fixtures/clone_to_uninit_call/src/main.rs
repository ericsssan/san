#![feature(clone_to_uninit)]
use std::clone::CloneToUninit;
use std::mem::MaybeUninit;

fn main() {
    let src = String::from("hello");
    let mut dst: MaybeUninit<String> = MaybeUninit::uninit();

    // Bug: clone_to_uninit — dst must be uninitialized; must not drop the old value.
    unsafe {
        src.clone_to_uninit(dst.as_mut_ptr() as *mut u8);
    }

    let cloned = unsafe { dst.assume_init() };
    println!("{cloned}");
}
