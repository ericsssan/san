use std::ptr;

fn main() {
    let mut s = std::mem::ManuallyDrop::new(String::from("hello"));

    // Bug: ptr::drop_in_place — must be called exactly once on valid, aligned, initialized data.
    unsafe { ptr::drop_in_place(&mut *s) };

    let mut v: Vec<i32> = vec![1, 2, 3];
    let p: *mut i32 = v.as_mut_ptr();

    // Bug: drop_in_place on element — must not be followed by Vec drop of same element.
    unsafe { ptr::drop_in_place(p) };
}
