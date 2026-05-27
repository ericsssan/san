use std::ptr::NonNull;

fn main() {
    let mut x: i32 = 42;
    let mut nn: NonNull<i32> = NonNull::from(&mut x);

    // Bug: NonNull::as_ref — pointer must be valid, aligned, initialized; no mutable alias.
    let r: &i32 = unsafe { nn.as_ref() };
    let _ = r;

    // Bug: NonNull::as_mut — no other reference may exist for the lifetime of the result.
    let r_mut: &mut i32 = unsafe { nn.as_mut() };
    *r_mut = 99;
}
