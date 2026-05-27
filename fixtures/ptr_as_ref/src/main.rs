fn main() {
    let x: i32 = 42;
    let p: *const i32 = &x;

    // Bug: *const T::as_ref — pointer must be valid, aligned, initialized; no mutable alias.
    let _r: Option<&i32> = unsafe { p.as_ref() };

    let mut y: i32 = 99;
    let pm: *mut i32 = &mut y;

    // Bug: *mut T::as_mut — no other reference may exist for the lifetime of the result.
    let _rm: Option<&mut i32> = unsafe { pm.as_mut() };
}
