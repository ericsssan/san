// Demonstrates calling the unchecked raw-pointer-to-reference conversion methods
// (stable since Rust 1.95). Unlike `as_ref()` / `as_mut()` which return Option<&T>,
// these variants skip the null check entirely — a null pointer causes immediate UB.

fn main() {
    let x: i32 = 42;
    let p: *const i32 = &x;

    // Bug: as_ref_unchecked on *const T — no null check; if p were null this is UB.
    let _r: &i32 = unsafe { p.as_ref_unchecked() };

    let mut y: i32 = 99;
    let pm: *mut i32 = &mut y;

    // Bug: as_ref_unchecked on *mut T — same null/validity requirements.
    let _r2: &i32 = unsafe { pm.as_ref_unchecked() };

    // Bug: as_mut_unchecked on *mut T — additionally requires exclusive access;
    // creating another reference to *pm while _m is live is aliasing UB.
    let _m: &mut i32 = unsafe { pm.as_mut_unchecked() };
}
