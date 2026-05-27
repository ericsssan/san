#![feature(unsafe_cell_access)]
// Demonstrates the nightly UnsafeCell reference-returning methods (feature `unsafe_cell_access`,
// tracking issue #136327). Unlike UnsafeCell::get() which returns *mut T, these return Rust
// references — the compiler assumes noalias, making aliasing violations more dangerous.

use std::cell::UnsafeCell;

fn main() {
    let cell = UnsafeCell::new(42i32);

    // Bug: as_ref_unchecked — returns &T from &UnsafeCell<T>; no mutable alias may exist
    // simultaneously. The compiler may assume the returned reference is never mutated.
    let _r: &i32 = unsafe { cell.as_ref_unchecked() };

    // Bug: as_mut_unchecked — returns &mut T from &UnsafeCell<T>; exclusive access required.
    // Calling this while _r is still live creates aliased &T / &mut T — immediate UB.
    let _m: &mut i32 = unsafe { cell.as_mut_unchecked() };

    // Bug: replace — swaps the inner value; no other reference to the interior may exist.
    let cell2 = UnsafeCell::new(99i32);
    let _old: i32 = unsafe { cell2.replace(0) };
}
