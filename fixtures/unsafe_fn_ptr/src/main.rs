/// Demonstrates calling through `unsafe fn(...)` function pointers.
///
/// Bug: if the pointer is null, stale after library unload, or ABI-mismatched,
/// calling through it is immediate UB.

unsafe fn add(a: i32, b: i32) -> i32 {
    a + b
}

struct RawVTable {
    compute: unsafe fn(i32, i32) -> i32,
}

fn main() {
    let vtable = RawVTable { compute: add };

    // Bug: call through stored `unsafe fn` pointer — must verify the pointer is
    // valid, non-null, and its ABI matches the actual function at the address.
    let result = unsafe { (vtable.compute)(1, 2) };
    println!("{result}");

    // Bug: same pattern via a raw variable.
    let fp: unsafe fn(i32, i32) -> i32 = add;
    let _ = unsafe { fp(3, 4) };
}
