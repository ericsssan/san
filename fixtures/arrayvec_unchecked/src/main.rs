// Bug: into_inner_unchecked — caller must ensure the ArrayVec is completely
// full (len == CAP). Trailing uninitialized slots become invalid T values (UB).
use arrayvec::ArrayVec;

fn main() {
    let mut v: ArrayVec<i32, 4> = ArrayVec::new();
    v.push(1);
    v.push(2);
    v.push(3);
    v.push(4);

    // Safe to call here since len == 4 == CAP, but san still flags it
    // to enforce the invariant is audited at every call site.
    let arr: [i32; 4] = unsafe { v.into_inner_unchecked() };
    println!("{:?}", arr);
}
