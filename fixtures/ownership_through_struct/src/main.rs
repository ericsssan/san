// Fixture: ownership tracking through struct construction.
// A raw pointer obtained from into_raw is stored in a struct field,
// then the struct is returned — this should NOT be flagged as a leak.
// Validates the Aggregate points_to propagation fix (commit 568aec5).

struct Wrapper {
    ptr: *mut u32,
}

fn wrap_it() -> Wrapper {
    let b = Box::new(42u32);
    let raw = Box::into_raw(b);
    Wrapper { ptr: raw } // owned pointer stored in struct — not a leak
}

fn leak_it() {
    let b = Box::new(99u32);
    let _raw = Box::into_raw(b);
    // raw goes out of scope without being passed to from_raw or stored — leak
}

fn main() {
    let w = wrap_it();
    unsafe { drop(Box::from_raw(w.ptr)) }; // reconstitute via from_raw
    leak_it();
}
