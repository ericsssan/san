// Fixture: into_raw with no corresponding from_raw — leak detected at Return.
fn leak() -> *mut u32 {
    let b = Box::new(42u32);
    Box::into_raw(b)
    // RawOwned pointer returned — tracked as escape by transfer, not a leak
    // (it's returned to the caller). Let's do the non-return case:
}

fn leak_internal() {
    let b = Box::new(99u32);
    let _raw = Box::into_raw(b);
    // _raw is dropped at end of scope but it's a raw pointer — no RAII drop.
    // The pointer is never passed to from_raw → leak.
}

fn main() {
    let _ = leak();
    leak_internal();
}
