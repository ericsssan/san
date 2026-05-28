// Fixture: demonstrates intra-procedural double-free detectable by flow analysis.
// The call-site checkers fire on both from_raw calls unconditionally; the flow
// checker fires on the SECOND one specifically because it sees Reconstituted state.
fn double_free() {
    let b = Box::new(42u32);
    let raw = Box::into_raw(b);
    unsafe {
        let _ = Box::from_raw(raw); // first reconstitution — fine
        let _ = Box::from_raw(raw); // double-free: raw is already Reconstituted
    }
}

fn main() {
    double_free();
}
