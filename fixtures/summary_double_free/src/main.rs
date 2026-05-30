// Fixture: double-free via cross-function call.
// A helper function reconstitutes a raw pointer via Box::from_raw.
// When called twice on the same pointer (which came from Box::into_raw
// in the caller), the second call is a double-free.
// Requires the summary mechanism: san builds a ParamHeapEffect::Reconstituted
// summary for consume_raw, then detects the second call on an already-
// Reconstituted object in double_free_via_fn.

fn consume_raw(ptr: *mut u32) {
    unsafe { let _ = Box::from_raw(ptr); }
}

fn double_free_via_fn() {
    let ptr = Box::into_raw(Box::new(42u32));
    consume_raw(ptr);  // first consumption: ptr transitions to Reconstituted
    consume_raw(ptr);  // san: ownership_double_free — double-free via summary
}

// Correct: consume only once.
fn no_double_free() {
    let ptr = Box::into_raw(Box::new(99u32));
    consume_raw(ptr);  // single consumption — correct
}

fn main() {
    no_double_free();
    let _ = double_free_via_fn as fn();
}
