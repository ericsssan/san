// Fixture: CString::into_raw / CString::from_raw double-free.
// Calling CString::from_raw twice on the same pointer frees the CString
// allocation twice — undefined behavior (heap corruption).
use std::ffi::CString;

fn double_free_cstring() {
    let cs = CString::new("hello").unwrap();
    let raw = cs.into_raw();
    unsafe {
        let _c1 = CString::from_raw(raw);
        let _c2 = CString::from_raw(raw); // san: double-free
    }
}

// Correct: single from_raw for a single into_raw.
fn no_double_free() {
    let cs = CString::new("world").unwrap();
    let raw = cs.into_raw();
    unsafe {
        let _ = CString::from_raw(raw); // single reconstitution — fine
    }
}

fn main() {
    double_free_cstring();
    no_double_free();
}
