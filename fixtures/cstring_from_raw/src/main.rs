use std::ffi::CString;

// Inter-procedural case: ptr comes from outside the function — flow cannot
// verify it was obtained from CString::into_raw, so the Tier-1 warning fires.
unsafe fn reconstruct_from_extern(ptr: *mut i8) -> CString {
    CString::from_raw(ptr) // san: cstring_from_raw — pointer provenance unknown
}

// Intra-procedural case: ptr comes from a tracked into_raw in the same function.
// Flow suppresses the Tier-1 warning because OwnershipProtocol handles it.
fn round_trip() {
    let original = CString::new("hello").unwrap();
    let raw = original.into_raw();
    let _rebuilt = unsafe { CString::from_raw(raw) }; // suppressed — flow-tracked
}

fn main() {
    round_trip();
}
