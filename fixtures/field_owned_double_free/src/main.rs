// Fixture: double-free via struct field round-trip.
// A raw pointer is stored into a struct field, then read back twice —
// the second reconstitution is a double-free.
// Tests the field_owned domain: tracking survives the field store/load cycle.

struct RawBuf {
    ptr: *mut u32,
}

/// Store raw ptr into a field, read it back, free it, then free again via field.
/// san: ownership_double_free on the second Box::from_raw.
fn field_double_free() {
    let ptr = Box::into_raw(Box::new(42u32));
    let buf = RawBuf { ptr };
    // First free: read the field and reconstitute.
    let p1 = buf.ptr;
    let _ = unsafe { Box::from_raw(p1) };
    // Second free: read the field again — object is already Reconstituted.
    let p2 = buf.ptr;
    let _ = unsafe { Box::from_raw(p2) };  // san: ownership_double_free
}

/// Store raw ptr into a field, then mutate the field (overwrite).
/// The SECOND store is a different allocation — no double-free.
fn field_overwrite_safe() {
    let ptr1 = Box::into_raw(Box::new(1u32));
    let ptr2 = Box::into_raw(Box::new(2u32));
    let mut buf = RawBuf { ptr: ptr1 };
    buf.ptr = ptr2;  // overwrite: field_owned[(buf, 0)] now tracks ptr2
    let _ = unsafe { Box::from_raw(buf.ptr) };  // frees ptr2 — correct
    // ptr1 is legitimately leaked here (no second free = no double-free finding)
    std::mem::forget(unsafe { Box::from_raw(ptr1) });
}

fn main() {
    let _ = field_double_free as fn();
    field_overwrite_safe();
}
