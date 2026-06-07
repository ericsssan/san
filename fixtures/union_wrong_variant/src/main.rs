// Fixture: union_wrong_variant — flow-proven variant mismatch.
//
// Positive cases: active_variant[u] = field A, read of field B → union_wrong_field (Bug)
// Negative cases: read of same field that was written → suppressed
union NumUnion {
    i: i64,
    f: f64,
    b: u8,
}

/// Aggregate init writes field `i` (index 0); reading `f` (index 1) is definite UB.
/// san: union_wrong_field
fn wrong_after_aggregate_init() -> f64 {
    let u = NumUnion { i: 0x4000_0000_0000_0000i64 };  // active = field 0
    unsafe { u.f }                                       // san: union_wrong_field
}

/// Field-assignment write, different field read.
/// san: union_wrong_field
fn wrong_after_field_write() -> u8 {
    let mut u = NumUnion { i: 0 };
    unsafe { u.f = 1.5_f64 };  // active_variant → field 1
    unsafe { u.b }              // san: union_wrong_field (active=1, read=2)
}

/// Pointer-to-union pattern: write through *ptr then read different field.
/// san: union_wrong_field
fn wrong_through_ptr() -> i64 {
    let mut u = NumUnion { f: 0.0 };   // active = field 1
    let p: *mut NumUnion = &mut u;
    unsafe { (*p).i }                  // san: union_wrong_field (active=1, read=0)
}

/// Read same field that was written — provably correct.
/// san: no finding
fn correct_same_field() -> i64 {
    let u = NumUnion { i: 42 };   // active = field 0
    unsafe { u.i }                // same field → suppressed
}

/// Overwrite with a different field, then read that new field — correct.
/// san: no finding for the final read
fn correct_after_overwrite() -> f64 {
    let mut u = NumUnion { i: 0 };    // active = field 0
    unsafe { u.f = 2.0_f64 };         // active → field 1
    unsafe { u.f }                     // same as new active → suppressed
}

fn main() {
    let _ = wrong_after_aggregate_init();
    let _ = wrong_after_field_write();
    let _ = wrong_through_ptr();
    let _ = correct_same_field();
    let _ = correct_after_overwrite();
}
