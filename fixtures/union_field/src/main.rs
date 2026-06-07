union Bits {
    i: i32,
    f: f32,
    bytes: [u8; 4],
}

fn main() {
    // Write via aggregate init (i field active).
    // Read of a different field: flow-proven wrong variant.
    let u = Bits { i: -1 };                        // active_variant[u] = 0 (field i)
    let _f: f32 = unsafe { u.f };                   // san: union_wrong_field (field 1 ≠ active 0)
    let _b: [u8; 4] = unsafe { u.bytes };           // san: union_wrong_field (field 2 ≠ active 0)

    // Write via field assignment, then read the SAME field: suppressed.
    let mut u2 = Bits { i: 0 };
    unsafe { u2.i = 7 };                            // active_variant[u2] = 0
    let _same: i32 = unsafe { u2.i };               // no finding — same field
}
