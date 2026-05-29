// Fixture: raw pointer dereferences written with `*ptr` syntax (not ptr::read/
// write calls). These are the most common form of raw deref and were previously
// missed entirely — the ptr_read/ptr_write/nonnull_deref checkers only match the
// function-call forms.

fn read_through_raw(p: *const u32) -> u32 {
    // san: raw_ptr_deref — read through a raw pointer
    unsafe { *p }
}

fn write_through_raw(p: *mut u32) {
    // san: raw_ptr_deref — write through a raw pointer
    unsafe { *p = 42 }
}

fn field_through_raw(p: *mut (u32, u32)) -> u32 {
    // san: raw_ptr_deref — field access through a raw pointer
    unsafe { (*p).0 }
}

// Safe derefs that MUST NOT be flagged.
fn safe_reference(r: &u32) -> u32 {
    *r
}

fn safe_box(b: Box<u32>) -> u32 {
    // `*box` lowers to a raw deref of the box's internal pointer, but it is safe.
    *b
}

fn safe_vec_index(v: &Vec<u32>) -> u32 {
    v[0]
}

fn main() {
    let mut x = 7u32;
    let pc: *const u32 = &x;
    let pm: *mut u32 = &mut x;
    let _ = read_through_raw(pc);
    write_through_raw(pm);
    let mut pair = (1u32, 2u32);
    let _ = field_through_raw(&mut pair);
    let _ = safe_reference(&x);
    let _ = safe_box(Box::new(9));
    let _ = safe_vec_index(&vec![1, 2, 3]);
}
