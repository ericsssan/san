use std::mem::{self, ManuallyDrop};

fn main() {
    let s = String::from("owned string");
    let ptr = s.as_ptr();
    let len = s.len();
    let cap = s.capacity();

    // Bug: mem::forget — ownership not picked up elsewhere in this example.
    mem::forget(s);
    let _ = (ptr, len, cap);

    // Bug: ManuallyDrop::new — destructor suppressed; must be managed explicitly.
    let _md = ManuallyDrop::new(vec![1u32, 2, 3]);
}
