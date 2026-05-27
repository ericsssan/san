#![feature(cell_leak)]
use std::cell::RefCell;

fn main() {
    let rc = RefCell::new(42u32);

    // Bug: try_borrow_unguarded — no borrow guard is held; if a mutable borrow
    // is created while this reference is alive, that is immediate UB.
    let v: &u32 = unsafe { rc.try_borrow_unguarded().unwrap() };
    println!("value: {v}");

    // Using `v` here while a mutable borrow could be created elsewhere is UB.
    // Safe alternative: let v = rc.borrow();
}
