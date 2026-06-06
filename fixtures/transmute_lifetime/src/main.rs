//! Positive fixture: san must fire [san::transmute_lifetime].
//!
//! Raw pointer → reference transmutes bypass all borrow-checker validation:
//! the fabricated reference's lifetime and aliasing are completely unchecked.
use std::ptr;

/// Fabricates a shared reference from *const T — lifetimes bypass borrow-ck.
unsafe fn ptr_to_ref<T>(p: *const T) -> &'static T {
    std::mem::transmute(p)   // ← san fires: *const T → &T transmute
}

/// Fabricates &mut T from *mut T — aliasing completely unchecked.
unsafe fn ptr_to_mut_ref<T>(p: *mut T) -> &'static mut T {
    std::mem::transmute(p)   // ← san fires: *mut T → &mut T transmute
}

fn main() {
    let val: u64 = 42;
    let r: &'static u64 = unsafe { ptr_to_ref(ptr::addr_of!(val)) };
    let mut val2: u64 = 7;
    let rm: &'static mut u64 = unsafe { ptr_to_mut_ref(ptr::addr_of_mut!(val2)) };
    let _ = r;
    let _ = rm;
}
