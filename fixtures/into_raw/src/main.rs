#![feature(thread_raw)]
use std::sync::{Arc, Weak};
use std::thread;

// Inter-procedural cases: the raw pointer escapes the function via return or
// parameter — into_raw still fires because flow cannot verify the lifecycle.

// Bug: Box::into_raw — pointer escapes to caller; caller must call from_raw exactly once.
fn box_leak() -> *mut u32 {
    let b = Box::new(42u32);
    Box::into_raw(b)
}

// Bug: Arc::into_raw — pointer escapes to caller.
fn arc_leak() -> *const String {
    let a = Arc::new(String::from("shared"));
    Arc::into_raw(a)
}

// Bug: Vec::into_raw_parts — pointer escapes to caller.
fn vec_leak() -> (*mut u32, usize, usize) {
    let v = vec![1u32, 2, 3];
    v.into_raw_parts()
}

// Suppressed (NOT a bug finding): into_raw immediately paired with from_raw in the
// same function — flow proves the pointer is consumed on all paths; no audit noise.
fn no_finding_paired() {
    let b = Box::new(99u32);
    let raw = Box::into_raw(b);
    let _ = unsafe { Box::from_raw(raw) };  // san: suppressed — flow-verified
}

// Bug: Box::leak — allocation is never freed; must be reclaimed manually.
fn box_leak_static() -> &'static mut String {
    let b = Box::new(String::from("leaked"));
    Box::leak(b)  // san: into_raw (Box::leak)
}

fn main() {
    let _leaked = box_leak_static();
    let raw = box_leak();
    unsafe { let _ = Box::from_raw(raw); }

    let arc_raw = arc_leak();
    unsafe { let _ = Arc::from_raw(arc_raw); }

    let (ptr, len, cap) = vec_leak();
    unsafe { let _ = Vec::from_raw_parts(ptr, len, cap); }

    // Bug: Weak::into_raw — pointer escapes.
    let arc2 = Arc::new(99u32);
    let w: Weak<u32> = Arc::downgrade(&arc2);
    let weak_raw: *const u32 = w.into_raw();
    unsafe { let _ = Weak::from_raw(weak_raw); }

    // Bug: Thread::into_raw — pointer escapes.
    let t = thread::spawn(|| {}).thread().clone();
    let thread_ptr = t.into_raw();
    unsafe { let _ = thread::Thread::from_raw(thread_ptr); }

    no_finding_paired();
}
