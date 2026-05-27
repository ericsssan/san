#![feature(thread_raw)]
use std::sync::{Arc, Weak};
use std::thread;

fn main() {
    // Bug: Box::into_raw — leaks Box; caller must call Box::from_raw exactly once.
    let b = Box::new(42u32);
    let raw: *mut u32 = Box::into_raw(b);
    let _ = unsafe { Box::from_raw(raw) };

    // Bug: Arc::into_raw — leaks Arc; caller must call Arc::from_raw exactly once.
    let a = Arc::new(String::from("shared"));
    let arc_raw: *const String = Arc::into_raw(a);
    let _ = unsafe { Arc::from_raw(arc_raw) };

    // Bug: Rc::into_raw — same as Arc but not thread-safe.
    let r = std::rc::Rc::new(vec![1u8, 2, 3]);
    let rc_raw: *const Vec<u8> = std::rc::Rc::into_raw(r);
    let _ = unsafe { std::rc::Rc::from_raw(rc_raw) };

    // Bug: Thread::into_raw — leaks Thread handle; must call Thread::from_raw exactly once.
    let t = thread::spawn(|| {}).thread().clone();
    let thread_ptr = t.into_raw();
    let _ = unsafe { thread::Thread::from_raw(thread_ptr) };

    // Bug: Vec::into_raw_parts — leaks Vec; caller must reconstitute via Vec::from_raw_parts.
    let v = vec![1u32, 2, 3];
    let (ptr, len, cap) = v.into_raw_parts();
    let _ = unsafe { Vec::from_raw_parts(ptr, len, cap) };

    // Bug: String::into_raw_parts — leaks String; reconstituted bytes must be valid UTF-8.
    let s = String::from("hello");
    let (sptr, slen, scap) = s.into_raw_parts();
    let _ = unsafe { String::from_raw_parts(sptr, slen, scap) };

    // Bug: Arc::Weak::into_raw — leaks Weak; caller must call Weak::from_raw exactly once.
    let arc2 = Arc::new(99u32);
    let w: Weak<u32> = Arc::downgrade(&arc2);
    let weak_raw: *const u32 = w.into_raw();
    let _ = unsafe { Weak::from_raw(weak_raw) };

    // Bug: Rc::Weak::into_raw — same as Arc::Weak but not thread-safe.
    let rc2 = std::rc::Rc::new(99u32);
    let rc_w = std::rc::Rc::downgrade(&rc2);
    let rc_weak_raw: *const u32 = rc_w.into_raw();
    let _ = unsafe { std::rc::Weak::from_raw(rc_weak_raw) };
}
