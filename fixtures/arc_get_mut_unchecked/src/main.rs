#![feature(get_mut_unchecked)]
// Demonstrates Arc::get_mut_unchecked and Rc::get_mut_unchecked (nightly, feature
// `get_mut_unchecked`, tracking issue #63292). These bypass the refcount check that
// the safe get_mut() uses. A latent soundness hole was documented in Jan 2025
// (rust-lang/rust#136322): any concurrent Arc drop for the borrow duration is UB.

use std::sync::Arc;
use std::rc::Rc;

fn main() {
    // Bug: Arc::get_mut_unchecked — strong count must be exactly 1, no Weak upgrading,
    // and no other Arc must be dropped for the duration of the returned borrow.
    let mut arc: Arc<i32> = Arc::new(42);
    let r: &mut i32 = unsafe { Arc::get_mut_unchecked(&mut arc) };
    *r = 100;

    // Bug: Rc::get_mut_unchecked — same requirements; additionally, no Rc::clone
    // may be dropped while the borrow is live (refcount write races the borrow).
    let mut rc: Rc<String> = Rc::new(String::from("hello"));
    let s: &mut String = unsafe { Rc::get_mut_unchecked(&mut rc) };
    s.push_str(" world");
}
