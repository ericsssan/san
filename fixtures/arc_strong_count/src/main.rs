// Bug: manually manipulating Arc/Rc strong counts bypasses ownership invariants.
// increment_strong_count: unbalanced increment → memory leak;
//   incrementing a dangling ptr → UB.
// decrement_strong_count: if count hits 0, value is dropped while raw ptr lives
//   → use-after-free on any subsequent access.
use std::rc::Rc;
use std::sync::Arc;

fn main() {
    // Arc::increment_strong_count — creates a phantom clone from a raw pointer.
    let arc = Arc::new(42i32);
    let ptr = Arc::into_raw(arc);
    unsafe {
        // Bug: increment without a matching from_raw or decrement causes a leak.
        Arc::increment_strong_count(ptr);
        // Bug: decrement may drop the allocation; ptr is now dangling.
        Arc::decrement_strong_count(ptr);
        // Retake ownership to avoid actual leak in the fixture.
        let _ = Arc::from_raw(ptr);
    }

    // Rc::increment_strong_count / decrement_strong_count (single-threaded).
    let rc = Rc::new(99i32);
    let ptr2 = Rc::into_raw(rc);
    unsafe {
        // Bug: same risks in single-threaded context.
        Rc::increment_strong_count(ptr2);
        Rc::decrement_strong_count(ptr2);
        let _ = Rc::from_raw(ptr2);
    }
}
