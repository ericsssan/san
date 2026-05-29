// Fixture: realloc-then-use. A raw pointer taken into a Vec's buffer is
// invalidated when the Vec reallocates (push/reserve/shrink_to_fit/…); using
// the stale pointer afterward is a (potential) use-after-free. This is the
// direct form of the RUSTSEC-2020-0007 (bitvec) bug class.

pub struct Holder {
    v: Vec<u32>,
}

impl Holder {
    pub fn bug(&mut self) -> u32 {
        let p = self.v.as_mut_ptr(); // p aliases the buffer
        self.v.push(99); // may reallocate -> p stale
        // san: use_after_free — reading through a pointer the realloc may have invalidated
        unsafe { *p }
    }

    pub fn ok(&mut self) -> u32 {
        // No reallocation between taking the pointer and using it.
        let p = self.v.as_mut_ptr();
        unsafe { *p }
    }
}

fn main() {
    let mut h = Holder { v: vec![1, 2, 3] };
    let _ = h.ok();
    let _ = Holder::bug as fn(&mut Holder) -> u32;
}
