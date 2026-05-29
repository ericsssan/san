// Fixture: cross-crate alias. `Vec::as_mut_ptr` (a std accessor in another
// crate) returns a pointer into self's owned buffer. Freeing that pointer while
// self still owns the Vec leaves it dangling — a double-free on Drop. Catching
// this needs a cross-crate alias-of-param summary for the std accessor.

pub struct Holder {
    v: Vec<u32>,
}

unsafe fn freeit(p: *mut u32) {
    let _ = Vec::from_raw_parts(p, 0, 0);
}

impl Holder {
    pub fn bug(&mut self) {
        let p = self.v.as_mut_ptr(); // p aliases self.v's buffer (cross-crate)
        // san: use_after_free — frees self.v's buffer without replacing it
        unsafe { freeit(p) }
    }

    pub fn ok(&mut self) {
        let p = self.v.as_mut_ptr();
        self.v = Vec::new(); // hand off ownership before freeing → correct
        unsafe { freeit(p) }
    }
}

fn main() {
    let mut h = Holder { v: vec![1, 2, 3] };
    h.ok();
    let _ = Holder::bug as fn(&mut Holder);
}
