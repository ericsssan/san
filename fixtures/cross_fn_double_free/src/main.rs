// Fixture: the real shape of RUSTSEC-2019-0009 (smallvec `grow` double-free).
// An accessor returns a pointer into `self` (interprocedural alias summary);
// freeing that pointer while `self` still holds it leaves `self` dangling — a
// double-free when `self` is later dropped. The detector must flag the buggy
// path and stay silent when `self` is reassigned first.

pub struct Buf {
    cap: usize,
    ptr: *mut u32,
}

// frees the pointer it is given (mirrors smallvec's `deallocate`).
unsafe fn deallocate(ptr: *mut u32, cap: usize) {
    let _ = Vec::from_raw_parts(ptr, 0, cap);
}

impl Buf {
    // returns `&mut` into self (mirrors heap_mut)
    fn slot(&mut self) -> &mut *mut u32 {
        &mut self.ptr
    }
    // hands back the pointer stored in self (mirrors triple_mut)
    fn current(&mut self) -> *mut u32 {
        unsafe { *self.slot() }
    }

    pub fn shrink_buggy(&mut self) {
        let ptr = self.current(); // ptr aliases self.ptr (via the accessor chain)
        // san: use_after_free — frees self's buffer without clearing self.ptr;
        // self is left dangling and double-frees on Drop.
        unsafe { deallocate(ptr, self.cap); }
    }

    pub fn shrink_ok(&mut self) {
        let ptr = self.current();
        self.ptr = std::ptr::null_mut(); // hand off ownership BEFORE freeing → correct
        unsafe { deallocate(ptr, self.cap); }
    }
}

fn main() {
    let mut b = Buf { cap: 0, ptr: std::ptr::null_mut() };
    b.shrink_ok();
    // shrink_buggy is UB to actually call; just reference it so it is retained.
    let _ = Buf::shrink_buggy as fn(&mut Buf);
}
