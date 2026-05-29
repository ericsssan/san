// Fixture: realloc-then-use through a WRAPPER method. `grow` reallocates the
// inner Vec indirectly; its `reallocs_param` summary propagates that effect to
// the caller, so a buffer pointer taken before the call and used after is a
// (potential) use-after-free. This is the interprocedural generalization of the
// direct realloc-then-use pattern.

pub struct W {
    v: Vec<u32>,
}

impl W {
    // Not itself a recognized Vec realloc method — the realloc is one level down.
    fn grow(&mut self) {
        self.v.reserve(1000);
    }

    pub fn bug(&mut self) -> u32 {
        let p = self.v.as_mut_ptr(); // p aliases the buffer
        self.grow(); // reallocates via the wrapper -> p stale
        // san: use_after_free — the wrapper's realloc may have moved the buffer
        unsafe { *p }
    }

    pub fn ok(&mut self) -> u32 {
        let p = self.v.as_mut_ptr();
        unsafe { *p } // no realloc between -> fine
    }
}

fn main() {
    let mut w = W { v: vec![1, 2, 3] };
    let _ = w.ok();
    let _ = W::bug as fn(&mut W) -> u32;
}
