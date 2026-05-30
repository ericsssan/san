// Fixture: aliased raw pointer stored in two structs, freed via from_raw on both.
// This is the metacall RUSTSEC-2026-0139 shape: Clone copies a raw pointer field,
// then both instances call Box::from_raw on the same allocation.
//
// Case 1 — INTRA-PROCEDURAL: two Aggregate constructions from the same raw local.
// Case 2 — via Clone: the clone function copies self.raw into the new struct.

struct SharedPtr {
    raw: *mut u32,
}

impl Clone for SharedPtr {
    fn clone(&self) -> Self {
        SharedPtr { raw: self.raw } // copies pointer — both own the same allocation
    }
}

// Both p1 and p2 are built from the same raw pointer (no Clone call).
fn aliased_double_free_direct() {
    let b = Box::new(42u32);
    let raw = Box::into_raw(b);
    let p1 = SharedPtr { raw };   // p1.raw = raw
    let p2 = SharedPtr { raw };   // p2.raw = same raw — aliased!
    unsafe {
        drop(Box::from_raw(p1.raw));  // first reconstitution — fine
        drop(Box::from_raw(p2.raw));  // san: double-free — p2.raw aliases p1.raw
    }
}

// Clone-based alias: p.clone() copies the raw pointer into a second struct.
fn aliased_double_free_via_clone() {
    let b = Box::new(99u32);
    let raw = Box::into_raw(b);
    let p = SharedPtr { raw };
    let q = p.clone();  // q.raw == p.raw — both point to same allocation
    unsafe {
        drop(Box::from_raw(p.raw));  // first reconstitution — fine
        drop(Box::from_raw(q.raw));  // san: double-free — q.raw aliases p.raw
    }
}

// Correct: only one struct, one from_raw call.
fn no_alias() {
    let b = Box::new(7u32);
    let raw = Box::into_raw(b);
    let p = SharedPtr { raw };
    unsafe {
        drop(Box::from_raw(p.raw));  // single reconstitution — fine
    }
}

fn main() {
    aliased_double_free_direct();
    aliased_double_free_via_clone();
    no_alias();
}
