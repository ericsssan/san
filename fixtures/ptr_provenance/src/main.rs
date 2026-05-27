use std::ptr;

fn main() {
    let x: u32 = 42;
    let p: *const u32 = &x;

    // Expose the provenance (method form) — marks the pointer for round-trip.
    let addr: usize = p.expose_provenance();

    // Bug: ptr::with_exposed_provenance — must use address from expose_provenance.
    let p2: *const u32 = unsafe { ptr::with_exposed_provenance(addr) };
    let _ = unsafe { *p2 };

    let mut y: u32 = 7;
    let pm: *mut u32 = &mut y;
    let addr2: usize = pm.expose_provenance();

    // Bug: ptr::with_exposed_provenance_mut — must use address from expose_provenance.
    let pm2: *mut u32 = unsafe { ptr::with_exposed_provenance_mut(addr2) };
    unsafe { *pm2 = 99 };
}
