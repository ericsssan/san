// Negative fixture: MaybeUninit field-by-field initialization via as_mut_ptr().
//
// All fields of the inner struct type are written through the raw pointer
// before assume_init() is called — the analysis must NOT fire assume_init.
use std::mem::MaybeUninit;

struct Point { x: f64, y: f64 }

struct Triple { a: u32, b: u32, c: u32 }

/// All two fields written — should be suppressed.
fn all_fields_written_2() -> Point {
    let mut mu = MaybeUninit::<Point>::uninit();
    let p = mu.as_mut_ptr();
    unsafe {
        (*p).x = 1.0;    // field 0 written
        (*p).y = 2.0;    // field 1 written — all fields done → init promoted
        mu.assume_init() // no finding
    }
}

/// All three fields written — suppressed.
fn all_fields_written_3() -> Triple {
    let mut mu = MaybeUninit::<Triple>::uninit();
    let p = mu.as_mut_ptr();
    unsafe {
        (*p).a = 1;
        (*p).b = 2;
        (*p).c = 3;      // all 3 written → init promoted
        mu.assume_init() // no finding
    }
}

/// MaybeUninit::write() — whole-struct write, suppressed.
fn whole_write() -> Triple {
    let mut mu = MaybeUninit::<Triple>::uninit();
    mu.write(Triple { a: 0, b: 0, c: 0 });
    unsafe { mu.assume_init() } // no finding
}

fn main() {
    let _ = all_fields_written_2();
    let _ = all_fields_written_3();
    let _ = whole_write();
}
