use std::mem::MaybeUninit;

fn uninit_read() -> i32 {
    let x = MaybeUninit::<i32>::uninit();
    // Bug: assume_init on uninitialized memory — undefined behaviour.
    unsafe { x.assume_init() }                // san: assume_init
}

fn properly_initialized() -> i32 {
    let mut x = MaybeUninit::<i32>::uninit();
    x.write(42);
    // write() sets init on the underlying MaybeUninit via ref_base — suppressed.
    unsafe { x.assume_init() }               // no finding
}

fn main() {
    println!("{}", uninit_read());
    println!("{}", properly_initialized());
}
