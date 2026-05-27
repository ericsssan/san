use std::mem::MaybeUninit;

fn uninit_read() -> i32 {
    let x = MaybeUninit::<i32>::uninit();
    // Bug: assume_init on uninitialized memory — undefined behaviour.
    unsafe { x.assume_init() }
}

fn properly_initialized() -> i32 {
    let mut x = MaybeUninit::<i32>::uninit();
    x.write(42);
    // Still flagged: san cannot yet track whether write() was called first.
    unsafe { x.assume_init() }
}

fn main() {
    println!("{}", uninit_read());
    println!("{}", properly_initialized());
}
