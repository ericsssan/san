#![feature(slice_swap_unchecked)]

fn main() {
    let mut v = [10u32, 20, 30, 40];

    // Bug: both indices must be < v.len(); unchecked skips that validation.
    unsafe { v.swap_unchecked(0, 3) };
    println!("after swap: {:?}", v);
}
