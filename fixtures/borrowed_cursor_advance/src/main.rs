#![feature(core_io_borrowed_buf)]
use std::io::BorrowedBuf;

fn main() {
    let mut buf = [0u8; 64];
    let mut bb: BorrowedBuf<'_> = buf.as_mut_slice().into();
    let mut cursor = bb.unfilled();

    // Actually write some data first.
    cursor.append(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // Bug: advance marks bytes as initialized — caller must have written them.
    // If called with n > actually written bytes, exposes uninitialized memory.
    unsafe { cursor.advance(10) };

    println!("filled: {}", bb.filled().len());
}
