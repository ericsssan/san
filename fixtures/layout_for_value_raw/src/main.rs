#![feature(layout_for_ptr)]
use std::alloc::Layout;
use std::mem;

fn main() {
    let v = vec![1u32, 2, 3];
    let slice: &[u32] = &v;
    let thin: *const u32 = slice.as_ptr();

    // Construct a fat pointer with potentially wrong metadata.
    let fat: *const [u32] = std::ptr::slice_from_raw_parts(thin, slice.len());

    // Bug: Layout::for_value_raw — metadata must be valid.
    let layout = unsafe { Layout::for_value_raw(fat) };
    println!("size={} align={}", layout.size(), layout.align());

    // Bug: mem::size_of_val_raw — metadata must be valid.
    let sz = unsafe { mem::size_of_val_raw(fat) };

    // Bug: mem::align_of_val_raw — metadata must be valid.
    let al = unsafe { mem::align_of_val_raw(fat) };

    println!("{sz} {al}");
}
