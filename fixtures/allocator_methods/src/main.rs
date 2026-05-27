#![feature(allocator_api)]
use std::alloc::{Global, Allocator, Layout};

fn main() {
    let layout = Layout::new::<u32>();

    let ptr = Global.allocate(layout).unwrap();

    // Bug: grow — old ptr is consumed; wrong layout or wrong allocator is UB.
    let new_layout = Layout::new::<u64>();
    let ptr2 = unsafe { Global.grow(ptr.cast(), layout, new_layout).unwrap() };

    // Bug: shrink — new_layout.size() must be <= old_layout.size().
    let ptr3 = unsafe { Global.shrink(ptr2.cast(), new_layout, layout).unwrap() };

    // Bug: deallocate — layout must match the original allocation exactly.
    unsafe { Global.deallocate(ptr3.cast(), layout) };

    println!("done");
}
