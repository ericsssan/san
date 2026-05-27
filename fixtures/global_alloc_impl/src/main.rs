use std::alloc::{GlobalAlloc, Layout, System};

// Bug: unsafe impl GlobalAlloc — must uphold all allocator invariants.
struct MyAllocator;

unsafe impl GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Delegates to System allocator for this example.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: MyAllocator = MyAllocator;

fn main() {
    let v: Vec<u32> = vec![1, 2, 3];
    let _ = v;
}
