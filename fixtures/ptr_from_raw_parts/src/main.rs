#![feature(ptr_metadata)]
use std::ptr::{self, NonNull};

trait Greet {
    fn hello(&self);
}

struct Foo;

impl Greet for Foo {
    fn hello(&self) {
        println!("hello from Foo");
    }
}

fn main() {
    let foo = Foo;
    let thin: *const Foo = &foo;

    // Get the vtable metadata for Foo as Greet.
    let fat: *const dyn Greet = &foo as &dyn Greet;
    let meta = ptr::metadata(fat);

    // Bug: ptr::from_raw_parts — vtable metadata must match the concrete type.
    let reconstructed: *const dyn Greet = unsafe { ptr::from_raw_parts(thin as *const (), meta) };
    unsafe { (*reconstructed).hello() };

    // Bug: ptr::from_raw_parts_mut for slice construction.
    let arr = [1u32, 2, 3];
    let slice: *const [u32] = unsafe { ptr::from_raw_parts(arr.as_ptr() as *const (), 3) };
    let _ = unsafe { &*slice };

    // Bug: NonNull::from_raw_parts — same vtable/length constraints apply.
    let nn_data: NonNull<()> = NonNull::new(thin as *mut ()).unwrap();
    let nn: NonNull<dyn Greet> = unsafe { NonNull::from_raw_parts(nn_data, meta) };
    unsafe { nn.as_ref().hello() };
}
