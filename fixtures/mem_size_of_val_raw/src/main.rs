#![feature(layout_for_ptr)]

trait Animal {
    fn sound(&self);
}

struct Dog;
impl Animal for Dog {
    fn sound(&self) { println!("woof"); }
}

fn main() {
    let nums = [1u32, 2, 3, 4];
    let slice_ptr: *const [u32] = &nums;

    // Bug: size_of_val_raw — pointer metadata must be valid.
    let sz = unsafe { std::mem::size_of_val_raw(slice_ptr) };
    println!("size of slice: {sz}");

    // Bug: align_of_val_raw — same validity requirements.
    let al = unsafe { std::mem::align_of_val_raw(slice_ptr) };
    println!("align of slice: {al}");

    // Also check with a dyn pointer — vtable metadata must match concrete type.
    let dog = Dog;
    let fat: *const dyn Animal = &dog as &dyn Animal;
    let dyn_sz = unsafe { std::mem::size_of_val_raw(fat) };
    println!("size of Dog via dyn: {dyn_sz}");
}
