fn main() {
    let mut a = 10u32;
    let mut b = 20u32;

    // Bug: ptr::swap — both pointers must be valid, aligned, and initialized.
    unsafe { std::ptr::swap(&raw mut a, &raw mut b) };
    println!("after swap: a={a}, b={b}");

    let mut arr = [1u32, 2, 3, 4];
    // Bug: ptr::swap_nonoverlapping — regions must not overlap.
    // Passing arr[0] and arr[2] with count=1 is fine, but with count=2 they overlap.
    unsafe {
        std::ptr::swap_nonoverlapping(arr.as_mut_ptr(), arr.as_mut_ptr().add(2), 1);
    }
    println!("after swap_nonoverlapping: {arr:?}");
}
