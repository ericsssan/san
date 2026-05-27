use std::cell::UnsafeCell;

fn main() {
    let cell = UnsafeCell::new(0i32);

    // Bug: UnsafeCell::get — returns *mut T; at most one &mut T may be active at a time.
    let ptr: *mut i32 = cell.get();
    unsafe { *ptr = 42 };

    // Bug: UnsafeCell::raw_get — same rules, called on raw pointer to cell.
    let cell_ptr: *const UnsafeCell<i32> = &cell;
    let raw: *mut i32 = UnsafeCell::raw_get(cell_ptr);
    let _ = unsafe { *raw };
}
