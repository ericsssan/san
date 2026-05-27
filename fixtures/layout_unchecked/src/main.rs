use std::alloc::Layout;

fn main() {
    // Bug: Layout::from_size_align_unchecked — align must be a power-of-two.
    let _layout = unsafe { Layout::from_size_align_unchecked(64, 8) };

    // Bug: using an unvalidated alignment from user input.
    let align: usize = 7; // NOT a power of two — UB
    let _bad = unsafe { Layout::from_size_align_unchecked(32, align) };
}
