// Bug: psm::on_stack — executes closure on a caller-managed stack buffer.
// Undersized or misaligned buffer silently corrupts adjacent memory.
// Stack overflow within the closure is undetectable.
fn main() {
    let stack = vec![0u8; 1024 * 1024]; // 1 MiB — caller must size carefully
    let base = stack.as_ptr() as *mut u8;

    let result = unsafe {
        psm::on_stack(base, 1024 * 1024, || {
            compute(40)
        })
    };
    println!("{result}");
}

fn compute(x: u32) -> u32 {
    x + 2
}
