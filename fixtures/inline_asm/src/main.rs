use std::arch::asm;

fn add_via_asm(a: u64, b: u64) -> u64 {
    let result: u64;
    // Bug: asm! — must verify register constraints, clobbers, and memory effects.
    unsafe {
        asm!(
            "add {0}, {1}",
            inout(reg) a => result,
            in(reg) b,
        );
    }
    result
}

fn main() {
    let sum = add_via_asm(3, 4);
    let _ = sum;
}
