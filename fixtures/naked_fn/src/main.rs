// Demonstrates #[unsafe(naked)] functions (stable since Rust 1.88).
// Naked functions suppress the compiler-generated prologue/epilogue entirely;
// the naked_asm! body must manually implement the full calling convention.
//
// Multi-arch: uses aarch64 or x86_64 assembly depending on the target.

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
extern "C" fn add_aarch64(a: i32, b: i32) -> i32 {
    // Bug: the programmer must ensure:
    // - arguments are in w0, w1 (AArch64 C ABI)
    // - return value is placed in w0
    // - callee-saved registers (x19-x28, x29, x30) are preserved
    // An incorrect implementation is UB at every call site.
    core::arch::naked_asm!("add w0, w0, w1", "ret")
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
extern "C" fn add_x86_64(a: i32, b: i32) -> i32 {
    // Bug: the programmer must ensure:
    // - arguments are in edi, esi (System V AMD64 ABI for i32)
    // - return value is placed in eax
    // - callee-saved registers (rbx, rbp, r12-r15) are preserved
    // - stack is 16-byte aligned at the call site
    core::arch::naked_asm!("lea eax, [rdi + rsi]", "ret")
}

fn main() {
    #[cfg(target_arch = "aarch64")]
    let _r = unsafe { add_aarch64(1, 2) };
    #[cfg(target_arch = "x86_64")]
    let _r = unsafe { add_x86_64(1, 2) };
}
