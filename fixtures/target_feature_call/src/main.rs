// Demonstrates calling a #[target_feature] function from a plain unsafe block
// without the corresponding CPU feature being in the calling function's context.
// Requires runtime feature detection before the call to be safe.
//
// Multi-arch: uses aarch64 neon on Apple Silicon, x86_64 SSE2 otherwise.

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon_sum(a: u32, b: u32) -> u32 {
    a + b
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sse2_sum(a: u32, b: u32) -> u32 {
    a + b
}

fn main() {
    // Bug: calling a target_feature function — the CPU feature (neon/sse2)
    // must be confirmed available before this call; calling without the
    // feature is undefined behaviour (SIGILL or silent wrong results).
    #[cfg(target_arch = "aarch64")]
    let _result = unsafe { neon_sum(1, 2) };

    #[cfg(target_arch = "x86_64")]
    let _result = unsafe { sse2_sum(1, 2) };
}
