// Multi-arch fixture: each cfg block targets one architecture.
// The san-driver is always compiled for the host, so only the host branch fires.

#[cfg(target_arch = "aarch64")]
fn main() {
    use std::arch::aarch64::*;
    let data = [1i32, 2, 3, 4];
    // Bug: SIMD intrinsic — requires NEON; alignment and lane-count must be correct.
    let v = unsafe { vld1q_s32(data.as_ptr()) };
    let sum = unsafe { vaddvq_s32(v) };
    println!("sum = {sum}");
}

#[cfg(target_arch = "x86_64")]
fn main() {
    use std::arch::x86_64::*;
    // Bug: SSE2 intrinsic — requires SSE2 CPU feature; _mm_load_si128 requires 16-byte alignment.
    unsafe {
        let a = _mm_set_epi32(1, 2, 3, 4);
        let b = _mm_set_epi32(5, 6, 7, 8);
        let c = _mm_add_epi32(a, b);
        let result: [i32; 4] = std::mem::transmute(c);
        println!("{:?}", result);
    }
}

#[cfg(target_arch = "x86")]
fn main() {
    use std::arch::x86::*;
    unsafe {
        let a = _mm_set_epi32(1, 2, 3, 4);
        let b = _mm_set_epi32(5, 6, 7, 8);
        let c = _mm_add_epi32(a, b);
        let result: [i32; 4] = std::mem::transmute(c);
        println!("{:?}", result);
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86")))]
fn main() {
    println!("arch_intrinsic fixture: no SIMD arch matched for this host");
}
