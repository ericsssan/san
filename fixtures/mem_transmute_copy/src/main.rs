#![feature(transmute_prefix, transmute_neo, mem_conjure_zst)]

fn main() {
    let src: u64 = 0x3FF0_0000_0000_0000u64; // bits of 1.0f64

    // Bug: mem::transmute_copy — size_of::<U>() must not exceed size_of::<T>().
    let dst: f64 = unsafe { std::mem::transmute_copy(&src) };
    let _ = dst;

    // Bug: extracting a u32 from a u64 — only copies lower 4 bytes (endian-dependent).
    let half: u32 = unsafe { std::mem::transmute_copy(&src) };
    let _ = half;

    // Bug: transmute_prefix — compiler enforces prefix size but not bit validity.
    let prefix: u16 = unsafe { std::mem::transmute_prefix::<u32, u16>(42u32) };
    let _ = prefix;

    // Bug: transmute_neo — compiler checks size+alignment but not bit validity.
    let neo: u32 = unsafe { std::mem::transmute_neo::<i32, u32>(42i32) };
    let _ = neo;

    // Bug: conjure_zst — UB if T is not actually a ZST.
    let _unit: () = unsafe { std::mem::conjure_zst() };
}
