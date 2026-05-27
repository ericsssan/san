use std::mem;

fn main() {
    // Bug: transmute from u32 to f32 — only safe if all bit patterns are valid f32
    // (all are, since f32 has no validity constraints beyond NaN semantics, but
    // transmuting a pointer to/from integer is UB if pointer provenance is violated).
    let x: u32 = 0x3F80_0000u32; // 1.0f32 in IEEE 754
    let _f: f32 = unsafe { mem::transmute(x) };

    // Bug: transmuting &[u8] to &[u16] — alignment and length assumptions.
    let bytes: &[u8] = &[0u8, 1, 2, 3];
    let _shorts: &[u16] = unsafe { mem::transmute(bytes) };

    // Bug: transmute_copy — same issues without the size check.
    let pair: (u32, u32) = (1, 2);
    let _u64: u64 = unsafe { mem::transmute_copy(&pair) };
}
