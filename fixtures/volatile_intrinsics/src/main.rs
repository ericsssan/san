#![feature(core_intrinsics)]
use std::intrinsics;

fn main() {
    let mut buf: [u8; 8] = [0u8; 8];
    let ptr = buf.as_mut_ptr();

    unsafe {
        // Bug: volatile_store — not atomic; using for inter-thread signaling without
        // synchronization is a data race.
        intrinsics::volatile_store(ptr, 0xAA_u8);

        // Bug: volatile_load — not atomic; concurrent writes from another thread are UB.
        let _v = intrinsics::volatile_load(ptr as *const u8);

        // Bug: volatile_set_memory — does not reliably clear sensitive data.
        intrinsics::volatile_set_memory(ptr, 0x00_u8, 8);

        // Bug: volatile_copy_nonoverlapping_memory — dst and src must not overlap.
        let mut dst: [u8; 8] = [0u8; 8];
        intrinsics::volatile_copy_nonoverlapping_memory(dst.as_mut_ptr(), ptr as *const u8, 8);

        // Bug: volatile_copy_memory — overlapping is allowed but not atomic.
        intrinsics::volatile_copy_memory(ptr, ptr.add(2) as *const u8, 4);

        // Bug: nontemporal_store — streaming store bypasses CPU cache; other threads
        // may see stale data without an explicit memory fence after the store sequence.
        intrinsics::nontemporal_store(ptr, 0xBB_u8);

        // Bug: unaligned_volatile_load — no alignment requirement, but src must be valid;
        // does NOT provide synchronization; concurrent writes are still a data race.
        let _u: u8 = intrinsics::unaligned_volatile_load(ptr as *const u8);

        // Bug: unaligned_volatile_store — unaligned writes allowed; NOT atomic.
        intrinsics::unaligned_volatile_store(ptr, 0xCC_u8);
    }
}
