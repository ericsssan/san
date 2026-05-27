// Fixture for typed_arena_unchecked checker.
// Exercises Arena::alloc_uninitialized which returns &mut [MaybeUninit<T>].

fn main() {
    let arena: typed_arena::Arena<u64> = typed_arena::Arena::new();

    // BUG: allocates 4 uninitialized u64 slots; caller must write every element
    // before any read. This fixture allocates but only writes 2 of 4 elements —
    // the remaining 2 are uninitialized and reading them would be UB.
    let buf: &mut [std::mem::MaybeUninit<u64>] = unsafe { arena.alloc_uninitialized(4) };

    // Initialize only the first two elements.
    buf[0].write(1);
    buf[1].write(2);
    // buf[2] and buf[3] are uninitialized — reading them is UB.

    let initialized: &[u64] = unsafe {
        &*(buf.get(0..2).unwrap() as *const [std::mem::MaybeUninit<u64>] as *const [u64])
    };
    println!("initialized: {:?}", initialized);
}
