use zerocopy::Unalign;

fn main() {
    // Bug: deref_mut_unchecked — if this Unalign<u32> resides at an unaligned
    // address, the &mut u32 violates Rust's alignment invariant (UB).
    // Common when the Unalign is embedded in a packed struct or a &[u8] cast.
    let mut u = Unalign::new(42u32);
    let _r: &mut u32 = unsafe { u.deref_mut_unchecked() };

    // Safe alternative: use get_mut_ptr() and ensure alignment is satisfied.
    println!("{}", u.get());
}
