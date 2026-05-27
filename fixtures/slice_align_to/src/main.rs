fn main() {
    let bytes: &[u8] = &[1, 0, 2, 0, 3, 0, 4, 0];
    // Bug: align_to reinterprets bytes as u16 — caller must guarantee all
    // bit patterns are valid for the target type.
    let (prefix, words, suffix): (&[u8], &[u16], &[u8]) = unsafe { bytes.align_to() };
    let _ = (prefix, words, suffix);

    let mut v = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    // Bug: align_to_mut — mutable transmutation; caller must not hold other
    // references to the prefix/suffix while the middle slice is live.
    let (pre, mid, suf): (&mut [u8], &mut [u16], &mut [u8]) = unsafe { v.align_to_mut() };
    let _ = (pre, mid, suf);
}
