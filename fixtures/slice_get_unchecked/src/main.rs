fn main() {
    let v = [10u32, 20, 30, 40, 50];

    // Bug: get_unchecked — index must be strictly < len; OOB is UB (no panic).
    let _elem: &u32 = unsafe { v.get_unchecked(2) };

    let mut buf = [0u8; 8];
    // Bug: get_unchecked_mut — index must be strictly < len.
    let slot: &mut u8 = unsafe { buf.get_unchecked_mut(5) };
    *slot = 0xFF;
}
