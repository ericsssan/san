fn main() {
    // Bug: char::from_u32_unchecked — value must be a valid Unicode scalar.
    let _c: char = unsafe { char::from_u32_unchecked(0x41) }; // 'A' — ok, but unsafe

    // Bug: surrogate value — UB.
    let _bad: char = unsafe { char::from_u32_unchecked(0xD800) };
}
