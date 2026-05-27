#![feature(ascii_char)]

fn main() {
    // Bug: byte must be < 128; values >= 128 have no ascii::Char representation.
    let b = b'A';
    let _c = unsafe { std::ascii::Char::from_u8_unchecked(b) };

    // Bug: digit must be 0..=9; any other value produces an invalid ascii::Char.
    let _d = unsafe { std::ascii::Char::digit_unchecked(5) };

    // Bug: char must have code point < 128; non-ASCII chars are UB here.
    let ch = 'Z';
    let _ac = unsafe { ch.as_ascii_unchecked() };

    // Bug: every byte in the string must be ASCII; non-ASCII bytes are UB.
    let s = "hello";
    let _as: &[std::ascii::Char] = unsafe { s.as_ascii_unchecked() };

    // Bug: u8 must be < 128; a byte >= 128 has no ascii::Char representation.
    let byte: u8 = 65u8; // 'A'
    let _abc = unsafe { byte.as_ascii_unchecked() };
}
