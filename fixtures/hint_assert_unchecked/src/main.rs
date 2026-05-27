fn main() {
    let x: u32 = 5;
    // Bug: hint::assert_unchecked — if condition is ever false, behaviour is undefined.
    unsafe { std::hint::assert_unchecked(x > 0) };
    unsafe { std::hint::assert_unchecked(x < 100) };
}
