// Bug: calling a foreign C function — ABI, pointer validity, and safety
// invariants must be upheld by the caller.
unsafe extern "C" {
    fn abs(x: i32) -> i32;
}

fn main() {
    let result = unsafe { abs(-42) };
    println!("{}", result);
}
