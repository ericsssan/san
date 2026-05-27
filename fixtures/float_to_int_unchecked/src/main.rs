fn main() {
    let x: f32 = 42.9;
    // Bug: to_int_unchecked — must verify finite and in-range before calling.
    let n: i32 = unsafe { x.to_int_unchecked() };
    let _ = n;

    let y: f64 = 1e18_f64;
    let m: u64 = unsafe { y.to_int_unchecked() };
    let _ = m;
}
