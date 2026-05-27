fn main() {
    let opt: Option<i32> = Some(42);
    // Bug: Option::unwrap_unchecked — UB if called on None.
    let _v: i32 = unsafe { opt.unwrap_unchecked() };

    let ok: Result<i32, &str> = Ok(7);
    // Bug: Result::unwrap_unchecked — UB if called on Err.
    let _n: i32 = unsafe { ok.unwrap_unchecked() };

    let err: Result<i32, &str> = Err("oops");
    // Bug: Result::unwrap_err_unchecked — UB if called on Ok.
    let _e: &str = unsafe { err.unwrap_err_unchecked() };
}
