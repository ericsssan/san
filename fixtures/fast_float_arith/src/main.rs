#![feature(core_intrinsics)]
use std::intrinsics::{fadd_fast, fdiv_fast, fmul_fast, frem_fast, fsub_fast};

fn main() {
    let a: f64 = 1.0_f64;
    let b: f64 = 2.0_f64;

    // Bug: fadd_fast — UB if either operand is NaN or Inf.
    let _add = unsafe { fadd_fast(a, b) };
    // Bug: fsub_fast — UB if either operand is NaN or Inf.
    let _sub = unsafe { fsub_fast(a, b) };
    // Bug: fmul_fast — UB if either operand is NaN or Inf or result overflows to Inf.
    let _mul = unsafe { fmul_fast(a, b) };
    // Bug: fdiv_fast — UB if divisor is 0 (produces Inf) or either is NaN.
    let _div = unsafe { fdiv_fast(a, b) };
    // Bug: frem_fast — UB if divisor is 0 (produces NaN) or either operand is NaN/Inf.
    let _rem = unsafe { frem_fast(a, b) };
}
