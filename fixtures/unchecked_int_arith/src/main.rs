#![feature(exact_div, exact_bitshifts, disjoint_bitor, funnel_shifts)]

fn main() {
    let a: u32 = 100;
    let b: u32 = 200;

    // Bug: overflow is UB, not a panic or wrapping result.
    let _add = unsafe { a.unchecked_add(b) };
    // Bug: unsigned underflow (a < b here) is UB.
    let _sub = unsafe { b.unchecked_sub(a) };
    // Bug: multiplicative overflow is UB.
    let _mul = unsafe { a.unchecked_mul(b) };
    // Bug: shift amount >= 32 for u32 is UB.
    let _shl = unsafe { a.unchecked_shl(2) };
    let _shr = unsafe { a.unchecked_shr(2) };

    let x: i32 = 100;
    // Bug: unchecked_neg on i32::MIN is UB.
    let _neg = unsafe { x.unchecked_neg() };

    // Bug: unchecked_div_exact — divisor != 0, must divide evenly, no MIN/-1 overflow.
    let y: i32 = 4;
    let _div_exact = unsafe { x.unchecked_div_exact(y) };
    // Bug: unchecked_shl_exact — shift in range AND no 1-bits shifted out.
    let _shl_exact = unsafe { x.unchecked_shl_exact(2) };
    // Bug: unchecked_shr_exact — shift in range AND no 1-bits shifted out.
    let _shr_exact = unsafe { x.unchecked_shr_exact(2) };
    // Bug: unchecked_disjoint_bitor — both operands must have no overlapping bits.
    let a: u32 = 0b0101;
    let b: u32 = 0b1010;
    let _bitor = unsafe { a.unchecked_disjoint_bitor(b) };
    // Bug: unchecked_funnel_shl / unchecked_funnel_shr — n must be < bit-width.
    let hi: u32 = 0xAAAA_BBBB;
    let lo: u32 = 0xCCCC_DDDD;
    let _fshl: u32 = unsafe { hi.unchecked_funnel_shl(lo, 8) };
    let _fshr: u32 = unsafe { hi.unchecked_funnel_shr(lo, 8) };
}
