#![feature(step_trait)]
use std::iter::Step;

fn main() {
    // Bug: Step::forward_unchecked — count must not cause overflow.
    // Passing a count that exceeds i32::MAX - start produces UB.
    let next: i32 = unsafe { <i32 as Step>::forward_unchecked(i32::MAX - 1, 1) };
    let _ = next;

    // Bug: Step::backward_unchecked — count must not cause underflow.
    // Passing a count larger than start - i32::MIN produces UB.
    let prev: i32 = unsafe { <i32 as Step>::backward_unchecked(i32::MIN + 1, 1) };
    let _ = prev;
}
