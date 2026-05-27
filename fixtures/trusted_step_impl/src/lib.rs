#![feature(step_trait, trusted_step, min_specialization)]
use std::iter::Step;

/// A custom ordinal type with a manually-implemented Step.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
struct Ordinal(u32);

impl Step for Ordinal {
    fn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
        if start <= end {
            let n = (end.0 - start.0) as usize;
            (n, Some(n))
        } else {
            (0, Some(0))
        }
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_add(count as u32).map(Ordinal)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_sub(count as u32).map(Ordinal)
    }
}

// Bug: TrustedStep asserts steps_between is exact; if arithmetic overflows the
// count will be wrong, enabling out-of-bounds accesses in range indexing.
unsafe impl std::iter::TrustedStep for Ordinal {}
