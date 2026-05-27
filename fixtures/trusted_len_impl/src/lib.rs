#![feature(trusted_len)]
use std::iter::TrustedLen;

/// Bug: TrustedLen impl may over-count, causing Vec::extend to write past allocation.
struct CountingIter {
    items: Vec<u32>,
    pos: usize,
}

impl Iterator for CountingIter {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.pos < self.items.len() {
            let v = self.items[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.items.len() - self.pos;
        (remaining, Some(remaining))
    }
}

// Bug: TrustedLen asserts size_hint is exact; if items grow between calls, this is UB.
unsafe impl TrustedLen for CountingIter {}
