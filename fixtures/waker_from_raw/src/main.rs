#![feature(local_waker)]
use std::task::{RawWaker, RawWakerVTable, Waker, LocalWaker};

static VTABLE: RawWakerVTable = RawWakerVTable::new(
    |data| RawWaker::new(data, &VTABLE),
    |_| {},
    |_| {},
    |_| {},
);

fn main() {
    // Bug: Waker::from_raw — vtable fn pointers and the data pointer must
    // uphold all safety requirements; vtable must be valid for Send+Sync.
    let raw = RawWaker::new(std::ptr::null(), &VTABLE);
    let _waker: Waker = unsafe { Waker::from_raw(raw) };

    // Bug: Waker::new (stable 1.83) — same safety requirements as from_raw.
    let _waker2: Waker = unsafe { Waker::new(std::ptr::null(), &VTABLE) };

    // Bug: LocalWaker::new (nightly local_waker) — same but not Send+Sync.
    let _lw: LocalWaker = unsafe { LocalWaker::new(std::ptr::null(), &VTABLE) };
}
