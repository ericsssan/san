//! Positive fixture: double-ownership of a raw file descriptor.
//! A raw fd integer is passed to `from_raw_fd` twice — both resulting
//! `File` objects will close the same descriptor on drop.
//! san must emit a `raw_fd` Error finding for the second `from_raw_fd` call.
use std::fs::File;
use std::os::unix::io::{FromRawFd, IntoRawFd};

fn double_owner(f: File) -> (File, File) {
    let fd = f.into_raw_fd();
    let a = unsafe { File::from_raw_fd(fd) };  // first consumer — fd now in fd_consumed
    let b = unsafe { File::from_raw_fd(fd) };  // Bug: fd already consumed → double-close
    (a, b)
}

fn main() {
    let f = File::open("/dev/null").unwrap();
    let (_a, _b) = double_owner(f);
}
