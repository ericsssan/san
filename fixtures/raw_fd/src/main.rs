use std::os::unix::io::{FromRawFd, RawFd};

fn main() {
    // Bug: from_raw_fd — fd must be valid, open, and uniquely owned.
    // Using stdin's fd (0) as an example — the original owner must not also close it.
    let fd: RawFd = 0;
    let _file: std::fs::File = unsafe { std::fs::File::from_raw_fd(fd) };
}
