use std::fs::File;
use memmap2::{Mmap, MmapOptions};

fn main() {
    let file = File::open("/etc/hosts").unwrap();

    // Bug: Mmap::map — if another process modifies the file, &[u8] bytes change silently.
    // san: memmap_unsafe — file must not be concurrently modified or truncated
    let _map = unsafe { Mmap::map(&file).unwrap() };

    // Bug: MmapOptions::map_exec — if the file is writable by another principal,
    //      an attacker can inject code into the executable mapping.
    // san: memmap_unsafe — file must not be writable by an untrusted principal
    let opts = MmapOptions::new();
    let _exec = unsafe { opts.map_exec(&file).unwrap() };
}
