// Bug: static mut — unguarded mutable global; concurrent access is a data race (UB).
static mut COUNTER: u32 = 0;
static mut BUFFER: [u8; 16] = [0u8; 16];

fn main() {
    unsafe {
        COUNTER += 1;
        BUFFER[0] = 42;
    }
}
