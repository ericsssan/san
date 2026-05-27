use bytes::{BufMut, BytesMut};

fn main() {
    let mut buf = BytesMut::with_capacity(64);

    // Bug: advance_mut without actually writing to the unfilled region first.
    // The advanced bytes contain uninitialized memory — any reader will see garbage.
    unsafe {
        buf.advance_mut(16);
    }

    println!("buf len: {}", buf.len());

    // A more typical (but still risky) pattern: get the raw chunk pointer,
    // write via unsafe, then advance.
    let mut buf2 = BytesMut::with_capacity(32);
    unsafe {
        let dst = buf2.chunk_mut();
        // Pretend we filled exactly 8 bytes (e.g. via a syscall).
        // Write the first two bytes only.
        let ptr = dst.as_mut_ptr();
        ptr.write(b'H');
        ptr.add(1).write(b'i');
        // advance_mut by 8 but only 2 were written — 6 bytes are uninit.
        buf2.advance_mut(8);
    }
}
