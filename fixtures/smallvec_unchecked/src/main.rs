use smallvec::SmallVec;
use std::mem::MaybeUninit;

fn main() {
    // Bug: from_buf_and_len_unchecked — len is not checked against inline capacity.
    // If len > A::size() the SmallVec's stored length exceeds its inline buffer.
    let mut buf: MaybeUninit<[u32; 4]> = MaybeUninit::uninit();
    unsafe {
        let ptr = buf.as_mut_ptr() as *mut u32;
        ptr.write(1);
        ptr.add(1).write(2);
        ptr.add(2).write(3);
        ptr.add(3).write(4);
    }
    let sv: SmallVec<[u32; 4]> = unsafe { SmallVec::from_buf_and_len_unchecked(buf, 4) };
    println!("{:?}", &sv[..]);
}
