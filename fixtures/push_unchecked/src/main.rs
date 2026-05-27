use arrayvec::ArrayVec;

fn main() {
    let mut av: ArrayVec<u32, 4> = ArrayVec::new();

    // Bug: push_unchecked without checking that len < capacity first.
    // If called when the array is full, this is an out-of-bounds write (UB).
    unsafe {
        av.push_unchecked(1u32);
        av.push_unchecked(2u32);
        av.push_unchecked(3u32);
        av.push_unchecked(4u32);
        // If this were called again: OOB write past the end of the array.
    }

    println!("{:?}", av.as_slice());
}
