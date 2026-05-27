fn main() {
    let data: Vec<u8> = vec![1, 2, 3, 4, 5];

    // Bug: as_chunks_unchecked — length 5 is not divisible by 2;
    // the last chunk reads one byte past the end of the allocation.
    let chunks: &[[u8; 2]] = unsafe { data.as_chunks_unchecked::<2>() };
    println!("chunks: {}", chunks.len());

    let mut data2: Vec<u8> = vec![1, 2, 3, 4, 5];
    // Bug: as_chunks_unchecked_mut — same length issue, mutable.
    let mchunks: &mut [[u8; 2]] = unsafe { data2.as_chunks_unchecked_mut::<2>() };
    println!("mchunks: {}", mchunks.len());
}
