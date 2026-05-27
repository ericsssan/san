use zerovec::{ZeroVec, ZeroSlice};
use potential_utf::PotentialCodePoint;

fn main() {
    // Bug: ZeroVec::from_bytes_unchecked — bytes not validated as valid T encoding.
    let bytes: &[u8] = &[1u8, 0, 0, 0, 2, 0, 0, 0];
    let _zv: ZeroVec<u32> = unsafe { ZeroVec::from_bytes_unchecked(bytes) };

    // Bug: ZeroSlice::from_bytes_unchecked — same byte-layout hazard.
    let _zs: &ZeroSlice<u32> = unsafe { ZeroSlice::from_bytes_unchecked(bytes) };

    // Bug: PotentialCodePoint::to_char_unchecked — value not validated as Unicode scalar.
    let pcp = PotentialCodePoint::from_char('A');
    let _ch: char = unsafe { pcp.to_char_unchecked() };
}
