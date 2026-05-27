use bitvec::index::{BitIdx, BitPos, BitSel};
use bitvec::prelude::*;
use bitvec::slice::from_raw_parts_unchecked;
use bitvec::ptr::{BitPtr, Const};

fn main() {
    // Bug: BitIdx::new_unchecked — idx must be < T::BITS (8 for u8).
    let _idx: BitIdx<u8> = unsafe { BitIdx::new_unchecked(5) };

    // Bug: BitPos::new_unchecked — pos must be < T::BITS.
    let _pos: BitPos<u8> = unsafe { BitPos::new_unchecked(3) };

    // Bug: BitSel::new_unchecked — sel must have exactly one bit set.
    let _sel: BitSel<u8> = unsafe { BitSel::new_unchecked(0b00001001u8) };

    // Bug: BitSlice::set_unchecked — no bounds check on index.
    let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0; 8];
    unsafe { bv.set_unchecked(2, true); }

    // Bug: BitSlice::replace_unchecked — no bounds check on index.
    let _old = unsafe { bv.replace_unchecked(2, false) };

    // Bug: BitSlice::copy_within_unchecked — no bounds check on ranges.
    let mut bv2: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0; 16];
    unsafe { bv2.copy_within_unchecked(0..4, 8); }

    // Bug: BitSlice::from_slice_unchecked — length overflow not checked.
    let data = [0u8; 4];
    let _bs: &BitSlice<u8, Msb0> = unsafe { BitSlice::from_slice_unchecked(&data) };

    // Bug: bitvec::slice::from_raw_parts_unchecked — pointer not validated.
    let bp: BitPtr<Const, u8, Msb0> = BitPtr::from_ref(&data[0]);
    let _bs2: &BitSlice<u8, Msb0> = unsafe { from_raw_parts_unchecked(bp, 16) };
}
