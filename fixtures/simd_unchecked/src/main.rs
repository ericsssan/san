#![feature(portable_simd)]
use std::simd::prelude::*;
use std::simd::Mask;

fn main() {
    let data = [10i32, 20, 30, 40];
    let indices = Simd::<usize, 4>::from_array([0, 2, 1, 3]);
    let mask = Mask::<isize, 4>::splat(true);

    // Bug: gather_select_unchecked — active indices must be in-bounds for `data`.
    let gathered = unsafe {
        i32x4::gather_select_unchecked(&data, mask, indices, i32x4::splat(0))
    };
    println!("gathered: {:?}", gathered.to_array());

    let mut target = [0i32; 4];
    // Bug: scatter_select_unchecked — active indices must be in-bounds and unique.
    unsafe {
        i32x4::from_array([1, 2, 3, 4]).scatter_select_unchecked(&mut target, mask, indices);
    }
    println!("scattered: {:?}", target);

    // Bug: Mask::set_unchecked — index must be < mask.len(); OOB writes past the mask storage.
    let mut m = Mask::<i32, 4>::splat(false);
    unsafe { m.set_unchecked(3, true) };
    println!("mask: {:?}", m);

    // Bug: load_select_unchecked — active lane i reads from slice[i]; i must be < slice.len().
    let mask_i32 = Mask::<i32, 4>::splat(true);
    let _loaded = unsafe { i32x4::load_select_unchecked(&data, mask_i32, i32x4::splat(0)) };

    // Bug: store_select_unchecked — active lane i writes to slice[i]; i must be < slice.len().
    let vals = i32x4::from_array([1, 2, 3, 4]);
    unsafe { vals.store_select_unchecked(&mut target, mask_i32) };

    // Bug: gather_ptr — every pointer lane must be valid for a T read.
    let ptrs: std::simd::Simd<*const i32, 4> = std::simd::Simd::from_array([
        &data[0], &data[1], &data[2], &data[3]
    ]);
    let _g = unsafe { i32x4::gather_ptr(ptrs) };

    // Bug: scatter_ptr — all pointer lanes must be valid for T write and be distinct.
    let dst_ptrs: std::simd::Simd<*mut i32, 4> = std::simd::Simd::from_array([
        &mut target[0], &mut target[1], &mut target[2], &mut target[3]
    ]);
    unsafe { vals.scatter_ptr(dst_ptrs) };

    // Bug: Mask::test_unchecked — index must be < mask.len(); OOB reads past the mask storage.
    let _bit = unsafe { m.test_unchecked(2) };

    // Bug: Mask::from_simd_unchecked — all lanes must be 0 or -1; any other value is UB.
    let raw: std::simd::Simd<i32, 4> = std::simd::Simd::splat(-1);
    let _m2 = unsafe { Mask::<i32, 4>::from_simd_unchecked(raw) };
}
