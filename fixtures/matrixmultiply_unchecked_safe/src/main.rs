//! Negative fixture: `sgemm`/`dgemm` calls with proven row-major stride coherence.
//! san must emit ZERO `matrixmultiply_unchecked` findings.
//!
//! The locals_are_eq domain (cast_origin for IntToInt casts) proves that the
//! row strides rsa=k, rsb=n, rsc=n are exactly the corresponding dimension
//! locals cast to isize — the standard row-major layout signature.

/// Row-major sgemm: strides are `k as isize` and `n as isize` — each
/// `*_isize` local has `cast_origin == *` so `locals_are_eq` proves coherence.
pub fn sgemm_row_major(
    m: usize, k: usize, n: usize,
    a: &[f32], b: &[f32], c: &mut [f32],
) {
    unsafe {
        matrixmultiply::sgemm(
            m, k, n,
            1.0f32,
            a.as_ptr(),      k as isize, 1isize, // rsa=k, csa=1 → row-major
            b.as_ptr(),      n as isize, 1isize, // rsb=n, csb=1
            0.0f32,
            c.as_mut_ptr(),  n as isize, 1isize, // rsc=n, csc=1
        );
    }
}

/// Same coherence pattern for dgemm (f64).
pub fn dgemm_row_major(
    m: usize, k: usize, n: usize,
    a: &[f64], b: &[f64], c: &mut [f64],
) {
    unsafe {
        matrixmultiply::dgemm(
            m, k, n,
            1.0f64,
            a.as_ptr(),      k as isize, 1isize,
            b.as_ptr(),      n as isize, 1isize,
            0.0f64,
            c.as_mut_ptr(),  n as isize, 1isize,
        );
    }
}

fn main() {
    let a = vec![1.0f32; 4];
    let b = vec![1.0f32; 4];
    let mut c = vec![0.0f32; 4];
    sgemm_row_major(2, 2, 2, &a, &b, &mut c);
    println!("{:?}", c);

    let ad = vec![1.0f64; 4];
    let bd = vec![1.0f64; 4];
    let mut cd = vec![0.0f64; 4];
    dgemm_row_major(2, 2, 2, &ad, &bd, &mut cd);
    println!("{:?}", cd);
}
