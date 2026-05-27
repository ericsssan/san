// Bug: sgemm — raw pointer BLAS-style matrix multiply without bounds checking.
// Incorrect dimensions or strides cause out-of-bounds reads/writes (UB).
// The caller must ensure every pointer is valid for the declared m*k/k*n/m*n elements.
fn main() {
    let a = vec![1.0f32; 4]; // 2x2
    let b = vec![1.0f32; 4]; // 2x2
    let mut c = vec![0.0f32; 4]; // 2x2 result

    unsafe {
        matrixmultiply::sgemm(
            2, 2, 2,        // m, k, n
            1.0,
            a.as_ptr(), 2, 1, // A, rsa=2, csa=1 (row-major)
            b.as_ptr(), 2, 1, // B
            0.0,
            c.as_mut_ptr(), 2, 1, // C
        );
    }
    println!("{:?}", c);
}
