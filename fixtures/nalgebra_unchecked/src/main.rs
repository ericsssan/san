use nalgebra::{Rotation3, Scale3, MatrixView3};

fn main() {
    // Bug: matrix_mut_unchecked — mutating the raw matrix can break the rotation
    // invariant (orthogonality, det = 1); subsequent rotation ops silently misbehave.
    let mut rot: Rotation3<f32> = Rotation3::identity();
    let _m = unsafe { rot.matrix_mut_unchecked() };

    // Bug: inverse_unchecked — scale factor 0.0 produces infinity for the inverse;
    // use inverse() which returns an Option, or check components first.
    let scale = Scale3::new(2.0f32, 3.0, 0.0);
    let _inv = unsafe { scale.inverse_unchecked() };

    // Bug: from_slice_unchecked — if the slice is shorter than rows * cols, reads
    // past the end of the allocation (UB).
    let data = vec![1.0f32; 9];
    let _view = unsafe { MatrixView3::from_slice_unchecked(&data, 0) };
}
