use ndarray::Array2;

fn main() {
    let arr = Array2::<f64>::zeros((4, 4));

    // Bug: uget without bounds checking — index components must be < dimension.
    // Out-of-bounds access reads memory past the array's allocation (UB).
    let _val: &f64 = unsafe { arr.uget([1, 2]) };
    println!("{}", _val);

    let mut arr2 = Array2::<f64>::zeros((4, 4));

    // Bug: uget_mut without bounds or aliasing check — exclusive access required.
    let _val_mut: &mut f64 = unsafe { arr2.uget_mut([3, 3]) };
    *_val_mut = 99.0;
    println!("{}", _val_mut);
}
