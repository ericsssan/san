use ordered_float::NotNan;

fn main() {
    let x = 1.0f64;

    // Bug: new_unchecked — value must not be NaN.
    // If it is, Ord/Eq/Hash invariants are broken — sorts and map lookups misbehave.
    let nn: NotNan<f64> = unsafe { NotNan::new_unchecked(x) };
    println!("{}", nn);

    // Pathological case: wrapping NaN silently corrupts ordering.
    let nan_val = f64::NAN;
    let broken: NotNan<f64> = unsafe { NotNan::new_unchecked(nan_val) };
    let _ = broken; // any comparison from here is UB
}
