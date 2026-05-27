fn classify(x: u8) -> &'static str {
    match x {
        0..=127 => "ascii",
        128..=255 => "high",
        // Bug: hint::unreachable_unchecked — if this path is reached, behaviour is undefined.
        #[allow(unreachable_patterns)]
        _ => unsafe { std::hint::unreachable_unchecked() },
    }
}

fn main() {
    let _ = classify(65);
}
