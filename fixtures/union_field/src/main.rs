union Bits {
    i: i32,
    f: f32,
    bytes: [u8; 4],
}

fn main() {
    // Bug: union field write — stored bytes may be reinterpreted through a different field.
    let u = Bits { i: -1 };

    // Bug: union field read — verify stored bytes are valid for the accessed field type.
    let _f: f32 = unsafe { u.f };
    let _b: [u8; 4] = unsafe { u.bytes };
}
