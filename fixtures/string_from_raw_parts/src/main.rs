fn main() {
    let original = String::from("hello, world");
    let mut buf = std::mem::ManuallyDrop::new(original);
    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    let cap = buf.capacity();

    // Bug: String::from_raw_parts — must verify UTF-8, correct allocator, length <= cap.
    let rebuilt = unsafe { String::from_raw_parts(ptr, len, cap) };
    println!("{}", rebuilt);
}
