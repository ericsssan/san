use std::mem::ManuallyDrop;

fn main() {
    let mut md: ManuallyDrop<String> = ManuallyDrop::new(String::from("hello"));

    // Bug: ManuallyDrop::drop — must be called exactly once.
    unsafe { ManuallyDrop::drop(&mut md) };

    let mut md2: ManuallyDrop<Vec<u8>> = ManuallyDrop::new(vec![1, 2, 3]);

    // Bug: ManuallyDrop::take — copy semantics; double-drop if both owners are dropped.
    let _val: Vec<u8> = unsafe { ManuallyDrop::take(&mut md2) };
}
