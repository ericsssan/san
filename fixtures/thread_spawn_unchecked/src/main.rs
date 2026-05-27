use std::thread;

fn main() {
    let data = vec![1i32, 2, 3];
    // Bug: spawn_unchecked — borrowed data must outlive the thread; no 'static guarantee.
    let handle = unsafe {
        thread::Builder::new()
            .spawn_unchecked(|| {
                let _sum: i32 = data.iter().sum();
            })
            .unwrap()
    };
    handle.join().unwrap();
}
