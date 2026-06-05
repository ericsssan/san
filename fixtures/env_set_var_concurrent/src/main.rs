//! Positive fixture: `env::set_var` called after `thread::spawn` — provably
//! concurrent environment mutation. san must emit `env_set_var` at Error
//! severity (escalated by the thread_spawned flow fact).
use std::thread;

fn main() {
    // Spawn a thread that reads the environment.
    let handle = thread::spawn(|| {
        let _ = std::env::var("MY_VAR");
    });

    // Bug: set_var after thread::spawn — the spawned thread may be reading
    // the environment concurrently; this is a data race on POSIX.
    unsafe { std::env::set_var("MY_VAR", "hello") };

    handle.join().unwrap();
}
