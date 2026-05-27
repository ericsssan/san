// Bug: signal_hook_registry::register — handler must only call async-signal-safe
// functions. The closure runs asynchronously, interrupting any thread at any point.
use std::io;

fn main() -> io::Result<()> {
    unsafe {
        let _id = signal_hook_registry::register(libc::SIGINT, || {
            // Bug: any non-async-signal-safe work here is UB under concurrent signal delivery
        })?;
        let _id2 = signal_hook_registry::register_sigaction(
            libc::SIGTERM,
            |_info: &libc::siginfo_t| {},
        )?;
    }
    Ok(())
}
