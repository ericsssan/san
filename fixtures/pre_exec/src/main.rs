#[cfg(unix)]
fn main() {
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new("echo");
    // Bug: pre_exec — closure runs post-fork before exec; only async-signal-safe ops allowed.
    unsafe {
        cmd.pre_exec(|| {
            // Doing anything non-async-signal-safe here (like printing) is UB.
            Ok(())
        });
    }
    let _ = cmd.args(["hello"]).spawn();
}

#[cfg(not(unix))]
fn main() {}
