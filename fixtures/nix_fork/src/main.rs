use nix::libc;
use nix::sys::signal::{self, Signal, SigAction, SigHandler, SaFlags, SigSet};
use nix::unistd::{fork, ForkResult};

extern "C" fn handle_sigint(_: libc::c_int) {
    // Bug: handler calls async-signal-unsafe code.
    let _ = std::io::Write::write(&mut std::io::stderr(), b"caught\n");
}

fn main() {
    // Bug: sigaction — handler must be async-signal-safe.
    let handler = SigHandler::Handler(handle_sigint);
    let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    unsafe { signal::sigaction(Signal::SIGINT, &action).unwrap() };

    // Bug: fork — multi-threaded programs must not fork without exec.
    match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => {
            println!("parent: child pid = {child}");
            nix::sys::wait::waitpid(child, None).unwrap();
        }
        ForkResult::Child => {
            println!("child");
            std::process::exit(0);
        }
    }
}
