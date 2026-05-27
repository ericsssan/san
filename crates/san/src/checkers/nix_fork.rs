/// Detects calls to `nix::unistd::fork`, `nix::sys::signal::signal`,
/// `nix::sys::signal::sigaction`, and `nix::sys::signal::SigSet::from_sigset_t_unchecked`.
///
/// **`fork()`** duplicates the calling process. Every `fork()` call is unsafe
/// because:
///   • In the child, only **async-signal-safe** functions may be called between
///     `fork()` and `exec*()`; calling any function that acquires a mutex (including
///     `malloc`, `printf`, `pthread_*`, etc.) is undefined behaviour if that mutex
///     was held by another thread at the time of the fork
///   • In a multi-threaded process, forking without immediately exec-ing is almost
///     always a bug: the child inherits only the calling thread, leaving all other
///     threads' work incomplete and their mutexes in unknown states (fork-safety bug)
///   • File descriptors, memory-mapped regions, and locks are inherited without
///     duplication; misuse causes double-close, double-free, or resource leaks
///
/// **`signal()` / `sigaction()`** install custom signal handlers. Signal handlers
/// run asynchronously in an interrupted context — only async-signal-safe operations
/// are legal inside a handler. Handlers that call `malloc`, acquire locks, or write
/// to stdio are UB.
///
/// **`SigSet::from_sigset_t_unchecked(sigset)`** constructs a `SigSet` from a raw
/// `libc::sigset_t` without validating its contents; an uninitialized or corrupted
/// sigset can cause subsequent signal operations to manipulate wrong signal masks.
///
/// Safe alternatives: use `std::process::Command::spawn()` instead of fork/exec;
/// use `signal_hook` crate for safe signal handling (writes to a pipe or atomics).
///
/// References: POSIX async-signal-safe function list, pthread_atfork(3).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NixFork;

impl Checker for NixFork {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("nix") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("unistd::fork") {
                (
                    "nix::unistd::fork",
                    "child process may only call async-signal-safe functions before exec(); \
                     forking a multi-threaded process without immediate exec is almost always UB \
                     (inherited mutexes may be locked by dead threads); use std::process::Command \
                     or the fork-exec idiom with careful child-side code review",
                )
            } else if path.ends_with("signal::signal") && path.contains("sys") {
                (
                    "nix::sys::signal::signal",
                    "signal handler runs asynchronously in an interrupted context; only \
                     async-signal-safe operations are legal inside the handler — calling malloc, \
                     locking a mutex, or using stdio is UB; prefer signal_hook crate for safe \
                     signal handling via pipe or atomic writes",
                )
            } else if path.ends_with("signal::sigaction") && path.contains("sys") {
                (
                    "nix::sys::signal::sigaction",
                    "installs a signal handler via sigaction(2); handler must be async-signal-safe; \
                     calling async-signal-unsafe functions inside the handler is UB; also unsafe \
                     because the previous SigAction returned may be invalid if not originally set \
                     by sigaction",
                )
            } else if path.ends_with("::from_sigset_t_unchecked") {
                (
                    "SigSet::from_sigset_t_unchecked",
                    "constructs a SigSet from a raw libc::sigset_t without validation; an \
                     uninitialized or corrupted sigset causes subsequent signal mask operations \
                     (sigprocmask, pthread_sigmask) to manipulate wrong or undefined signal masks",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "nix_fork",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
