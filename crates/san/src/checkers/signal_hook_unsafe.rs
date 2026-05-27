/// Detects calls to `signal_hook_registry::register`, `register_sigaction`,
/// `register_signal_unchecked`, and `register_unchecked` — unsafe signal
/// handler registration functions.
///
/// Signal handlers execute asynchronously, interrupting the program at an
/// arbitrary point (including inside memory allocators or locks). The handler
/// closure must only perform **async-signal-safe** operations:
///
///   • **Forbidden**: heap allocation (`Vec::push`, `Box::new`, `String`,
///     `HashMap::insert`), I/O via Rust's standard library (`println!`,
///     `eprintln!`, file operations), mutex locking (`Mutex::lock`),
///     thread-local storage access, panicking
///   • **Allowed**: writing to an atomic flag, writing to a pre-allocated
///     byte pipe (via raw `write(2)` syscall), storing to a fixed-size array
///
/// `register(signal, action)`:
///   • `action` is an `Fn() + Send + Sync + 'static` — closures over
///     non-atomic data produce data races since the handler may interrupt
///     any thread at any moment
///   • No more than SIG_ATOMIC_MAX handlers may be registered per signal
///
/// `register_sigaction(signal, action)`:
///   • Like `register`, but passes `&siginfo_t` to the handler — raw signal
///     info struct; must not be stored or used after the handler returns
///
/// `register_unchecked(signal, action)` / `register_signal_unchecked(signal, action)`:
///   • Additional unsafety: does not verify that `signal` is a valid signal
///     number or that registering a handler for it is safe (e.g.,
///     `SIGKILL`/`SIGSTOP` cannot be caught, and `SIGBUS`/`SIGSEGV`/`SIGFPE`
///     require careful SA_SIGINFO handling)
///
/// Safe alternatives: the high-level `signal-hook` crate wraps these APIs
/// with `Signals` and `SignalIterator`, which communicate via an internal
/// self-pipe and perform all non-async-signal-safe work outside the handler.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SignalHookUnsafe;

impl Checker for SignalHookUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.starts_with("signal_hook_registry::") {
                continue;
            }

            let (fn_name, note) = if path == "signal_hook_registry::register" {
                (
                    "signal_hook_registry::register",
                    "handler executes asynchronously inside any thread at any point; \
                     must only perform async-signal-safe operations: no heap allocation, \
                     no Rust I/O, no mutex locking, no panicking; use atomics or a \
                     self-pipe pattern to communicate with non-handler code",
                )
            } else if path == "signal_hook_registry::register_sigaction" {
                (
                    "signal_hook_registry::register_sigaction",
                    "same async-signal-safety constraints as `register`; the `&siginfo_t` \
                     passed to the handler must not be stored or used after the handler returns",
                )
            } else if path == "signal_hook_registry::register_unchecked"
                || path == "signal_hook_registry::register_signal_unchecked"
            {
                (
                    "signal_hook_registry::register_unchecked",
                    "same async-signal-safety constraints as `register`, plus: does not \
                     validate the signal number — SIGKILL/SIGSTOP cannot be caught; \
                     SIGBUS/SIGSEGV/SIGFPE require SA_SIGINFO and special handler structure",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "signal_hook_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
