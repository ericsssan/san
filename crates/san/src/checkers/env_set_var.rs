/// Detects calls to `std::env::set_var` and `std::env::remove_var`
/// (now `unsafe fn` in Rust nightly as of 2024).
///
/// Setting or removing environment variables is not thread-safe on most
/// POSIX operating systems: `setenv(3)` / `unsetenv(3)` / `putenv(3)` are
/// not guaranteed to be re-entrant, and most libc implementations hold a
/// non-recursive lock that is separate from Rust's standard library. As a
/// result:
///
///   • Calling `set_var` or `remove_var` concurrently with any other thread
///     that reads the environment (e.g. via `env::var`, `std::process::Command`,
///     `getenv(3)` from C code, or many third-party crates) is a data race
///     on the underlying C string table — undefined behaviour on POSIX
///   • On glibc, the implementation uses a global linked-list with a non-
///     recursive lock; re-entrant access from signal handlers (which may
///     call `getenv`) can deadlock
///   • On macOS, `setenv` is documented as "not safe to call in multi-
///     threaded programs"
///   • After `fork(2)`, the child's environment is a copy — but using
///     `set_var` in a forked child that also runs Rust std (e.g. via
///     `std::process::Command`) can race with the parent's allocator or
///     with the child's signal-handler-registered code
///
/// **`remove_var`** carries the same hazards: it modifies the same global
/// string table.
///
/// Safe alternatives:
///   • Set the environment **before** spawning any threads (in `main`, before
///     `ThreadBuilder::spawn` / `thread::spawn` calls)
///   • Use a synchronization-aware environment abstraction from a crate
///   • Prefer `Command::env`/`Command::env_remove` to set vars for a child
///     process without mutating the current process's environment
///
/// The `unsafe` requirement was added in nightly Rust (tracking issue #27970).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct EnvSetVar;

impl Checker for EnvSetVar {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("env::set_var") {
                (
                    "env::set_var",
                    "not thread-safe on POSIX: concurrent reads of the environment \
                     (from any thread, signal handler, or C code) are a data race; \
                     only safe before the first `thread::spawn` call; \
                     prefer `Command::env` to set vars for child processes",
                )
            } else if path.ends_with("env::remove_var") {
                (
                    "env::remove_var",
                    "not thread-safe on POSIX: concurrent reads of the environment \
                     (from any thread, signal handler, or C code) are a data race; \
                     only safe before the first `thread::spawn` call; \
                     prefer `Command::env_remove` to remove vars for child processes",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "env_set_var",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
