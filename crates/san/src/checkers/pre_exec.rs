/// Detects calls to `CommandExt::pre_exec` and `CommandExt::before_exec` (Unix only).
/// (`before_exec` was deprecated in 1.37; became `unsafe fn` in the Rust 2024 edition.)
///
/// `pre_exec(f)` registers a closure to run in the child process after `fork()`
/// but before `exec()`. This interval is extremely constrained:
///
/// The caller must guarantee ALL of the following in the closure body:
///   • Only async-signal-safe functions are called (see POSIX async-signal-safety).
///     This means: NO heap allocation, NO Rust standard library functions that
///     may allocate or lock, NO `println!`, NO `eprintln!`, NO `Vec::push`, etc.
///   • No mutexes acquired in the parent are taken in the child (they may be
///     locked in the parent and the child will deadlock trying to acquire them).
///   • No file descriptor tables are modified in a way that races with the parent.
///   • The closure must not return `Err` if you want `exec` to succeed; returning
///     `Err` aborts the child process with the given error.
///
/// Common bugs:
///   • Calling `eprintln!` / `println!` in the closure → deadlock on stdio locks
///   • Calling any Rust allocation function → deadlock on the global allocator mutex
///   • Calling `std::env::set_var` → lock contention with the parent's env map
///   • Calling `std::fs::*` functions that use Rust's I/O layer → allocations
///
/// The safe alternative for most use cases is `Command::current_dir`, `Command::uid`,
/// `Command::gid`, and the other `CommandExt` builder methods that are safe.
///
/// Only available on Unix (`std::os::unix::process::CommandExt`).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PreExec;

impl Checker for PreExec {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let fn_name = if path.ends_with("CommandExt::pre_exec") {
                "CommandExt::pre_exec"
            } else if path.ends_with("CommandExt::before_exec") {
                "CommandExt::before_exec (deprecated; use pre_exec)"
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "pre_exec",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — closure runs post-fork before exec; \
                     ONLY async-signal-safe operations are allowed; \
                     heap allocation, Rust I/O, and any locked resource will deadlock; \
                     use CommandExt builder methods (uid, gid, etc.) instead where possible"
                ),
            });
        }

        findings
    }
}
