/// Detects calls to `from_raw_fd`, `from_raw_socket`, `from_raw_handle`,
/// `borrow_raw`, and the ownership-leaking `into_raw_fd`/`into_raw_socket`/
/// `into_raw_handle`.
///
/// These functions (part of `FromRawFd`/`FromRawSocket`/`FromRawHandle` traits)
/// create an owned I/O object from a raw file descriptor/socket/handle.
/// The caller must guarantee:
///   • The descriptor is a valid, open descriptor of the appropriate type
///   • Ownership is transferred — the descriptor must not be closed, duplicated,
///     or passed to another owner after this call
///   • Double-close: if the original owner (e.g. OwnedFd, UnixStream) still
///     exists and closes the fd on drop, the resulting object will operate on
///     an already-closed or reallocated descriptor
///   • On POSIX: use `OwnedFd::from_raw_fd` (preferably from `io_uring::OwnedFd`
///     or `rustix`) to model ownership correctly
///
/// Flow suppression: `from_raw_fd(x)` where `x` was produced by a preceding
/// `into_raw_fd()` call is the canonical safe transfer pattern and is suppressed.
/// Flow escalation: `from_raw_fd(x)` where `x` was already consumed by a prior
/// `from_raw_fd` on any reaching path is double-ownership (Error).
///
/// I/O safety pattern: always pair `into_raw_fd` with `from_raw_fd` and ensure
/// exactly one owner of each file descriptor at any point.
///
/// RustSec: RUSTSEC-2025-0051 (xcb), RUSTSEC-2019-0037 (pnet).
use crate::analysis::transfer::first_arg_local;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RawFd;

impl Checker for RawFd {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let span = terminator.source_info.span;
            if span.from_expansion() {
                continue;
            }

            // ── from_raw_* family: may suppress (transfer) or escalate (double-own) ──
            let is_from_call = path.ends_with("::from_raw_fd")
                || path.ends_with("::from_raw_socket")
                || path.ends_with("::from_raw_handle")
                || path.ends_with("::from_raw_handle_or_invalid")
                || (path.ends_with("::borrow_raw")
                    && (path.contains("BorrowedFd") || path.contains("BorrowedSocket")));

            if is_from_call {
                let fn_name = if path.ends_with("::from_raw_fd") {
                    "from_raw_fd"
                } else if path.ends_with("::from_raw_socket") {
                    "from_raw_socket"
                } else if path.ends_with("::from_raw_handle")
                    || path.ends_with("::from_raw_handle_or_invalid")
                {
                    "from_raw_handle"
                } else {
                    "borrow_raw"
                };

                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    if let Some(arg_local) = first_arg_local(args) {
                        if state.fd_was_transferred(arg_local) {
                            // into_raw_fd → from_raw_fd: canonical transfer pattern; safe.
                            continue;
                        }
                        if state.fd_is_consumed(arg_local) {
                            findings.push(Finding {
                                rule_id: "raw_fd",
                                severity: Severity::Error,
                                span,
                                message: format!(
                                    "double-ownership: `{fn_name}` on an fd integer already passed \
                                     to `from_raw_fd` — both Rust objects will close the same \
                                     descriptor on drop; use `dup(2)` if two independent owners \
                                     are intended"
                                ),
                            });
                            continue;
                        }
                    }
                }

                let note = match fn_name {
                    "from_raw_fd" =>
                        "descriptor must be valid and uniquely owned; \
                         double-close UB if another owner closes the same descriptor; \
                         use OwnedFd and `from_raw_fd` via rustix/io_uring for correct I/O safety",
                    "from_raw_socket" =>
                        "socket must be valid and uniquely owned; \
                         double-close UB if another owner closes the same socket",
                    "from_raw_handle" =>
                        "handle must be valid and uniquely owned; \
                         double-close UB if another owner closes the same handle",
                    _ =>
                        "fd/socket must remain valid and open for the entire lifetime of the \
                         returned BorrowedFd/BorrowedSocket; using an invalid descriptor is UB",
                };
                findings.push(Finding {
                    rule_id: "raw_fd",
                    severity: Severity::Warning,
                    span,
                    message: format!("`{fn_name}` — {note}"),
                });
                continue;
            }

            // ── into_raw_* family: always flag (ownership leaked to raw integer) ──
            let (fn_name, note) = if path.ends_with("::into_raw_fd") {
                (
                    "into_raw_fd",
                    "leaks the file descriptor — caller must close it exactly once \
                     (e.g. via OwnedFd::from_raw_fd); forgetting to close causes an \
                     fd leak; closing twice (via another owner) causes use-after-close",
                )
            } else if path.ends_with("::into_raw_socket") {
                (
                    "into_raw_socket",
                    "leaks the socket — caller must close it exactly once; \
                     double-close or forgetting to close are both bugs",
                )
            } else if path.ends_with("::into_raw_handle") {
                (
                    "into_raw_handle",
                    "leaks the Windows HANDLE — caller must close it exactly once \
                     via CloseHandle; double-close or forgetting to close are both bugs",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "raw_fd",
                severity: Severity::Warning,
                span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
