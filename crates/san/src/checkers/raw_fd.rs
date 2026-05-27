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
/// I/O safety pattern: always pair `into_raw_fd` with `from_raw_fd` and ensure
/// exactly one owner of each file descriptor at any point.
///
/// RustSec: RUSTSEC-2025-0051 (xcb), RUSTSEC-2019-0037 (pnet).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RawFd;

impl Checker for RawFd {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, note) = if path.ends_with("::from_raw_fd") {
                (
                    "from_raw_fd",
                    "descriptor must be valid and uniquely owned; \
                     double-close UB if another owner closes the same descriptor; \
                     use OwnedFd and `from_raw_fd` via rustix/io_uring for correct I/O safety",
                )
            } else if path.ends_with("::from_raw_socket") {
                (
                    "from_raw_socket",
                    "socket must be valid and uniquely owned; \
                     double-close UB if another owner closes the same socket",
                )
            } else if path.ends_with("::from_raw_handle")
                || path.ends_with("::from_raw_handle_or_invalid")
            {
                (
                    "from_raw_handle",
                    "handle must be valid and uniquely owned; \
                     double-close UB if another owner closes the same handle",
                )
            } else if path.ends_with("::borrow_raw")
                && (path.contains("BorrowedFd") || path.contains("BorrowedSocket"))
            {
                (
                    "borrow_raw",
                    "fd/socket must remain valid and open for the entire lifetime of the \
                     returned BorrowedFd/BorrowedSocket; using an invalid descriptor is UB",
                )
            } else if path.ends_with("::into_raw_fd") {
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
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
