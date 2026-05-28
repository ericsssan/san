/// Detects calls to `CString::as_ptr`, `CString::into_raw`, and
/// `CString::from_vec_unchecked`.
///
/// `CString::as_ptr()` returns a `*const c_char` that borrows the CString's
/// internal allocation. The pointer is valid only as long as the CString is
/// alive. A classic and very easy bug:
///
/// ```rust
/// // WRONG: CString is dropped at the semicolon — ptr is dangling
/// let ptr = CString::new("hello").unwrap().as_ptr();
/// libc_fn(ptr); // use-after-free
/// ```
///
/// The correct pattern is to keep the CString alive for the duration of use:
/// ```rust
/// let s = CString::new("hello").unwrap();
/// libc_fn(s.as_ptr()); // s is still alive here
/// ```
///
/// `CString::into_raw()` deliberately leaks the CString and transfers ownership
/// of the pointer to the caller. The memory must be freed exactly once via
/// `CString::from_raw` with the same CString, or manually via the same allocator.
///
/// RustSec: RUSTSEC-2025-0022 (openssl — `Md::fetch` use-after-free due to
/// `CString::drop`'s behavior with temporary values).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CStringAsPtr;

impl Checker for CStringAsPtr {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("CString::as_ptr") {
                (
                    "CString::as_ptr",
                    "pointer is only valid while the CString is alive; if called on a \
                     temporary (`CString::new(...).unwrap().as_ptr()`), the CString is \
                     dropped at the semicolon and the pointer is immediately dangling",
                )
            } else if path.ends_with("CString::into_raw") {
                (
                    "CString::into_raw",
                    "leaks the CString — memory must be freed via `CString::from_raw` with \
                     the same pointer exactly once; double-free or leak if misused",
                )
            } else if path.ends_with("CString::from_vec_unchecked") {
                (
                    "CString::from_vec_unchecked",
                    "bytes must not contain interior nul bytes; if they do, C functions \
                     receiving the pointer will stop at the first nul, causing truncation \
                     or security-relevant null-byte injection (e.g. in path construction); \
                     use `CString::new` for the checked version",
                )
            } else if path.ends_with("CString::from_vec_with_nul_unchecked") {
                (
                    "CString::from_vec_with_nul_unchecked",
                    "bytes must end with exactly one nul byte and contain no interior nuls; \
                     violating either condition causes C callers to truncate or overflow; \
                     use `CString::from_vec_with_nul` for the checked version (returns Result)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "cstring_as_ptr",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
