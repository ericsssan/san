/// Detects calls to unsafe construction and initialization methods on
/// `triomphe::Arc`, `triomphe::ArcBorrow`, `triomphe::ThinArc`, and
/// `triomphe::UniqueArc`.
///
/// `triomphe` is a fork of `std::sync::Arc` optimized for Firefox's Servo engine,
/// widely used in high-performance Rust. Its unsafe APIs carry the same risks as
/// their `std::sync::Arc` equivalents, but target triomphe's distinct internal layout:
///
/// **`Arc::from_raw(ptr)` / `Arc::from_raw_slice(ptr)`**:
///   • `ptr` must have been produced by `Arc::into_raw` (or `Arc::as_ptr`) on a
///     live triomphe `Arc<T>` with the same type T
///   • Calling `from_raw` on a raw pointer from `std::sync::Arc::into_raw` or any
///     other allocator is UB (different allocation layout and reference-count field)
///   • Must call exactly once per `into_raw` — extra calls cause double-free,
///     missing calls cause a memory leak
///
/// **`ArcBorrow::from_ptr(ptr)`**:
///   • `ptr` must point to a live `triomphe::Arc<T>` allocation; the ArcBorrow does
///     not increment the count, so the referent must outlive the borrow
///   • Providing a pointer that is not a live Arc (or from a different Arc type)
///     is use-after-free or type confusion UB
///
/// **`ThinArc::from_raw(ptr)`**:
///   • Same ownership and layout requirements as `Arc::from_raw`, but for the
///     thin-pointer variant (header + slice in a single allocation)
///   • The pointer must have been produced by `ThinArc::into_raw`
///
/// **`UniqueArc::assume_init(arc)` / `assume_init_slice(arc)` / `assume_init_slice_with_header(arc)`**:
///   • Asserts that the memory managed by a `UniqueArc<MaybeUninit<T>>` is fully
///     initialized; calling this before all fields are written is an uninit read (UB)
///
/// Common bugs: reconstructing a triomphe Arc from a pointer produced by `std::sync::Arc`,
/// reconstructing after the last live Arc has already been dropped (use-after-free),
/// or calling `assume_init` before completing the initialization loop.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct TriompheUnchecked;

impl Checker for TriompheUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("triomphe") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::from_ptr") && path.contains("ArcBorrow") {
                (
                    "triomphe::ArcBorrow::from_ptr",
                    "ptr must point to a live triomphe::Arc<T> allocation; the borrow does NOT \
                     increment the reference count — the Arc must outlive the ArcBorrow; \
                     using a pointer from a dropped Arc or a different allocator is use-after-free",
                )
            } else if path.ends_with("::from_raw") && path.contains("ThinArc") {
                (
                    "triomphe::ThinArc::from_raw",
                    "ptr must have been produced by ThinArc::into_raw on a live ThinArc; \
                     the thin-arc layout (header + slice in one allocation) differs from \
                     std::sync::Arc — using a std Arc pointer is immediate UB",
                )
            } else if path.ends_with("::from_raw") && path.contains("Arc") {
                (
                    "triomphe::Arc::from_raw",
                    "ptr must have been produced by triomphe::Arc::into_raw on a live Arc<T>; \
                     triomphe's internal layout differs from std::sync::Arc — do not mix pointers; \
                     must call exactly once per into_raw to avoid double-free or memory leak",
                )
            } else if path.ends_with("::assume_init_slice_with_header") {
                (
                    "UniqueArc::assume_init_slice_with_header",
                    "both the header and all slice elements must be fully initialized before this \
                     call; partial initialization is UB",
                )
            } else if path.ends_with("::assume_init_slice") {
                (
                    "UniqueArc::assume_init_slice",
                    "every element of the MaybeUninit<[T]> slice must be initialized before this \
                     call; partial initialization followed by assume_init_slice is UB",
                )
            } else if path.ends_with("::assume_init") {
                (
                    "UniqueArc::assume_init",
                    "all bytes of the MaybeUninit<T> must be written before calling assume_init; \
                     reading from any uninitialized field after this call is UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "triomphe_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
