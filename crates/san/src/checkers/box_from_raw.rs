/// Detects calls to `Box::from_raw`, `Box::from_raw_in`, `Box::from_non_null`,
/// and `Box::from_non_null_in`.
///
/// These functions reclaim ownership of a heap allocation from a raw pointer or NonNull.
/// The caller must guarantee ALL of the following:
///   • The pointer was obtained from `Box::into_raw` / `Box::into_non_null` (or `Box::leak`)
///     for the same T
///   • The pointer is not used again after this call (use-after-free)
///   • The reconstruct function is called exactly once for this pointer (double-free)
///   • The pointer points to a valid, fully-initialized T
///   • The global allocator matches the one that produced the pointer
///   • For `from_raw_in`: the allocator `A` must match the one originally used
///   • For `from_non_null`: the NonNull must have been produced by `Box::into_non_null`
///
/// `Box::from_non_null` is the NonNull-typed analogue of `Box::from_raw`; the same
/// ownership and validity rules apply. (Nightly: feature `box_vec_non_null`.)
///
/// Common bugs: calling from_raw on a pointer that was never boxed,
/// calling it twice (double-free), or using the pointer after calling it.
///
/// RustSec: RUSTSEC-2021-0050 (containers), RUSTSEC-2021-0003 (renderdoc-sys),
/// and many FFI boundary crates that pass Box pointers across ABI boundaries.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BoxFromRaw;

impl Checker for BoxFromRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, extra) = if path.ends_with("Box::<T>::from_raw")
                || path.ends_with("Box::from_raw")
                || (path.ends_with("::from_raw") && path.contains("Box"))
            {
                ("Box::from_raw", "")
            } else if path.ends_with("Box::<T, A>::from_raw_in") || path.ends_with("Box::from_raw_in") {
                (
                    "Box::from_raw_in",
                    " and the allocator `A` must match the one that produced the pointer",
                )
            } else if path.ends_with("::from_non_null") && path.contains("Box") {
                (
                    "Box::from_non_null",
                    "; NonNull must have been produced by `Box::into_non_null` for the same T",
                )
            } else if path.ends_with("::from_non_null_in") && path.contains("Box") {
                (
                    "Box::from_non_null_in",
                    "; NonNull must have been produced by `Box::into_non_null_with_allocator` \
                     for the same T, and the allocator `A` must match \
                     (nightly feature `box_vec_non_null`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "box_from_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — pointer must come from `Box::into_raw` for the same T{extra}, \
                     must not be used again, and must be called exactly once (double-free if called twice)"
                ),
            });
        }

        findings
    }
}
