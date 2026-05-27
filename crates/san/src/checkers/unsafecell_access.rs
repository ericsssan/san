/// Detects calls to `UnsafeCell::as_ref_unchecked`, `UnsafeCell::as_mut_unchecked`,
/// and `UnsafeCell::replace` (nightly, feature `unsafe_cell_access`, tracking issue #136327).
///
/// These methods yield Rust references or swap the inner value directly:
///   • `as_ref_unchecked(&self) -> &T` — no mutable reference to the interior
///     may exist simultaneously, and no concurrent mutation may occur
///   • `as_mut_unchecked(&self) -> &mut T` — exclusive access to the interior
///     is required; no other reference (shared or mutable) may exist simultaneously,
///     even through other `UnsafeCell::get` paths
///   • `replace(&self, value: T) -> T` — swaps the inner value and returns the old
///     one; no other reference to the interior may exist while this runs;
///     concurrent use is UB
///
/// The critical difference from `UnsafeCell::get()` (which returns `*mut T`):
/// these return Rust references, so the compiler emits noalias annotations assuming
/// no aliasing. Violating the aliasing rules is therefore more likely to be
/// miscompiled silently rather than caught at runtime.
///
/// Common bugs: calling `as_mut_unchecked` while any other reference to the
/// same cell is live, using `as_ref_unchecked` concurrently with a write,
/// calling `replace` without exclusive access.
///
/// Nightly: requires `#![feature(unsafe_cell_access)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnsafeCellAccess;

impl Checker for UnsafeCellAccess {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("UnsafeCell") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::as_ref_unchecked") {
                (
                    "UnsafeCell::as_ref_unchecked",
                    "no mutable reference to the interior may exist simultaneously; \
                     no concurrent mutation may occur",
                )
            } else if path.ends_with("::as_mut_unchecked") {
                (
                    "UnsafeCell::as_mut_unchecked",
                    "exclusive access required — no other reference (shared or mutable) \
                     may exist simultaneously; the noalias annotation on the returned \
                     &mut T enables miscompilation if aliased",
                )
            } else if path.ends_with("::replace") && path.contains("UnsafeCell") {
                (
                    "UnsafeCell::replace",
                    "swaps the inner value in place; no other reference to the interior \
                     may exist while this runs; concurrent access is UB \
                     (nightly feature `unsafe_cell_access`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "unsafecell_access",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
