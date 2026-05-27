/// Detects calls to `std::hint::assert_unchecked` and `std::intrinsics::assume`.
///
/// `assert_unchecked(cond)` tells the optimizer to assume `cond` is always true
/// without verifying it at runtime. This is a performance hint — the optimizer
/// may eliminate branches or generate tighter code based on this assumption.
///
/// The caller must guarantee:
///   • `cond` is ALWAYS true when execution reaches this point
///   • If `cond` is ever false, the behavior is immediately undefined —
///     the optimizer may miscompile the surrounding code (removing safety checks,
///     reordering memory accesses, generating incorrect control flow)
///
/// Unlike `assert!(cond)` which panics on failure, `assert_unchecked` with a
/// false condition causes **silent UB** — no panic, no observable error at the
/// point of violation; the bug manifests elsewhere in surprising ways.
///
/// Common bugs: using stale invariants that no longer hold after refactoring,
/// off-by-one reasoning errors, incorrect assumptions about input ranges.
///
/// Stable since Rust 1.81.0. Analogous to `__builtin_assume` in GCC/Clang.
///
/// `std::intrinsics::assume(cond)` is the underlying unsafe intrinsic; requires
/// `#![feature(core_intrinsics)]` on nightly. `hint::assert_unchecked` is the
/// stable public API that delegates to this intrinsic.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HintAssertUnchecked;

impl Checker for HintAssertUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let fn_name = if path.ends_with("hint::assert_unchecked") {
                "hint::assert_unchecked"
            } else if path.ends_with("intrinsics::assume") {
                "intrinsics::assume"
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "hint_assert_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — the condition must ALWAYS be true; \
                     if ever false, the optimizer may silently miscompile surrounding \
                     code (no panic, no error — pure UB); use `assert!` unless the \
                     invariant is provably unbreakable"
                ),
            });
        }

        findings
    }
}
