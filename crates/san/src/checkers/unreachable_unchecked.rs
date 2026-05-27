/// Detects calls to `std::hint::unreachable_unchecked`.
///
/// `unreachable_unchecked()` tells the compiler that the code path is provably
/// unreachable. If the path IS reached at runtime, the behaviour is UNDEFINED —
/// the compiler may assume it never happens and miscompile surrounding code.
/// This is one of the most dangerous `unsafe` operations because:
///   • The undefined behaviour is silent — no panic, no crash on all targets
///   • LLVM may use the "unreachable" hint to eliminate safety checks elsewhere
///   • Any logic error that makes the path reachable turns into potential ACE
///
/// The safe alternative is the `unreachable!()` macro (panics at runtime).
///
/// Common bugs: match arms added after the fact, enum variants added to an
/// exhaustive pattern, incorrect assumptions about invariants that later break.
///
/// RustSec: RUSTSEC-2019-0017 (once_cell).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnreachableUnchecked;

impl Checker for UnreachableUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("hint::unreachable_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "unreachable_unchecked",
                severity: Severity::Error,
                span: terminator.source_info.span,
                message: "`hint::unreachable_unchecked` — if this path is ever reached at \
                          runtime, behaviour is undefined (no panic; LLVM may miscompile); \
                          use `unreachable!()` unless the invariant is rigorously proven"
                    .to_string(),
            });
        }

        findings
    }
}
