/// Detects calls to `Option::unwrap_unchecked`, `Result::unwrap_unchecked`,
/// and `Result::unwrap_err_unchecked`.
///
/// These skip the None/Err check and assume the value is in the expected variant.
/// The caller must guarantee:
///   • `Option::unwrap_unchecked`: the option is `Some` — calling on `None` is UB
///   • `Result::unwrap_unchecked`: the result is `Ok` — calling on `Err` is UB
///   • `Result::unwrap_err_unchecked`: the result is `Err` — calling on `Ok` is UB
///
/// Unlike panicking `unwrap()`, these produce undefined behaviour on violation.
/// The compiler may assume the check is always satisfied and miscompile
/// surrounding code (e.g. eliminate branches that would only run on None/Err).
///
/// Common bugs: optimistically removing the check for performance, then
/// encountering the case in production (unexpected None from an API, transient
/// I/O error in a Result).
///
/// The safe alternative is `unwrap()` or `expect()` which panic on failure
/// rather than causing undefined behaviour.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnwrapUnchecked;

impl Checker for UnwrapUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("Option::<T>::unwrap_unchecked")
                || path.ends_with("Option::unwrap_unchecked")
            {
                (
                    "Option::unwrap_unchecked",
                    "UB if called on None; use unwrap() or expect() if the None case \
                     is not provably impossible",
                )
            } else if path.ends_with("Result::<T, E>::unwrap_unchecked")
                || path.ends_with("Result::unwrap_unchecked")
            {
                (
                    "Result::unwrap_unchecked",
                    "UB if called on Err; use unwrap() or expect() if Err is not \
                     provably impossible",
                )
            } else if path.ends_with("Result::<T, E>::unwrap_err_unchecked")
                || path.ends_with("Result::unwrap_err_unchecked")
            {
                (
                    "Result::unwrap_err_unchecked",
                    "UB if called on Ok; use unwrap_err() if Ok is not provably impossible",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "unwrap_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
