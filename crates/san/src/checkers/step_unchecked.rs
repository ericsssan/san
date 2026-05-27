/// Detects calls to `Step::forward_unchecked` and `Step::backward_unchecked`
/// (nightly: `#![feature(step_trait)]`).
///
/// `Step` is the trait underlying Rust's range iterators (`0..n`, `a..=b`).
/// The unchecked variants skip overflow checking:
///
/// `Step::forward_unchecked(start, count)`:
///   • Advances `start` by `count` steps without checking for overflow
///   • If `start + count` overflows or exceeds the type's maximum value, the
///     result is immediate UB — subsequent indexing may read out of bounds
///   • Safe alternative: `Step::forward_checked` (returns `Option`)
///
/// `Step::backward_unchecked(start, count)`:
///   • Moves `start` backward by `count` steps without checking for underflow
///   • If `start - count` underflows or goes below the type's minimum value,
///     the result is immediate UB
///   • Safe alternative: `Step::backward_checked` (returns `Option`)
///
/// Common bugs:
///   • Using `forward_unchecked` with user-supplied counts without prior bounds checks
///   • Range arithmetic on enums where not every step is a valid discriminant
///   • Off-by-one in loop bounds that lets count exceed the range of the type
///
/// Nightly: `#![feature(step_trait)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct StepUnchecked;

impl Checker for StepUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("forward_unchecked") && path.contains("Step")
            {
                (
                    "Step::forward_unchecked",
                    "start + count must not overflow the type's range; overflow is immediate UB \
                     and may cause out-of-bounds range iteration; use Step::forward_checked \
                     (returns Option) or verify the count before calling",
                )
            } else if path.ends_with("backward_unchecked") && path.contains("Step") {
                (
                    "Step::backward_unchecked",
                    "start - count must not underflow the type's minimum value; underflow is \
                     immediate UB and may cause out-of-bounds range iteration; use \
                     Step::backward_checked (returns Option) or verify the count before calling",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "step_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
