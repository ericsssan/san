/// Detects calls to `f32::to_int_unchecked` and `f64::to_int_unchecked`.
///
/// `to_int_unchecked::<T>(self)` converts a floating-point value to integer T
/// without checking that the value is representable. The caller must guarantee:
///   • The value is finite (not NaN and not infinite); NaN is never representable
///     as an integer and its cast is immediate UB
///   • The value, when truncated toward zero, fits within T's range; e.g.,
///     casting 1e20_f32 to u32 (max ~4e9) is UB — the result is unspecified
///     and the compiler may generate arbitrary code
///   • On x86 with SSE2: out-of-range casts produce the "integer indefinite"
///     value (0x80000000 for i32) — this is implementation-defined, NOT
///     a guaranteed safe fallback
///
/// Common bugs: not checking for NaN before the cast (e.g., from user input
/// or trigonometric computation), not checking the magnitude against
/// T::MAX before casting large floats.
///
/// The safe alternatives are `as` casts (which saturate or wrap depending on
/// the type and edition) or explicit range checks before calling this function.
///
/// RustSec: float-to-int UB appears in physics engines, audio signal processing,
/// and any numerical code that casts computed floating-point results to indices
/// or counts without range validation.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct FloatToIntUnchecked;

impl Checker for FloatToIntUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("to_int_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "float_to_int_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`to_int_unchecked` — value must be finite (not NaN, not infinite) and \
                          fit within the target integer type's range when truncated toward zero; \
                          NaN and out-of-range values are immediate UB"
                    .to_string(),
            });
        }

        findings
    }
}
