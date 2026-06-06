/// Detects unsafe Unicode scalar construction in ICU4X zero-copy types.
///
/// **`potential_utf` unchecked conversion**:
///   • `PotentialCodePoint::to_char_unchecked()` — converts a raw u32-backed
///     code-point without checking that the value is a valid Unicode scalar;
///     values outside U+0000-U+10FFFF or surrogates (U+D800-U+DFFF) are not
///     valid `char` values in Rust, producing immediate UB (Rust guarantees
///     `char` is always a valid scalar)
///
/// Note: `ZeroVec::from_bytes_unchecked` and `ZeroSlice::from_bytes_unchecked`
/// are covered by the general `from_bytes_unchecked` checker.
///
/// Safe alternatives:
///   • `ZeroVec::parse_bytes(bytes)` / `ZeroSlice::parse_bytes(bytes)` -- validate
///     alignment and byte count, returning `Result`
///   • `PotentialCodePoint::to_char()` -- returns `Option<char>`, `None` for
///     surrogates and out-of-range values
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ZerovecUnchecked;

impl Checker for ZerovecUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if path.ends_with("::to_char_unchecked") && path.contains("PotentialCodePoint") {
                findings.push(Finding {
                    rule_id: "zerovec_unchecked",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`PotentialCodePoint::to_char_unchecked` -- the raw u32 value must \
                              be a valid Unicode scalar (U+0000-U+10FFFF, excluding surrogates \
                              U+D800-U+DFFF); an invalid value produces an invalid char, which \
                              is immediate UB in Rust; use to_char() -> Option<char>"
                        .to_string(),
                });
            }
        }

        findings
    }
}
