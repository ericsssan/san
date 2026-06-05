/// Detects calls to `char::from_u32_unchecked`.
///
/// `char::from_u32_unchecked(u)` creates a `char` from a `u32` without validating
/// that `u` is a valid Unicode scalar value. The caller must guarantee:
///   • `u` is in the range 0x0000..=0xD7FF or 0xE000..=0x10FFFF
///   • Values in 0xD800..=0xDFFF are surrogates — creating a char from them is UB
///   • Values above 0x10FFFF are not valid Unicode — creating a char from them is UB
///
/// Creating an invalid `char` can lead to:
///   • Corruption of UTF-8 strings when the char is formatted or encoded
///   • Incorrect behavior in Unicode algorithms (classification, case-folding, etc.)
///   • Undefined behavior if passed to safe Rust functions expecting valid chars
///
/// Use `char::from_u32` (returns `Option<char>`) as the safe alternative.
///
/// Seen in: text processing libraries, parser combinators, and any code that
/// maps integer values to characters (e.g. rayon's parallel iterator code).
use crate::analysis::transfer::first_arg_local;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CharFromU32Unchecked;

impl Checker for CharFromU32Unchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            // Actual path: `std::char::methods::<impl char>::from_u32_unchecked`
            if !path.ends_with("::from_u32_unchecked") || !path.contains("char") {
                continue;
            }

            // Suppress when the u32 is proven to be a valid Unicode scalar on all
            // reaching paths: in 0x0000..=0xD7FF or 0xE000..=0x10FFFF.
            // The two sequential SwitchInt guards (e.g. `u >= 0xE000 && u <= 0x10FFFF`)
            // accumulate const_lower/const_upper so local_is_valid_scalar can verify.
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(arg) = first_arg_local(args) {
                    if state.local_is_valid_scalar(arg) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "char_from_u32_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`char::from_u32_unchecked` — value must be a valid Unicode scalar: \
                          0x0..=0xD7FF or 0xE000..=0x10FFFF; surrogates (0xD800..=0xDFFF) and \
                          values > 0x10FFFF are UB; use `char::from_u32` (returns Option) instead"
                    .to_string(),
            });
        }

        findings
    }
}
