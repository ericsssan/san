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
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CharFromU32Unchecked;

impl Checker for CharFromU32Unchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            // Actual path: `std::char::methods::<impl char>::from_u32_unchecked`
            if !path.ends_with("::from_u32_unchecked") || !path.contains("char") {
                continue;
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
