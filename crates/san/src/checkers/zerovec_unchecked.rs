/// Detects unsafe construction of ICU4X zero-copy vector types that bypass
/// byte-layout validation.
///
/// **`zerovec` unchecked constructors**:
///   • `ZeroVec::from_bytes_unchecked(bytes)` — constructs a borrowed `ZeroVec<T>`
///     from raw bytes without verifying byte-order or alignment; if the bytes do not
///     represent valid little-endian `T` values the resulting vector is corrupt (UB)
///   • `ZeroSlice::from_bytes_unchecked(bytes)` — same hazard for the slice form;
///     all slice indexing and iteration will produce garbage or UB values
///
/// **`potential_utf` unchecked conversion**:
///   • `PotentialCodePoint::to_char_unchecked()` — converts a raw u32-backed code-point
///     without checking that the value is a valid Unicode scalar; values outside
///     U+0000–U+10FFFF or surrogates (U+D800–U+DFFF) are not valid `char` values in
///     Rust, producing immediate UB (Rust guarantees `char` is always a valid scalar)
///
/// Safe alternatives:
///   • `ZeroVec::parse_bytes(bytes)` / `ZeroSlice::parse_bytes(bytes)` — validate
///     alignment and byte count, returning `Result`
///   • `PotentialCodePoint::to_char()` — returns `Option<char>`, `None` for surrogates
///     and out-of-range values
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

            let (fn_name, note) = if path.ends_with("::from_bytes_unchecked")
                && (path.contains("ZeroVec") || path.contains("ZeroSlice"))
            {
                let ty = if path.contains("ZeroSlice") { "ZeroSlice" } else { "ZeroVec" };
                (
                    if ty == "ZeroSlice" { "ZeroSlice::from_bytes_unchecked" } else { "ZeroVec::from_bytes_unchecked" },
                    "bytes must be a valid little-endian encoding of T elements; misaligned or \
                     corrupt bytes produce an invalid ZeroVec/ZeroSlice — all subsequent reads \
                     and iterations yield garbage or UB; use parse_bytes() → Result instead",
                )
            } else if path.ends_with("::to_char_unchecked")
                && path.contains("PotentialCodePoint")
            {
                (
                    "PotentialCodePoint::to_char_unchecked",
                    "the raw u32 value must be a valid Unicode scalar (U+0000–U+10FFFF, \
                     excluding surrogates U+D800–U+DFFF); an invalid value produces an \
                     invalid char, which is immediate UB in Rust; use to_char() → Option<char>",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "zerovec_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
