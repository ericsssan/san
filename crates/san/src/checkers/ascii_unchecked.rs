/// Detects calls to unsafe ASCII conversion functions:
/// `ascii::Char::from_u8_unchecked`, `ascii::Char::digit_unchecked`,
/// `char::as_ascii_unchecked`, `str::as_ascii_unchecked`,
/// `u8::as_ascii_unchecked`, `[u8]::as_ascii_unchecked`, and `[u8; N]::as_ascii_unchecked`.
/// (Nightly feature `ascii_char`.)
///
/// These functions convert bytes, chars, or string slices into `ascii::Char`
/// or `&[ascii::Char]` without validating that the input is valid ASCII.
///
/// Safety requirements:
///
/// `ascii::Char::from_u8_unchecked(b)`:
///   • `b` must be < 128 (a valid ASCII byte); values >= 128 are not ASCII
///     and produce an `ascii::Char` with an invalid bit pattern (UB)
///
/// `ascii::Char::digit_unchecked(d)`:
///   • `d` must be in 0..=9; any other value produces an invalid `ascii::Char`
///
/// `char::as_ascii_unchecked()`:
///   • The `char` must be ASCII (code point < 128); non-ASCII chars have no
///     `ascii::Char` representation and this call is UB for them
///
/// `str::as_ascii_unchecked()`:
///   • Every byte in the string must be valid ASCII (< 128); a single
///     non-ASCII byte is UB; use `str::as_ascii()` which returns `Option`
///
/// The safe alternatives are `ascii::Char::from_u8`, `char::as_ascii`, and
/// `str::as_ascii`, all of which return `Option` and never cause UB.
///
/// Nightly: `#![feature(ascii_char)]`
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AsciiUnchecked;

impl Checker for AsciiUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("Char::from_u8_unchecked") {
                (
                    "ascii::Char::from_u8_unchecked",
                    "byte must be < 128; values >= 128 are not valid ASCII and produce \
                     an ascii::Char with an invalid bit pattern (UB); use from_u8() instead",
                )
            } else if path.ends_with("Char::digit_unchecked") {
                (
                    "ascii::Char::digit_unchecked",
                    "argument must be in 0..=9; any other value produces an invalid \
                     ascii::Char (UB); use Char::from_u8 or explicit matching instead",
                )
            } else if path.ends_with("::as_ascii_unchecked") && path.contains("str") {
                (
                    "str::as_ascii_unchecked",
                    "every byte in the string must be valid ASCII (< 128); a single \
                     non-ASCII byte is UB; use str::as_ascii() which returns Option",
                )
            } else if path.ends_with("::as_ascii_unchecked") && path.contains("char") {
                (
                    "char::as_ascii_unchecked",
                    "char must have code point < 128 (ASCII); non-ASCII chars have no \
                     ascii::Char representation — this call is UB for them; \
                     use char::as_ascii() which returns Option",
                )
            } else if path.ends_with("::as_ascii_unchecked")
                && (path.contains("slice") || path.contains("array"))
            {
                (
                    "[u8]::as_ascii_unchecked / [u8; N]::as_ascii_unchecked",
                    "every byte in the slice or array must be valid ASCII (< 128); \
                     a single byte >= 128 is UB; use as_ascii() which returns Option",
                )
            } else if path.ends_with("::as_ascii_unchecked") && path.contains("num") {
                (
                    "u8::as_ascii_unchecked",
                    "byte must be < 128 (valid ASCII); a byte >= 128 has no ascii::Char \
                     representation — this call is UB for non-ASCII bytes; \
                     use u8::as_ascii() which returns Option",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ascii_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
