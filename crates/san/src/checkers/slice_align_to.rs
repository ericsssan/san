/// Detects calls to `slice::align_to` and `slice::align_to_mut`.
///
/// `align_to::<U>()` splits a slice of T into a prefix, a middle slice of U,
/// and a suffix. The middle portion is a **transmutation** of the underlying
/// bytes to type U. The caller must guarantee:
///   • Every bit pattern produced by reinterpreting the T bytes is a valid
///     instance of U — if U has validity constraints (e.g. bool, char, NonNull,
///     enum discriminants) this is not automatically satisfied by alignment alone
///   • No other references to the same memory are mutated through a different alias
///     during the lifetime of the returned slices (especially for `align_to_mut`)
///
/// Alignment itself is handled by the function (that's the point), but the
/// **type validity** is entirely the caller's responsibility.
///
/// Common bugs: reinterpreting `u8` as a type with restricted bit patterns
/// (bool, char, enum), using the middle slice while still holding mutable
/// references through the prefix/suffix, or mixing `align_to_mut` with
/// concurrent readers.
///
/// RustSec: RUSTSEC-2024-0424 (libafl), RUSTSEC-2021-0121 (crypto2).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceAlignTo;

impl Checker for SliceAlignTo {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::align_to_mut")
                && path.contains("slice")
            {
                (
                    "align_to_mut",
                    "the middle slice is a mutable transmutation of the source bytes to \
                     the target type; every bit pattern must be a valid instance of the \
                     target type (bool/char/enum/NonNull have restricted bit patterns); \
                     no concurrent mutable aliases through prefix/suffix are permitted",
                )
            } else if path.ends_with("::align_to") && path.contains("slice") {
                (
                    "align_to",
                    "the middle slice is a transmutation of the source bytes to the target \
                     type; every bit pattern must be a valid instance of the target type \
                     (bool/char/enum/NonNull have restricted bit patterns); alignment is \
                     handled but type validity is not checked",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "slice_align_to",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
