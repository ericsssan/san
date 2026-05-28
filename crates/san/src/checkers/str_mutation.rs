/// Detects calls to `str::as_bytes_mut` and `String::as_mut_vec`.
///
/// Both functions expose the raw bytes of a UTF-8 string for mutation.
/// The caller must guarantee that the bytes remain **valid UTF-8** after
/// any modification — violating this produces a `str` or `String` whose
/// contents are invalid UTF-8, which is immediately undefined behaviour
/// for any subsequent operation that relies on the UTF-8 invariant
/// (display, indexing, encoding, comparison, hashing, etc.).
///
/// `String::as_mut_vec` additionally allows changing the length and
/// capacity of the underlying `Vec<u8>`; shrinking below the actual
/// string length or writing a length larger than the allocated capacity
/// is also undefined behaviour.
///
/// Common bugs: writing arbitrary bytes without checking UTF-8 validity,
/// truncating a multi-byte codepoint leaving a partial sequence,
/// appending bytes that form invalid continuations.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct StrMutation;

impl Checker for StrMutation {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::as_bytes_mut") {
                (
                    "as_bytes_mut",
                    "all written bytes must form valid UTF-8 when the borrow ends; \
                     truncating a multi-byte codepoint or writing non-UTF-8 bytes is UB",
                )
            } else if path.ends_with("String::as_mut_vec") || path.ends_with("::as_mut_vec") {
                (
                    "as_mut_vec",
                    "the underlying Vec<u8> must contain valid UTF-8 at all times; \
                     modifying length/capacity to violate the UTF-8 invariant is UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "str_mutation",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
