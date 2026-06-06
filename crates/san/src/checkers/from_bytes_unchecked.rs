/// Detects calls to any `from_bytes_unchecked` function regardless of crate.
///
/// Any method named `from_bytes_unchecked` reinterprets a raw byte slice as a
/// typed value without validation. The caller must guarantee:
///   • The byte slice is properly aligned for the target type
///   • The bytes contain a fully-initialized, valid representation of the type
///   • The length is exactly right for the target type's layout
///
/// Violating any of these produces a reference with an invalid bit pattern —
/// immediate undefined behaviour. This pattern appears in zero-copy
/// serialization (rkyv, zerovec, zerocopy), DFA deserialization (regex-automata),
/// and any crate that maps on-disk or on-wire byte representations to types.
///
/// Safe alternatives: use the checked variant (typically returns `Result` or
/// `Option`) which validates alignment and layout before constructing the value.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct FromBytesUnchecked;

impl Checker for FromBytesUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::from_bytes_unchecked")
                && !path.ends_with("::from_slice_unchecked")
                && !path.ends_with("::from_slice_unchecked_mut")
            {
                continue;
            }

            findings.push(Finding {
                rule_id: "from_bytes_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{path}` — bytes must be properly aligned for the target type, \
                     fully initialized, and contain a valid bit pattern; misaligned or \
                     invalid bytes are immediate UB; use the checked variant (returns \
                     Result/Option) for untrusted data"
                ),
            });
        }

        findings
    }
}
