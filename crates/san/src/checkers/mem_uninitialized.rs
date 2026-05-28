/// Detects any call to the deprecated `mem::uninitialized()`.
///
/// `mem::uninitialized()` produces immediate undefined behaviour for most types
/// (bools, references, enums, integers on some targets). It was deprecated in
/// Rust 1.39 in favour of `MaybeUninit`. Any remaining call site is a bug.
/// Real-world CVEs: RUSTSEC-2021-0032 (byte_struct), RUSTSEC-2021-0040 (arenavec).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MemUninitialized;

impl Checker for MemUninitialized {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("mem::uninitialized") {
                continue;
            }

            findings.push(Finding {
                rule_id: "mem_uninitialized",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message:
                    "`mem::uninitialized()` is immediately undefined behaviour for most types. \
                     Replace with `MaybeUninit::uninit()` and explicit initialization."
                        .to_string(),
            });
        }

        findings
    }
}
