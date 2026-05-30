/// Detects direct calls to `CloneToUninit::clone_to_uninit` (stable since Rust 1.81).
///
/// `clone_to_uninit(src, dst)` clones `src` into the uninitialized memory at `dst`.
/// The caller must guarantee:
///   • `dst` is non-null and valid for writes of `size_of_val(src)` bytes
///   • `dst` is properly aligned for the concrete type of `src`
///   • For DSTs (e.g., `[T]`, `str`, `dyn Trait`): the metadata embedded in `dst`
///     must match `src`'s metadata exactly
///   • The old value at `dst` must NOT be dropped — it was uninitialized
///   • If the clone panics, `dst` may be in a partially-initialized state;
///     the caller must not assume it is either initialized or uninitialized
///
/// After a successful call, `dst` holds an owned clone of `src` that the caller
/// is responsible for dropping exactly once.
///
/// Common bugs: writing to already-initialized memory (leaking the old value),
/// incorrect size calculation for DSTs, failing to account for panic-safety
/// (partially-initialized dst is UB if further used after an earlier panic).
///
/// Stable since Rust 1.81.0.
use crate::analysis::state::FreedKind;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CloneToUninitCall;

impl Checker for CloneToUninitCall {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::clone_to_uninit") {
                continue;
            }

            // clone_to_uninit(&self, dst: *mut u8) — dst is args[1].
            let dst_local = args.get(1).and_then(|a| match &a.node {
                Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                _ => None,
            });

            if let (Some(state), Some(dst)) = (flow.state_before_terminator(tcx, body, bb), dst_local) {
                match state.freed_kind(dst) {
                    FreedKind::Definite => {
                        findings.push(uaf_finding(terminator.source_info.span, "write", false));
                        continue;
                    }
                    FreedKind::Potential => {
                        findings.push(uaf_finding(terminator.source_info.span, "write", true));
                        continue;
                    }
                    FreedKind::NotFreed => {}
                }
                // Suppress audit noise for explicitly managed raw memory.
                if state.ptr_is_raw_owned(dst) {
                    continue;
                }
            }

            findings.push(Finding {
                rule_id: "clone_to_uninit_call",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`clone_to_uninit` — dst must be non-null, aligned, and valid for \
                          size_of_val(src) bytes; dst must NOT hold an initialized value \
                          (the old value will not be dropped — leak if initialized); \
                          if the clone panics, dst is partially initialized — UB to use afterward"
                    .to_string(),
            });
        }

        findings
    }
}
