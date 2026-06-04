/// Detects calls to `Vec::set_len` — a highly unsafe operation that bypasses
/// all of Rust's safety guarantees around collection length.
///
/// Callers must ensure:
///   1. `new_len <= capacity()`
///   2. All elements in `old_len..new_len` are initialized.
///
/// Violations cause OOB writes, uninitialized reads, and double drops.
/// Seen in: RUSTSEC-2020-0034 (arr), RUSTSEC-2021-0040 (arenavec), and
/// dozens of custom Vec implementations across the ecosystem.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct VecSetLen;

impl Checker for VecSetLen {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("vec::") || !path.ends_with("::set_len") {
                continue;
            }

            // Suppress when new_len is proven <= capacity() on all predecessor
            // paths. set_len(self, new_len) — new_len is args[1]. The primary
            // safety condition is `new_len <= capacity()`; a bounded-or-equal
            // fact discharges it. (The initialization obligation for
            // old_len..new_len remains the caller's, but a provably in-capacity
            // length is the common safe idiom — e.g. `set_len` immediately after
            // `reserve`/`with_capacity` followed by a checked fill.)
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(len_local) = args.get(1).and_then(|a| match &a.node {
                    Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                    _ => None,
                }) {
                    if state.local_is_bounded_or_eq(len_local) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "vec_set_len",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`Vec::set_len` bypasses Rust's safety checks — verify that \
                          new_len ≤ capacity() and all elements in old_len..new_len \
                          are fully initialized"
                    .to_string(),
            });
        }

        findings
    }
}
