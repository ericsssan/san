/// Flow-sensitive ownership protocol checker.
///
/// Detects intra-procedural ownership violations that the call-site checkers
/// (`into_raw`, `box_from_raw`) cannot see:
///
/// 1. **Double-free**: `Box::from_raw` (or equivalent) called on a pointer that was
///    already reconstituted on the current control-flow path.
/// 2. **Conditional double-free**: `from_raw` called when the pointer may have been
///    reconstituted on one branch but not another (join state = MaybeFreed).
/// 3. **Leak**: function returns with a `RawOwned` pointer that was never passed to
///    `from_raw`, `mem::forget`, or any function that could consume it.
///
/// The analysis uses allocation-site abstraction: each `into_raw` call site
/// (identified by basic block index) is a unique abstract object. The heap state
/// lattice is `RawOwned → Reconstituted / Freed / Escaped / MaybeFreed`.
use crate::analysis::object::HeapState;
use crate::analysis::transfer::{first_arg_local, is_from_raw};
use crate::analysis::FlowResults;
use crate::{Finding, FlowChecker, Severity};
use rustc_middle::mir::{Body, Local, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct OwnershipProtocol;

impl FlowChecker for OwnershipProtocol {
    fn check_flow<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut leaked_objects = std::collections::HashSet::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            // Replay statements to get the state just before the terminator.
            let Some(state) = flow.state_before_terminator(tcx, body, bb) else {
                continue;
            };

            let Some(terminator) = &block_data.terminator else { continue };

            match &terminator.kind {
                TerminatorKind::Return => {
                    // _0 is the return place in MIR; objects being returned to the caller
                    // are not leaks — the caller takes ownership.
                    let return_local = Local::from_usize(0);
                    let returned: std::collections::HashSet<_> =
                        state.objects_for(return_local).collect();

                    let mut seen = std::collections::HashSet::new();
                    for (_, objs) in &state.points_to {
                        for obj_id in objs {
                            if returned.contains(obj_id) || !seen.insert(*obj_id) {
                                continue;
                            }
                            if matches!(state.heap.get(obj_id), Some(HeapState::RawOwned)) {
                                if leaked_objects.insert(*obj_id) {
                                    findings.push(Finding {
                                        rule_id: "ownership_leak",
                                        severity: Severity::Warning,
                                        span: terminator.source_info.span,
                                        message: "raw pointer obtained from `into_raw` is never \
                                                  reconstituted via `from_raw` — memory leak"
                                            .to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                TerminatorKind::Call { func, args, .. } => {
                    let Some((def_id, _)) = func.const_fn_def() else { continue };
                    let path = tcx.def_path_str(def_id);

                    if !is_from_raw(&path) {
                        continue;
                    }

                    let Some(arg_local) = first_arg_local(args) else { continue };

                    for obj_id in state.objects_for(arg_local) {
                        match state.heap.get(&obj_id) {
                            Some(HeapState::Reconstituted) => {
                                findings.push(Finding {
                                    rule_id: "ownership_double_free",
                                    severity: Severity::Warning,
                                    span: terminator.source_info.span,
                                    message: format!(
                                        "`{}` called on a pointer that was already \
                                         reconstituted on this path — double-free",
                                        from_raw_short(&path)
                                    ),
                                });
                            }
                            Some(HeapState::MaybeFreed) => {
                                findings.push(Finding {
                                    rule_id: "ownership_double_free",
                                    severity: Severity::Warning,
                                    span: terminator.source_info.span,
                                    message: format!(
                                        "`{}` — potential double-free: pointer may have \
                                         already been reconstituted on another control-flow path",
                                        from_raw_short(&path)
                                    ),
                                });
                            }
                            _ => {}
                        }
                    }
                }

                _ => {}
            }
        }

        findings
    }
}

fn from_raw_short(path: &str) -> &str {
    if path.contains("Box") {
        "Box::from_raw"
    } else if path.contains("Arc") {
        "Arc::from_raw"
    } else if path.contains("Rc") {
        "Rc::from_raw"
    } else if path.contains("Vec") {
        "Vec::from_raw_parts"
    } else {
        "from_raw"
    }
}
