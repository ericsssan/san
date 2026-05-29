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
use crate::analysis::summary::{nth_arg_local, ParamHeapEffect};
use crate::analysis::transfer::{first_arg_local, is_from_raw};
use crate::analysis::FlowResults;
use crate::{Finding, Checker, Severity};
use rustc_middle::mir::{Body, Local, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct OwnershipProtocol;

impl Checker for OwnershipProtocol {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut leaked_objects = std::collections::HashSet::new();

        // Inside `Drop::drop`, freeing the receiver's owned buffer is the whole
        // point — the owner is being destroyed, so it is not "left dangling".
        // Suppress the owner-aliased-free detection there to avoid false positives.
        let in_drop = is_drop_method(tcx, body);

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
                    // Resolve a direct fn item, or an indirect call through a
                    // fn pointer whose reified target flow tracked.
                    let Some(def_id) = func.const_fn_def().map(|(id, _)| id).or_else(|| {
                        crate::analysis::transfer::operand_local(func)
                            .and_then(|l| state.fn_ptr_targets.get(&l).copied())
                    }) else {
                        continue;
                    };
                    let path = tcx.def_path_str(def_id);

                    // Determine which argument locals this call frees: directly via
                    // `from_raw`, or via a callee summarised as reconstituting a
                    // parameter (e.g. smallvec's `deallocate` → `Vec::from_raw_parts`).
                    let mut freed: Vec<Local> = Vec::new();
                    if is_from_raw(&path) {
                        freed.extend(first_arg_local(args));
                    } else if let Some(summary) = flow.summaries.get(&def_id) {
                        for (idx, effect) in &summary.param_effects {
                            if *effect == ParamHeapEffect::Reconstituted {
                                freed.extend(nth_arg_local(args, *idx));
                            }
                        }
                    }
                    if freed.is_empty() {
                        continue;
                    }

                    // Freeing a pointer that still aliases the interior of a live
                    // owner (e.g. `&mut self`'s heap buffer) leaves that owner
                    // holding a dangling pointer — a use-after-free now and a
                    // double-free when the owner is later dropped. This is the
                    // cross-function/-Drop shape that intra-procedural analysis
                    // and the ownership round-trip checks both miss.
                    for &freed_local in &freed {
                        // Only a REFERENCE-parameter owner (`&mut self`) is left
                        // dangling by this free — a by-value owner is consumed
                        // (e.g. `into_vec(self)` does `from_raw_parts` then
                        // `forget(self)`, which is correct). By-value owners are
                        // handled only by the realloc-stale path, not here.
                        let owns_live_ref = state
                            .owners_of(freed_local)
                            .any(|o| crate::analysis::transfer::is_reference_param(body, o));
                        if !in_drop && owns_live_ref {
                            findings.push(Finding {
                                rule_id: "use_after_free",
                                severity: Severity::Warning,
                                span: terminator.source_info.span,
                                message:
                                    "freeing a pointer that still aliases memory owned by a live \
                                     value (e.g. `&mut self`'s buffer) — the owner is left with a \
                                     dangling pointer; double-free when it is dropped"
                                        .to_string(),
                            });
                        }
                    }

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

/// Is `body` a drop context — the `drop` method of a `Drop` impl, or the
/// compiler-generated drop glue (`drop_in_place`) that the impl gets inlined
/// into? Freeing the receiver's owned buffer is correct in both.
fn is_drop_method<'tcx>(tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> bool {
    use rustc_middle::ty::InstanceKind;
    if matches!(body.source.instance, InstanceKind::DropGlue(..)) {
        return true;
    }
    let Some(drop_trait) = tcx.lang_items().drop_trait() else { return false };
    // `drop` is an *impl* item, so resolve its impl and check the trait it
    // implements (`trait_of_assoc` only covers items declared inside a trait).
    let Some(impl_id) = tcx.impl_of_assoc(body.source.def_id()) else { return false };
    tcx.impl_is_of_trait(impl_id)
        && tcx.impl_trait_ref(impl_id).skip_binder().def_id == drop_trait
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
