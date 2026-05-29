use std::collections::HashMap;

use rustc_hir::def_id::DefId;
use rustc_middle::mir::{BasicBlock, Body, Local, Operand};
use rustc_middle::ty::TyKind;

use crate::analysis::dataflow::FlowResults;
use crate::analysis::object::{HeapState, ObjectId};
use crate::analysis::state::BlockState;
use crate::analysis::transfer::first_arg_local;

/// Avoids collision with BasicBlock-index ObjectIds used in the normal flow.
pub const SUMMARY_BASE: u32 = 0x8000_0000;

/// Effect a function has on one of its raw-pointer parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamHeapEffect {
    /// The parameter's backing allocation is untouched (not reconstituted, not escaped).
    None,
    /// The parameter was passed to `Box::from_raw` / `Arc::from_raw` etc.
    /// (the heap object transitions `RawOwned → Reconstituted`).
    Reconstituted,
    /// The parameter was passed to an opaque call and its provenance is lost.
    Escaped,
}

/// Compact summary of what a function does to raw-pointer parameters and its
/// return value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FnSummary {
    /// `(param_index, effect)` — only parameters with a non-`None` effect are stored.
    pub param_effects: Vec<(usize, ParamHeapEffect)>,
    /// `true` when the return value is a freshly-owned raw pointer created inside
    /// this function (i.e. the function calls `into_raw` and returns that pointer).
    pub returns_raw_owned: bool,
}

/// Maps local DefIds to their pre-computed summaries.
pub type SummaryMap = HashMap<DefId, FnSummary>;

// ── summary_initial_state ─────────────────────────────────────────────────────

/// Build the seed `BlockState` for summary computation: every raw-pointer
/// argument local gets its own virtual heap object with id `SUMMARY_BASE +
/// param_idx`, initialised as `RawOwned`.
pub fn summary_initial_state<'tcx>(body: &Body<'tcx>) -> BlockState {
    let mut state = BlockState::default();

    // args are locals 1..=arg_count (local _0 is the return place).
    for param_idx in 0..body.arg_count {
        let local = Local::from_usize(param_idx + 1);
        let ty = body.local_decls[local].ty;
        if matches!(ty.kind(), TyKind::RawPtr(..)) {
            let obj_id = ObjectId(SUMMARY_BASE + param_idx as u32);
            state
                .points_to
                .insert(local, std::iter::once(obj_id).collect());
            state.heap.insert(obj_id, HeapState::RawOwned);
        }
    }

    state
}

// ── extract_summary ───────────────────────────────────────────────────────────

/// Derive a `FnSummary` by inspecting the fixpoint `FlowResults` of a
/// function body that was analysed with `summary_initial_state` as the seed.
pub fn extract_summary<'tcx>(body: &Body<'tcx>, flow: &FlowResults) -> FnSummary {
    // Collect the entry states of all Return basic blocks and join them.
    let mut joined: Option<BlockState> = None;
    for (bb, block_data) in body.basic_blocks.iter_enumerated() {
        let Some(term) = &block_data.terminator else { continue };
        if !matches!(term.kind, rustc_middle::mir::TerminatorKind::Return) {
            continue;
        }
        if let Some(state) = flow.state_at(bb) {
            joined = Some(match joined {
                None => state.clone(),
                Some(existing) => existing.join_with(state).0,
            });
        }
    }

    let Some(exit_state) = joined else {
        return FnSummary { param_effects: vec![], returns_raw_owned: false };
    };

    // Determine per-parameter effects.
    let mut param_effects = Vec::new();
    for param_idx in 0..body.arg_count {
        let obj_id = ObjectId(SUMMARY_BASE + param_idx as u32);
        let effect = match exit_state.heap.get(&obj_id) {
            Some(HeapState::Reconstituted) => ParamHeapEffect::Reconstituted,
            Some(HeapState::Escaped) | Some(HeapState::MaybeFreed) => ParamHeapEffect::Escaped,
            _ => ParamHeapEffect::None,
        };
        if effect != ParamHeapEffect::None {
            param_effects.push((param_idx, effect));
        }
    }

    // Determine whether the function returns a freshly-owned raw pointer.
    // _0 is the return place; if it points to an object whose id < SUMMARY_BASE
    // (a call-site ObjectId minted by `into_raw` handling), it is raw-owned.
    let return_local = Local::from_usize(0);
    let returns_raw_owned = exit_state
        .objects_for(return_local)
        .any(|id| id.0 < SUMMARY_BASE && matches!(exit_state.heap.get(&id), Some(HeapState::RawOwned)));

    FnSummary { param_effects, returns_raw_owned }
}

// ── apply_fn_summary ──────────────────────────────────────────────────────────

/// Apply a callee's `FnSummary` at the call site.
///
/// * For each `(param_idx, Reconstituted)`: transition the corresponding
///   argument's heap objects from `RawOwned → Reconstituted` and remove the
///   local from `points_to`.
/// * For each `(param_idx, Escaped)`: escape the argument local.
/// * `returns_raw_owned`: seed `dest` with a fresh `RawOwned` object keyed on
///   `call_bb`; otherwise clear `dest`.
pub fn apply_fn_summary<'tcx>(
    state: &mut BlockState,
    _body: &Body<'tcx>,
    args: &[rustc_span::Spanned<Operand<'tcx>>],
    dest: Local,
    call_bb: BasicBlock,
    summary: &FnSummary,
) {
    for (param_idx, effect) in &summary.param_effects {
        // Resolve the actual argument at position `param_idx`.
        let Some(arg_local) = nth_arg_local(args, *param_idx) else { continue };

        match effect {
            ParamHeapEffect::Reconstituted => {
                let objs: Vec<_> = state.objects_for(arg_local).collect();
                for id in objs {
                    if matches!(state.heap.get(&id), Some(HeapState::RawOwned)) {
                        state.heap.insert(id, HeapState::Reconstituted);
                    }
                }
                // Keep `arg_local` pointing at the now-`Reconstituted` object
                // (do NOT remove it from `points_to`): the callee took ownership,
                // so any *subsequent* use of this pointer in the caller is a
                // use-after-free. Mirrors the literal `from_raw` handler, which
                // also leaves the source local linked so a second use is caught.
                state.local_proto.remove(&arg_local);
            }
            ParamHeapEffect::Escaped => {
                state.escape_local(arg_local);
            }
            ParamHeapEffect::None => {}
        }
    }

    if summary.returns_raw_owned {
        let obj_id = ObjectId(call_bb.index() as u32);
        state.points_to.insert(dest, std::iter::once(obj_id).collect());
        state.heap.insert(obj_id, HeapState::RawOwned);
    } else {
        state.points_to.remove(&dest);
        state.local_proto.remove(&dest);
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the plain `Local` at argument position `idx` (0-based), requiring
/// no projections (like `first_arg_local` but for arbitrary positions).
fn nth_arg_local<'tcx>(
    args: &[rustc_span::Spanned<Operand<'tcx>>],
    idx: usize,
) -> Option<Local> {
    args.get(idx).and_then(|a| first_arg_local(std::slice::from_ref(a)))
}
