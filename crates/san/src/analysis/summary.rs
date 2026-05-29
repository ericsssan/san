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
    /// `Some(n)` when the function returns a pointer that aliases the *interior*
    /// of parameter `n` (e.g. an accessor like `triple_mut`/`as_mut_ptr` handing
    /// back the receiver's owned buffer). The caller's destination then aliases
    /// whatever it passed for parameter `n`, so freeing it would leave that
    /// argument dangling.
    pub returns_alias_of_param: Option<usize>,
    /// `Some(n)` when the function reallocates the backing buffer of parameter
    /// `n` (a Vec/String realloc somewhere inside, possibly via a wrapper like
    /// `BitVec::into_boxed_slice`). Any pointer the caller holds into that
    /// buffer is invalidated by the call — a use afterward is a use-after-free.
    pub reallocs_param: Option<usize>,
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
pub fn extract_summary<'tcx>(
    tcx: rustc_middle::ty::TyCtxt<'tcx>,
    body: &Body<'tcx>,
    flow: &FlowResults,
) -> FnSummary {
    // Collect the states at all Return terminators and join them. We replay each
    // return block's statements (not just its entry state) so effects written by
    // those statements — e.g. `_0 = &mut self.field` in a single-block accessor —
    // are reflected in the summary.
    let mut joined: Option<BlockState> = None;
    for (bb, block_data) in body.basic_blocks.iter_enumerated() {
        let Some(term) = &block_data.terminator else { continue };
        if !matches!(term.kind, rustc_middle::mir::TerminatorKind::Return) {
            continue;
        }
        if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
            joined = Some(match joined {
                None => state,
                Some(existing) => existing.join_with(&state).0,
            });
        }
    }

    let Some(exit_state) = joined else {
        return FnSummary {
            param_effects: vec![],
            returns_raw_owned: false,
            returns_alias_of_param: None,
            reallocs_param: None,
        };
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

    // If the return value aliases the interior of a parameter, record which one.
    // Owner locals are parameter locals 1..=arg_count; param index = local - 1.
    let returns_alias_of_param = exit_state.owners_of(return_local).find_map(|owner| {
        let k = owner.as_usize();
        (k >= 1 && k <= body.arg_count).then(|| k - 1)
    });

    // A parameter whose buffer was reallocated anywhere in the body (tracked in
    // `realloced_params`) yields a `reallocs_param` effect — propagated up
    // through wrapper methods so a caller's pointer into that buffer is flagged.
    let reallocs_param = exit_state.realloced_params.iter().find_map(|owner| {
        let k = owner.as_usize();
        (k >= 1 && k <= body.arg_count).then(|| k - 1)
    });

    FnSummary { param_effects, returns_raw_owned, returns_alias_of_param, reallocs_param }
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
    body: &Body<'tcx>,
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

    // If the callee hands back a pointer into one of its parameters, the
    // destination aliases the same owner the argument did. The argument counts
    // as a persistent owner only if it is itself a reference parameter or
    // already aliases one — a by-value local (e.g. `into_vec(self)`, which then
    // `mem::forget`s `self`) is consumed, not a persistent owner, so freeing
    // through it is not a use-after-free.
    state.owner_alias.remove(&dest);
    if let Some(n) = summary.returns_alias_of_param {
        if let Some(arg) = nth_arg_local(args, n) {
            let owners: Vec<Local> = if let Some(set) = state.owner_alias.get(&arg) {
                set.iter().copied().collect()
            } else if crate::analysis::transfer::is_reference_param(body, arg) {
                vec![arg]
            } else {
                Vec::new()
            };
            for owner in owners {
                state.set_owner_alias(dest, owner);
            }
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the plain `Local` at argument position `idx` (0-based), requiring
/// no projections (like `first_arg_local` but for arbitrary positions).
pub fn nth_arg_local<'tcx>(
    args: &[rustc_span::Spanned<Operand<'tcx>>],
    idx: usize,
) -> Option<Local> {
    args.get(idx).and_then(|a| first_arg_local(std::slice::from_ref(a)))
}
