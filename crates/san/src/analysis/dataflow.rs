use std::collections::{HashSet, VecDeque};
use std::rc::Rc;

use rustc_middle::mir::{BasicBlock, BasicBlockData, Body, TerminatorKind, UnwindAction};
use rustc_middle::ty::TyCtxt;

use crate::analysis::state::BlockState;
use crate::analysis::summary::SummaryMap;
use crate::analysis::transfer::{apply_statement, apply_terminator};

pub struct FlowResults {
    /// Stable fixpoint state at the entry of each basic block.
    /// `None` means the block is unreachable.
    pub entry_states: Vec<Option<BlockState>>,
    /// The interprocedural summaries this body was analyzed against, so checkers
    /// can tell which calls free which parameter (e.g. a `deallocate(p)` whose
    /// summary reconstitutes param 0). Empty during summary extraction itself.
    pub summaries: Rc<SummaryMap>,
}

impl FlowResults {
    pub fn state_at(&self, bb: BasicBlock) -> Option<&BlockState> {
        self.entry_states.get(bb.index()).and_then(|s| s.as_ref())
    }

    /// Recompute the state at the terminator of `bb` by replaying statements
    /// over the stored entry state. Returns `None` if `bb` is unreachable.
    pub fn state_before_terminator<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        bb: BasicBlock,
    ) -> Option<BlockState> {
        let mut state = self.state_at(bb)?.clone();
        for stmt in &body.basic_blocks[bb].statements {
            apply_statement(&mut state, tcx, body, stmt);
        }
        Some(state)
    }

    /// Recompute the state at an arbitrary `Location` by replaying the block's
    /// statements up to (but not including) `location.statement_index`. For a
    /// terminator location (`statement_index == statements.len()`) this is the
    /// same as `state_before_terminator`. Returns `None` if unreachable.
    pub fn state_at_location<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        location: rustc_middle::mir::Location,
    ) -> Option<BlockState> {
        let mut state = self.state_at(location.block)?.clone();
        let block = &body.basic_blocks[location.block];
        let upto = location.statement_index.min(block.statements.len());
        for stmt in &block.statements[..upto] {
            apply_statement(&mut state, tcx, body, stmt);
        }
        Some(state)
    }
}

/// Forward worklist fixpoint over `body`. Findings are NOT generated here —
/// this is pure state computation. Call `FlowChecker::check_flow` afterwards.
pub fn compute_flow<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    summaries: &Rc<SummaryMap>,
) -> FlowResults {
    let entry_states = run_fixpoint(tcx, body, BlockState::default(), summaries);
    FlowResults { entry_states, summaries: Rc::clone(summaries) }
}

/// Like `compute_flow` but seeds the entry block with the raw-pointer
/// parameters marked as `RawOwned`. Used during summary extraction so the
/// analysis models the effect of the function on its own arguments.
pub fn compute_flow_for_summary<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    summaries: &SummaryMap,
) -> FlowResults {
    use crate::analysis::summary::summary_initial_state;
    let entry_states = run_fixpoint(tcx, body, summary_initial_state(body), summaries);
    FlowResults { entry_states, summaries: Rc::new(SummaryMap::new()) }
}

/// Internal worklist fixpoint engine, returning the per-block entry states.
fn run_fixpoint<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    initial_state: BlockState,
    summaries: &SummaryMap,
) -> Vec<Option<BlockState>> {
    let num_blocks = body.basic_blocks.len();
    let mut entry_states: Vec<Option<BlockState>> = vec![None; num_blocks];

    // Seed the entry block.
    entry_states[0] = Some(initial_state);

    let mut worklist: VecDeque<BasicBlock> = VecDeque::new();
    let mut in_worklist: HashSet<BasicBlock> = HashSet::new();

    let entry_bb = BasicBlock::from_usize(0);
    worklist.push_back(entry_bb);
    in_worklist.insert(entry_bb);

    while let Some(bb) = worklist.pop_front() {
        in_worklist.remove(&bb);

        let entry = match &entry_states[bb.index()] {
            Some(s) => s.clone(),
            None => continue,
        };

        // Compute exit state.
        let mut state = entry;
        let block_data = &body.basic_blocks[bb];
        for stmt in &block_data.statements {
            apply_statement(&mut state, tcx, body, stmt);
        }
        if let Some(term) = &block_data.terminator {
            apply_terminator(&mut state, tcx, body, bb, term, summaries);
        }

        // Propagate to each successor.
        for succ in block_successors(block_data) {
            let changed = match &entry_states[succ.index()] {
                None => {
                    entry_states[succ.index()] = Some(state.clone());
                    true
                }
                Some(existing) => {
                    let (merged, changed) = existing.join_with(&state);
                    if changed {
                        entry_states[succ.index()] = Some(merged);
                    }
                    changed
                }
            };
            if changed && !in_worklist.contains(&succ) {
                worklist.push_back(succ);
                in_worklist.insert(succ);
            }
        }
    }

    entry_states
}

fn block_successors(block_data: &BasicBlockData<'_>) -> Vec<BasicBlock> {
    let Some(term) = &block_data.terminator else {
        return vec![];
    };
    use TerminatorKind::*;
    match &term.kind {
        Goto { target } => vec![*target],
        SwitchInt { targets, .. } => targets.all_targets().to_vec(),
        Return | Unreachable | CoroutineDrop | TailCall { .. } => vec![],
        Call { target, unwind, .. } => {
            let mut succs = Vec::new();
            if let Some(t) = target {
                succs.push(*t);
            }
            push_unwind(&mut succs, unwind);
            succs
        }
        Drop { target, unwind, .. } => {
            let mut succs = vec![*target];
            push_unwind(&mut succs, unwind);
            succs
        }
        Assert { target, unwind, .. } => {
            let mut succs = vec![*target];
            push_unwind(&mut succs, unwind);
            succs
        }
        FalseEdge { real_target, imaginary_target } => {
            vec![*real_target, *imaginary_target]
        }
        FalseUnwind { real_target, unwind } => {
            let mut succs = vec![*real_target];
            push_unwind(&mut succs, unwind);
            succs
        }
        Yield { resume, drop, .. } => {
            let mut succs = vec![*resume];
            if let Some(d) = drop {
                succs.push(*d);
            }
            succs
        }
        InlineAsm { targets, unwind, .. } => {
            let mut succs: Vec<BasicBlock> = targets.to_vec();
            push_unwind(&mut succs, unwind);
            succs
        }
        UnwindResume | UnwindTerminate(_) => vec![],
    }
}

fn push_unwind(succs: &mut Vec<BasicBlock>, unwind: &UnwindAction) {
    if let UnwindAction::Cleanup(bb) = unwind {
        succs.push(*bb);
    }
}
