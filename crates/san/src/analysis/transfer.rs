use rustc_middle::mir::{
    BasicBlock, Body, Local, Operand, Rvalue, Statement, StatementKind, Terminator,
    TerminatorKind,
};
use rustc_middle::ty::{TyCtxt, TyKind};

use crate::analysis::object::{HeapState, ObjectId};
use crate::analysis::state::BlockState;
use crate::analysis::typestate::{ProtocolId, ProtocolState};

pub fn apply_statement<'tcx>(
    state: &mut BlockState,
    _tcx: TyCtxt<'tcx>,
    _body: &Body<'tcx>,
    stmt: &Statement<'tcx>,
) {
    let StatementKind::Assign(assign) = &stmt.kind else { return };
    let (dst, rvalue) = &**assign;

    // Store into projection (field/deref) → escape any tracked source local.
    if !dst.projection.is_empty() {
        if let Some(src) = rvalue_local(rvalue) {
            state.escape_local(src);
        }
        return;
    }

    let dst_local = dst.local;

    match rvalue {
        // Rvalue::Use gained a second field (WithRetag) in this nightly.
        Rvalue::Use(Operand::Move(src), _) if src.projection.is_empty() => {
            // Move: transfer tracking from src to dst, clearing src.
            let src_local = src.local;
            let objs = state.points_to.remove(&src_local).unwrap_or_default();
            let proto = state.local_proto.remove(&src_local);
            if !objs.is_empty() {
                state.points_to.insert(dst_local, objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            if let Some(p) = proto {
                state.local_proto.insert(dst_local, p);
            } else {
                state.local_proto.remove(&dst_local);
            }
        }
        Rvalue::Use(Operand::Copy(src), _) if src.projection.is_empty() => {
            // Copy: alias — dst points to the same objects as src.
            let src_local = src.local;
            if let Some(objs) = state.points_to.get(&src_local).cloned() {
                state.points_to.insert(dst_local, objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            if let Some(proto) = state.local_proto.get(&src_local).copied() {
                state.local_proto.insert(dst_local, proto);
            } else {
                state.local_proto.remove(&dst_local);
            }
        }
        _ => {
            // Unknown rvalue: clear tracking on dst.
            state.points_to.remove(&dst_local);
            state.local_proto.remove(&dst_local);
        }
    }
}

pub fn apply_terminator<'tcx>(
    state: &mut BlockState,
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    bb: BasicBlock,
    term: &Terminator<'tcx>,
) {
    match &term.kind {
        TerminatorKind::Call { func, args, destination, .. } => {
            let Some((def_id, _)) = func.const_fn_def() else {
                escape_raw_ptr_args(state, body, args);
                return;
            };
            let path = tcx.def_path_str(def_id);

            // Only track if destination is a plain local (no projection).
            if !destination.projection.is_empty() {
                escape_raw_ptr_args(state, body, args);
                return;
            }
            let dest = destination.local;

            if is_into_raw(&path) {
                // Allocation site abstraction: all allocations at this call site share ObjectId.
                let obj_id = ObjectId(bb.index() as u32);
                state.points_to.insert(dest, std::iter::once(obj_id).collect());
                // Strong update: mark as freshly owned regardless of prior state.
                state.heap.insert(obj_id, HeapState::RawOwned);
            } else if is_from_raw(&path) {
                if let Some(src) = first_arg_local(args) {
                    let objs: Vec<_> = state.objects_for(src).collect();
                    for id in objs {
                        // Transition RawOwned → Reconstituted so the checker can detect
                        // a second from_raw on the same object.
                        if matches!(state.heap.get(&id), Some(HeapState::RawOwned)) {
                            state.heap.insert(id, HeapState::Reconstituted);
                        }
                        // If already Reconstituted/MaybeFreed the checker fires — don't change
                        // state here so it stays visible.
                    }
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
            } else if is_mem_forget(&path) {
                if let Some(src) = first_arg_local(args) {
                    // Escape owned objects — forgotten memory is intentionally untracked.
                    let objs: Vec<_> = state.objects_for(src).collect();
                    for id in objs {
                        state.heap.insert(id, HeapState::Escaped);
                    }
                    state.points_to.remove(&src);
                    // Protocol: Forgotten means the caller took responsibility.
                    if let Some(proto_id) = state.local_proto.remove(&src) {
                        state.typestate.insert(proto_id, ProtocolState::Forgotten);
                    }
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
            } else if is_epoch_pin(&path) {
                let proto_id = ProtocolId(bb.index() as u32);
                state.local_proto.insert(dest, proto_id);
                state.typestate.insert(proto_id, ProtocolState::Active);
            } else if is_lock_acquire(&path) {
                let proto_id = ProtocolId(bb.index() as u32);
                state.local_proto.insert(dest, proto_id);
                state.typestate.insert(proto_id, ProtocolState::Active);
            } else {
                // Unrecognized call: escape any tracked raw-pointer args, clear dest.
                escape_raw_ptr_args(state, body, args);
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
            }
        }

        TerminatorKind::Drop { place, .. } => {
            if place.projection.is_empty() {
                let local = place.local;
                // RAII drop: protocol instance is consumed.
                if let Some(proto_id) = state.local_proto.remove(&local) {
                    state.typestate.insert(proto_id, ProtocolState::Consumed);
                }
                // Don't remove from heap: RawOwned objects dropped here are leaks,
                // and the checker needs to see them at Return.
                state.points_to.remove(&local);
            }
        }

        _ => {}
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn rvalue_local<'tcx>(rvalue: &Rvalue<'tcx>) -> Option<Local> {
    match rvalue {
        Rvalue::Use(op, _) => operand_local(op),
        _ => None,
    }
}

pub fn operand_local<'tcx>(op: &Operand<'tcx>) -> Option<Local> {
    match op {
        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
        _ => None,
    }
}

/// Extract the Local from the first argument of a call, if it is a plain local.
pub fn first_arg_local<'tcx>(
    args: &[rustc_span::Spanned<Operand<'tcx>>],
) -> Option<Local> {
    args.first().and_then(|a| operand_local(&a.node))
}

/// Escape any tracked locals that are passed as raw pointers to an opaque call.
fn escape_raw_ptr_args<'tcx>(
    state: &mut BlockState,
    body: &Body<'tcx>,
    args: &[rustc_span::Spanned<Operand<'tcx>>],
) {
    for arg in args {
        if let Some(local) = operand_local(&arg.node) {
            let ty = body.local_decls[local].ty;
            if matches!(ty.kind(), TyKind::RawPtr(..)) || state.points_to.contains_key(&local) {
                state.escape_local(local);
            }
        }
    }
}

// ── predicate helpers ─────────────────────────────────────────────────────────

pub fn is_into_raw(path: &str) -> bool {
    let tail_matches = path.ends_with("::into_raw")
        || path.ends_with("::into_raw_with_allocator")
        || path.ends_with("::into_non_null")
        || path.ends_with("::into_raw_parts")
        || path.ends_with("::into_raw_parts_with_alloc");
    let crate_matches = path.contains("Box")
        || path.contains("Arc")
        || path.contains("Rc")
        || path.contains("Vec")
        || path.contains("String")
        || path.contains("Thread");
    tail_matches && crate_matches
}

pub fn is_from_raw(path: &str) -> bool {
    let direct = path.ends_with("::from_raw")
        && (path.contains("Box")
            || path.contains("Arc")
            || path.contains("Rc")
            || path.contains("Weak")
            || path.contains("Thread"));
    let from_raw_in = path.ends_with("::from_raw_in")
        && (path.contains("Box") || path.contains("Arc") || path.contains("Rc"));
    let from_non_null =
        (path.ends_with("::from_non_null") || path.ends_with("::from_non_null_in"))
            && path.contains("Box");
    let vec_parts = (path.ends_with("::from_raw_parts") || path.ends_with("::from_raw_parts_in"))
        && (path.contains("Vec") || path.contains("String"));
    direct || from_raw_in || from_non_null || vec_parts
}

pub fn is_mem_forget(path: &str) -> bool {
    matches!(path, "std::mem::forget" | "core::mem::forget")
}

pub fn is_epoch_pin(path: &str) -> bool {
    (path.ends_with("::pin") || path.ends_with("::pin_reuse")) && path.contains("epoch")
}

pub fn is_lock_acquire(path: &str) -> bool {
    let is_acquire = path.ends_with("::lock")
        || path.ends_with("::try_lock")
        || path.ends_with("::write")
        || path.ends_with("::read")
        || path.ends_with("::lock_arc");
    let is_sync = path.contains("Mutex") || path.contains("RwLock") || path.contains("ReentrantMutex");
    is_acquire && is_sync
}

pub fn is_force_unlock(path: &str) -> bool {
    path.ends_with("::force_unlock")
        || path.ends_with("::force_unlock_fair")
        || path.ends_with("::force_unlock_read")
        || path.ends_with("::force_unlock_write")
        || path.ends_with("::force_unlock_read_fair")
        || path.ends_with("::force_unlock_write_fair")
}

pub fn is_shared_deref(path: &str) -> bool {
    (path.ends_with("::deref") || path.ends_with("::deref_mut") || path.ends_with("::as_ref"))
        && path.contains("Shared")
}
