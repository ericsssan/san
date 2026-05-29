use rustc_middle::mir::{
    BasicBlock, BinOp, Body, Local, Operand, Rvalue, Statement, StatementKind, Terminator,
    TerminatorKind,
};
use rustc_middle::ty::{TyCtxt, TyKind};

use crate::analysis::object::{HeapState, InitState, ObjectId};
use crate::analysis::state::BlockState;
use crate::analysis::summary::{apply_fn_summary, SummaryMap};
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
            let protos = state.local_proto.remove(&src_local).unwrap_or_default();
            if !objs.is_empty() {
                state.points_to.insert(dst_local, objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            if !protos.is_empty() {
                state.local_proto.insert(dst_local, protos);
            } else {
                state.local_proto.remove(&dst_local);
            }
            // Transfer init state: move src → dst, clear src.
            if let Some(init) = state.init.remove(&src_local) {
                state.init.insert(dst_local, init);
            } else {
                state.init.remove(&dst_local);
            }
            // Transfer buf_written: move src → dst, clear src.
            if state.buf_written.remove(&src_local) {
                state.buf_written.insert(dst_local);
            } else {
                state.buf_written.remove(&dst_local);
            }
            // Transfer lt_facts: move src → dst, clear src.
            if let Some(v) = state.lt_facts.remove(&src_local) {
                state.lt_facts.insert(dst_local, v);
            } else {
                state.lt_facts.remove(&dst_local);
            }
            // Transfer ge_facts: move src → dst, clear src.
            if let Some(v) = state.ge_facts.remove(&src_local) {
                state.ge_facts.insert(dst_local, v);
            } else {
                state.ge_facts.remove(&dst_local);
            }
            // Transfer bounded: move src → dst, clear src.
            if state.bounded.remove(&src_local) {
                state.bounded.insert(dst_local);
            } else {
                state.bounded.remove(&dst_local);
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
            if let Some(protos) = state.local_proto.get(&src_local).cloned() {
                state.local_proto.insert(dst_local, protos);
            } else {
                state.local_proto.remove(&dst_local);
            }
            // Copy init state: dst gets the same state as src.
            if let Some(init) = state.init.get(&src_local).cloned() {
                state.init.insert(dst_local, init);
            } else {
                state.init.remove(&dst_local);
            }
            // Copy buf_written: dst is written if src was written.
            if state.buf_written.contains(&src_local) {
                state.buf_written.insert(dst_local);
            } else {
                state.buf_written.remove(&dst_local);
            }
            // Copy lt_facts: dst gets the same fact as src.
            if let Some(v) = state.lt_facts.get(&src_local).copied() {
                state.lt_facts.insert(dst_local, v);
            } else {
                state.lt_facts.remove(&dst_local);
            }
            // Copy ge_facts: dst gets the same fact as src.
            if let Some(v) = state.ge_facts.get(&src_local).copied() {
                state.ge_facts.insert(dst_local, v);
            } else {
                state.ge_facts.remove(&dst_local);
            }
            // Copy bounded: dst is bounded if src was bounded.
            if state.bounded.contains(&src_local) {
                state.bounded.insert(dst_local);
            } else {
                state.bounded.remove(&dst_local);
            }
        }
        Rvalue::BinaryOp(op, operands) => {
            let (op1, _op2) = operands.as_ref();
            // Clear any tracked special state for dst.
            state.points_to.remove(&dst_local);
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.bounded.remove(&dst_local);
            match op {
                BinOp::Lt => {
                    if let Some(lhs) = operand_local(op1) {
                        state.lt_facts.insert(dst_local, lhs);
                    } else {
                        state.lt_facts.remove(&dst_local);
                    }
                    state.ge_facts.remove(&dst_local);
                }
                BinOp::Ge => {
                    if let Some(lhs) = operand_local(op1) {
                        state.ge_facts.insert(dst_local, lhs);
                    } else {
                        state.ge_facts.remove(&dst_local);
                    }
                    state.lt_facts.remove(&dst_local);
                }
                _ => {
                    state.lt_facts.remove(&dst_local);
                    state.ge_facts.remove(&dst_local);
                }
            }
        }
        _ => {
            // Unknown rvalue: clear tracking on dst.
            state.points_to.remove(&dst_local);
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
            // For a projected move, also clear the base local to prevent stale tracking.
            // E.g. `_dst = move _src.field` leaves `_src` tracked but field is gone.
            if let Rvalue::Use(Operand::Move(src), _) = rvalue {
                if !src.projection.is_empty() {
                    state.points_to.remove(&src.local);
                    state.local_proto.remove(&src.local);
                    state.init.remove(&src.local);
                    state.buf_written.remove(&src.local);
                    state.lt_facts.remove(&src.local);
                    state.ge_facts.remove(&src.local);
                    state.bounded.remove(&src.local);
                }
            }
        }
    }
}

pub fn apply_terminator<'tcx>(
    state: &mut BlockState,
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    bb: BasicBlock,
    term: &Terminator<'tcx>,
    summaries: &SummaryMap,
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
                // Allocation-site abstraction: all allocations at this call site share ObjectId.
                let obj_id = ObjectId(bb.index() as u32);
                state.points_to.insert(dest, std::iter::once(obj_id).collect());
                // Strong update: mark as freshly owned regardless of prior state.
                state.heap.insert(obj_id, HeapState::RawOwned);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_from_raw(&path) {
                if let Some(src) = first_arg_local(args) {
                    let objs: Vec<_> = state.objects_for(src).collect();
                    for id in objs {
                        // Transition RawOwned → Reconstituted so the checker can detect
                        // a second from_raw on the same object.
                        if matches!(state.heap.get(&id), Some(HeapState::RawOwned)) {
                            state.heap.insert(id, HeapState::Reconstituted);
                        }
                    }
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_mem_forget(&path) {
                // Use base-local extraction so `mem::forget(container.field)` is handled.
                if let Some(src) = first_arg_base_local(args) {
                    let objs: Vec<_> = state.objects_for(src).collect();
                    for id in objs {
                        state.heap.insert(id, HeapState::Escaped);
                    }
                    state.points_to.remove(&src);
                    let proto_ids = state.local_proto.remove(&src).unwrap_or_default();
                    for proto_id in &proto_ids {
                        state.typestate.insert(*proto_id, ProtocolState::Forgotten);
                    }
                    // If no ProtocolId was tracked (e.g., guard received as a parameter),
                    // check whether the local's type looks like a guard. If so, flag that
                    // an untracked forget occurred so the lock-state checker isn't confused.
                    if proto_ids.is_empty() {
                        let ty = body.local_decls[src].ty;
                        if is_guard_type(tcx, ty) {
                            state.untracked_forget_seen = true;
                        }
                    }
                    state.init.remove(&src);
                    state.buf_written.remove(&src);
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_epoch_pin(&path) {
                let proto_id = ProtocolId(bb.index() as u32);
                state.local_proto.entry(dest).or_default().insert(proto_id);
                state.typestate.insert(proto_id, ProtocolState::Active);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_lock_acquire(&path) {
                let proto_id = ProtocolId(bb.index() as u32);
                state.local_proto.entry(dest).or_default().insert(proto_id);
                state.typestate.insert(proto_id, ProtocolState::Active);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_maybe_uninit_assume_init(&path) {
                // assume_init consumes the MaybeUninit<T> by value — clear its init tracking.
                if let Some(src) = first_arg_local(args) {
                    state.init.remove(&src);
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_maybe_uninit_init(&path) {
                // MaybeUninit::new(val), MaybeUninit::zeroed(), or MaybeUninit::write(val) —
                // the destination is provably initialized.
                state.init.insert(dest, InitState::Initialized);
                state.buf_written.remove(&dest);
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_buf_write(&path) {
                // BufMut::put_slice / put_bytes / put — the self/buf argument has bytes written.
                // Record that the first argument (the buf local) had bytes written to it.
                if let Some(buf_local) = first_arg_local(args) {
                    state.buf_written.insert(buf_local);
                }
                // The return dest (usually unit) gets cleared of any stale tracking.
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if let Some(summary) = summaries.get(&def_id) {
                // Known local function: apply its pre-computed interprocedural summary.
                apply_fn_summary(state, body, args, dest, bb, summary);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else {
                // Unrecognized call: escape any tracked raw-pointer args, clear dest.
                escape_raw_ptr_args(state, body, args);
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            }
        }

        TerminatorKind::Assert { cond, expected, .. } => {
            if let Operand::Move(p) | Operand::Copy(p) = cond {
                if p.projection.is_empty() {
                    let cond_local = p.local;
                    if *expected {
                        // assert(cond, true) — cond was proven true; if cond = lhs < rhs, lhs is bounded
                        if let Some(&lhs) = state.lt_facts.get(&cond_local) {
                            state.bounded.insert(lhs);
                        }
                    } else {
                        // assert(cond, false) — cond was proven false; if cond = lhs >= rhs, lhs < rhs holds
                        if let Some(&lhs) = state.ge_facts.get(&cond_local) {
                            state.bounded.insert(lhs);
                        }
                    }
                }
            }
        }

        TerminatorKind::Drop { place, .. } => {
            if place.projection.is_empty() {
                let local = place.local;
                // RAII drop: consume all protocol instances tracked for this local.
                let proto_ids = state.local_proto.remove(&local).unwrap_or_default();
                for proto_id in proto_ids {
                    state.typestate.insert(proto_id, ProtocolState::Consumed);
                }
                // Don't remove from heap: RawOwned objects dropped here are leaks,
                // and the checker needs to see them at Return.
                state.points_to.remove(&local);
                state.init.remove(&local);
                state.buf_written.remove(&local);
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

/// Extract the Local from the first call argument, requiring no projections.
/// Use for `from_raw` — the raw pointer must be a plain local.
pub fn first_arg_local<'tcx>(
    args: &[rustc_span::Spanned<Operand<'tcx>>],
) -> Option<Local> {
    args.first().and_then(|a| operand_local(&a.node))
}

/// Extract the **base** Local from the first call argument, accepting projections.
/// Use for `mem::forget` where `mem::forget(container.field)` is valid.
pub fn first_arg_base_local<'tcx>(
    args: &[rustc_span::Spanned<Operand<'tcx>>],
) -> Option<Local> {
    args.first().and_then(|a| match &a.node {
        Operand::Move(p) | Operand::Copy(p) => Some(p.local),
        _ => None,
    })
}

/// Returns `true` if `ty` looks like a lock guard (type name contains "Guard").
/// Used to detect when a guard received as a function parameter is forgotten.
fn is_guard_type<'tcx>(tcx: TyCtxt<'tcx>, ty: rustc_middle::ty::Ty<'tcx>) -> bool {
    let check_adt = |def_id| {
        let name = tcx.item_name(def_id);
        name.as_str().contains("Guard")
    };
    match ty.kind() {
        TyKind::Adt(adt_def, _) => check_adt(adt_def.did()),
        TyKind::Ref(_, inner, _) => {
            if let TyKind::Adt(adt_def, _) = inner.kind() {
                check_adt(adt_def.did())
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Escape any tracked locals passed as raw pointers to an opaque call.
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
    let type_matches = path.contains("::Box::")
        || path.contains("::Box<")
        || path.contains("::Arc::")
        || path.contains("::Arc<")
        || path.contains("::Rc::")
        || path.contains("::Rc<")
        || path.contains("::Vec::")
        || path.contains("::Vec<")
        || path.contains("::String::")
        || path.contains("::Thread::")
        || path.contains("::Weak::")
        || path.contains("::Weak<");
    tail_matches && type_matches
}

pub fn is_from_raw(path: &str) -> bool {
    let direct = path.ends_with("::from_raw")
        && (path.contains("::Box::")
            || path.contains("::Box<")
            || path.contains("::Arc::")
            || path.contains("::Arc<")
            || path.contains("::Rc::")
            || path.contains("::Rc<")
            || path.contains("::Weak::")
            || path.contains("::Weak<")
            || path.contains("::Thread::"));
    let from_raw_in = path.ends_with("::from_raw_in")
        && (path.contains("::Box::")
            || path.contains("::Box<")
            || path.contains("::Arc::")
            || path.contains("::Arc<")
            || path.contains("::Rc::")
            || path.contains("::Rc<"));
    let from_non_null = (path.ends_with("::from_non_null")
        || path.ends_with("::from_non_null_in"))
        && (path.contains("::Box::") || path.contains("::Box<"));
    let vec_parts = (path.ends_with("::from_raw_parts")
        || path.ends_with("::from_raw_parts_in"))
        && (path.contains("::Vec::") || path.contains("::Vec<") || path.contains("::String::"));
    direct || from_raw_in || from_non_null || vec_parts
}

pub fn is_mem_forget(path: &str) -> bool {
    matches!(path, "std::mem::forget" | "core::mem::forget")
}

pub fn is_epoch_pin(path: &str) -> bool {
    (path.ends_with("::pin") || path.ends_with("::pin_reuse")) && path.contains("epoch")
}

/// Matches lock *acquisition* methods on well-known sync primitives.
/// `::read` and `::write` are deliberately excluded — they are too ambiguous
/// with async RwLock types that return futures instead of guards.
pub fn is_lock_acquire(path: &str) -> bool {
    let is_acquire = path.ends_with("::lock")
        || path.ends_with("::try_lock")
        || path.ends_with("::lock_arc");
    let is_sync = path.contains("::Mutex::")
        || path.contains("::Mutex<")
        || path.contains("::RwLock::")
        || path.contains("::RwLock<")
        || path.contains("::ReentrantMutex::")
        || path.contains("::ReentrantMutex<");
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

/// Returns `true` for `MaybeUninit` constructors that produce a provably initialized value:
/// `MaybeUninit::new(val)`, `MaybeUninit::zeroed()`, and `MaybeUninit::write(val)`.
pub fn is_maybe_uninit_init(path: &str) -> bool {
    path.contains("MaybeUninit")
        && (path.ends_with("::new") || path.ends_with("::zeroed") || path.ends_with("::write"))
}

/// Returns `true` for `BufMut` write methods that guarantee bytes are written before advancing.
pub fn is_buf_write(path: &str) -> bool {
    path.ends_with("::put_slice") || path.ends_with("::put_bytes") || path.ends_with("::put")
        || path.ends_with("::put_u8") || path.ends_with("::put_i8")
        || path.ends_with("::put_u16") || path.ends_with("::put_u16_le") || path.ends_with("::put_u16_ne")
        || path.ends_with("::put_i16") || path.ends_with("::put_i16_le") || path.ends_with("::put_i16_ne")
        || path.ends_with("::put_u32") || path.ends_with("::put_u32_le") || path.ends_with("::put_u32_ne")
        || path.ends_with("::put_i32") || path.ends_with("::put_i32_le") || path.ends_with("::put_i32_ne")
        || path.ends_with("::put_u64") || path.ends_with("::put_u64_le") || path.ends_with("::put_u64_ne")
        || path.ends_with("::put_i64") || path.ends_with("::put_i64_le") || path.ends_with("::put_i64_ne")
        || path.ends_with("::put_f32") || path.ends_with("::put_f32_le") || path.ends_with("::put_f32_ne")
        || path.ends_with("::put_f64") || path.ends_with("::put_f64_le") || path.ends_with("::put_f64_ne")
}

/// Returns `true` for `MaybeUninit::assume_init` and related consuming variants.
pub fn is_maybe_uninit_assume_init(path: &str) -> bool {
    path.contains("MaybeUninit") && path.contains("assume_init")
}
