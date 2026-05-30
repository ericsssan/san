use rustc_middle::mir::{
    BasicBlock, BinOp, Body, CastKind, Local, Operand, ProjectionElem, Rvalue, Statement,
    StatementKind, Terminator, TerminatorKind,
};
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::{TyCtxt, TyKind};

use crate::analysis::object::{HeapState, InitState, ObjectId};
use crate::analysis::state::BlockState;
use crate::analysis::summary::{apply_fn_summary, SummaryMap};
use crate::analysis::typestate::{ProtocolId, ProtocolState};

/// Object-id namespace for pointers invalidated by a reallocation, kept clear of
/// call-site ids (small `bb.index()` values) and summary ids (`SUMMARY_BASE`).
const REALLOC_BASE: u32 = 0x4000_0000;

pub fn apply_statement<'tcx>(
    state: &mut BlockState,
    _tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    stmt: &Statement<'tcx>,
) {
    let StatementKind::Assign(assign) = &stmt.kind else { return };
    let (dst, rvalue) = &**assign;

    // Any write to (a projection rooted at) a local breaks owner-aliases to it:
    // the field the alias referred to may have just been reassigned. This is the
    // path-sensitive guard that keeps the *correct* realloc path (which stores a
    // fresh buffer into `self.data` before freeing the old one) from being
    // flagged, while the buggy fall-through path (no such store) stays flagged.
    state.invalidate_owner(dst.local);

    // Store into projection (field/deref) → escape any tracked source local.
    // Exception: field writes to the return place (`_0.field = ...`, no Deref) are
    // common in optimized MIR for Clone-style bodies. Propagate the source's
    // points_to into _0 so summary extraction sees SUMMARY_BASE objects there.
    if !dst.projection.is_empty() {
        let is_return_place = dst.local.as_usize() == 0;
        let has_deref = dst.projection.iter().any(|e| matches!(e, ProjectionElem::Deref));
        if is_return_place && !has_deref {
            if let Some(src_local) = rvalue_local(rvalue) {
                if let Some(objs) = state.points_to.get(&src_local).cloned() {
                    if !objs.is_empty() {
                        state.points_to.entry(Local::from_usize(0))
                            .or_default()
                            .extend(objs);
                    }
                }
            }
        } else if let Some(src) = rvalue_local(rvalue) {
            state.escape_local(src);
        }
        return;
    }

    let dst_local = dst.local;
    update_owner_alias(state, body, dst_local, rvalue);
    update_fn_ptr_target(state, dst_local, rvalue);

    match rvalue {
        // Rvalue::Use gained a second field (WithRetag) in this nightly.
        Rvalue::Use(Operand::Move(src), _) if src.projection.is_empty() => {
            // Move: transfer tracking from src to dst, clearing src.
            let src_local = src.local;
            let objs = state.points_to.remove(&src_local).unwrap_or_default();
            let protos = state.local_proto.remove(&src_local).unwrap_or_default();
            // Indirect write (*ptr = val, or (*self).field = val): the source value
            // is being stored into memory we can't track via the base local. Escape
            // the raw-owned objects rather than propagating them to dst_local (which
            // would be the pointer base, not the actual target location).
            let has_deref = dst.projection.iter().any(|e| matches!(e, ProjectionElem::Deref));
            if !dst.projection.is_empty() && has_deref {
                for id in &objs {
                    let current = state.heap.get(id).copied();
                    if !matches!(current, Some(HeapState::Reconstituted) | Some(HeapState::MaybeFreed)) {
                        state.heap.insert(*id, HeapState::Escaped);
                    }
                }
                state.points_to.remove(&dst_local);
            } else if !objs.is_empty() {
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
            // For indirect writes (*ptr = copy val), the value is stored into external
            // memory — escape any raw-owned objects tracked on src.
            let src_local = src.local;
            let has_deref = dst.projection.iter().any(|e| matches!(e, ProjectionElem::Deref));
            if !dst.projection.is_empty() && has_deref {
                if let Some(objs) = state.points_to.get(&src_local) {
                    for id in objs.iter().copied().collect::<Vec<_>>() {
                        let current = state.heap.get(&id).copied();
                        if !matches!(current, Some(HeapState::Reconstituted) | Some(HeapState::MaybeFreed)) {
                            state.heap.insert(id, HeapState::Escaped);
                        }
                    }
                }
                state.points_to.remove(&dst_local);
            } else if let Some(objs) = state.points_to.get(&src_local).cloned() {
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
        // Field read: `dst = src.field` (or `dst = src.0` for tuples). dst.projection
        // is empty (guaranteed by the early return above); src has non-Deref projections.
        // Propagate the base local's points_to so that `from_raw(w.ptr)` can reconstitute
        // an object tracked on `w` — otherwise the field copy loses the tracking and
        // the object stays RawOwned at the function's Return, triggering a spurious leak.
        //
        // Also covers `dst = (*ref_to_struct).field` — a single leading Deref followed
        // by field projections only (no nested Deref).  This lets Clone::clone propagate
        // the caller's raw-pointer tracking through `self.field` reads so that the clone
        // summary captures `returns_ptr_of_param`, enabling double-free detection when
        // both original and clone are consumed via Box::from_raw in the same body.
        Rvalue::Use(Operand::Copy(src) | Operand::Move(src), _)
            if !src.projection.is_empty()
                && {
                    let mut proj = src.projection.iter();
                    // Allow an optional single leading Deref (reference through &T),
                    // then require all remaining elements to be non-Deref field/index.
                    if matches!(proj.next(), Some(ProjectionElem::Deref)) {
                        proj.all(|e| !matches!(e, ProjectionElem::Deref))
                    } else {
                        // No Deref at all — already handled; allow if no Deref anywhere.
                        src.projection.iter().all(|e| !matches!(e, ProjectionElem::Deref))
                    }
                } =>
        {
            let src_base = src.local;
            if let Some(objs) = state.points_to.get(&src_base).cloned() {
                state.points_to.insert(dst_local, objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        // Reference / raw-pointer creation (`_ref = &_struct` or `_ptr = &raw const (*ref)`)
        // where the base local carries raw-pointer tracking. Propagate points_to so that
        // call arguments built from these rvalues (e.g. `ptr::read(&original)`,
        // Clone's `&self`) carry the struct's allocation tracking into the callee.
        Rvalue::Ref(_, _, place) if place.projection.is_empty() => {
            if let Some(objs) = state.points_to.get(&place.local).cloned() {
                if !objs.is_empty() {
                    state.points_to.insert(dst_local, objs);
                } else {
                    state.points_to.remove(&dst_local);
                }
            } else {
                state.points_to.remove(&dst_local);
            }
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        // `&raw const (*ref_local)` / `&raw mut (*ref_local)` — a raw-pointer address-of with
        // a single leading Deref (common in ptr::read call sites and FFI glue).
        // The result points to the same allocation as the base reference.
        Rvalue::RawPtr(_, place)
            if matches!(place.projection.as_ref(), [ProjectionElem::Deref]) =>
        {
            if let Some(objs) = state.points_to.get(&place.local).cloned() {
                if !objs.is_empty() {
                    state.points_to.insert(dst_local, objs);
                } else {
                    state.points_to.remove(&dst_local);
                }
            } else {
                state.points_to.remove(&dst_local);
            }
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        // `&raw const local` — direct raw address-of without Deref (no-projection case).
        Rvalue::RawPtr(_, place) if place.projection.is_empty() => {
            if let Some(objs) = state.points_to.get(&place.local).cloned() {
                if !objs.is_empty() {
                    state.points_to.insert(dst_local, objs);
                } else {
                    state.points_to.remove(&dst_local);
                }
            } else {
                state.points_to.remove(&dst_local);
            }
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        // Aggregate struct/tuple/enum construction: if any operand carries raw-pointer
        // ownership tracking, propagate it to the aggregate so that returning a struct
        // wrapping an `into_raw` pointer is not falsely reported as a leak. For example,
        // `Box::into_raw(b).cast()` stored in a `NonNull` field and returned as part of
        // `RawTask { ptr: nonull }` must show the owned object in the return value.
        Rvalue::Aggregate(_, operands) => {
            let agg_objs: std::collections::BTreeSet<_> = operands
                .iter()
                .filter_map(|op| match op {
                    Operand::Copy(p) | Operand::Move(p) if p.projection.is_empty() => {
                        state.points_to.get(&p.local)
                    }
                    _ => None,
                })
                .flat_map(|objs| objs.iter().copied())
                .collect();
            if !agg_objs.is_empty() {
                state.points_to.insert(dst_local, agg_objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        // Pointer-identity casts (PtrToPtr, Transmute) preserve the allocation
        // the pointer refers into — dst points to the same objects as src. This
        // matters for stale-pointer detection: after a realloc, a *mut T → *const T
        // cast of the stale pointer must still carry the MaybeFreed state.
        Rvalue::Cast(
            CastKind::PtrToPtr | CastKind::Transmute,
            Operand::Copy(src) | Operand::Move(src),
            _,
        ) if src.projection.is_empty() => {
            let src_local = src.local;
            if let Some(objs) = state.points_to.get(&src_local).cloned() {
                state.points_to.insert(dst_local, objs);
            } else {
                state.points_to.remove(&dst_local);
            }
            // Clear other non-pointer facts.
            state.local_proto.remove(&dst_local);
            state.init.remove(&dst_local);
            state.buf_written.remove(&dst_local);
            state.lt_facts.remove(&dst_local);
            state.ge_facts.remove(&dst_local);
            state.bounded.remove(&dst_local);
        }
        Rvalue::BinaryOp(op, operands) => {
            let (op1, _op2) = operands.as_ref();
            // For Offset/Add/Sub, the result points into the same allocation as the
            // source pointer — propagate the stale/freed state of the pointer operand.
            if matches!(op, BinOp::Offset | BinOp::Add | BinOp::Sub) {
                let ptr_objs = [operands.0.place(), operands.1.place()]
                    .into_iter()
                    .flatten()
                    .filter(|p| p.projection.is_empty())
                    .find_map(|p| state.points_to.get(&p.local).cloned());
                if let Some(objs) = ptr_objs {
                    state.points_to.insert(dst_local, objs);
                } else {
                    state.points_to.remove(&dst_local);
                }
            } else {
                state.points_to.remove(&dst_local);
            }
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
            // Resolve the callee: a direct fn item, or an indirect call through a
            // fn pointer whose reified target we tracked (vtable/fn-ptr resolution).
            // For trait method calls (e.g. `<SharedPtr as Clone>::clone`), MIR stores the
            // TRAIT method's def_id with substitutions.  Our summary map keys on the
            // concrete IMPL's def_id, so we resolve the instance first.
            let callee = func.const_fn_def()
                .map(|(id, substs)| {
                    use rustc_middle::ty::{Instance, InstanceKind, TypingEnv};
                    // Trait method calls use the TRAIT's def_id in MIR; our summary map
                    // keys on the concrete IMPL's def_id.  Only attempt resolution for
                    // AssocFn items (trait methods) to avoid ICEs on generic contexts.
                    // Use the caller's param_env so type normalization doesn't fail on
                    // abstract type parameters.
                    // Only resolve if this is a trait method (trait_of_assoc returns Some).
                    let is_trait_method = tcx.trait_of_assoc(id).is_some();
                    if is_trait_method {
                        let typing_env = TypingEnv::post_analysis(tcx, body.source.def_id());
                        Instance::try_resolve(tcx, typing_env, id, substs)
                            .ok()
                            .flatten()
                            .and_then(|inst| match inst.def {
                                InstanceKind::Item(did) => Some(did),
                                _ => None,
                            })
                            .unwrap_or(id)
                    } else {
                        id
                    }
                })
                .or_else(|| {
                    operand_local(func).and_then(|l| state.fn_ptr_targets.get(&l).copied())
                });
            // Reallocation invalidates outstanding pointers into the buffer:
            // `let p = self.v.as_mut_ptr(); self.v.push(x); use(p)`. When a
            // reallocating method is called on an owner, every pointer currently
            // aliasing that owner is marked stale (MaybeFreed — realloc is
            // capacity-conditional), so a later use is flagged as a potential
            // use-after-free. Done BEFORE invalidate_owner_args, which would
            // otherwise drop the aliases on the `&mut` receiver.
            // Which argument's buffer (if any) does this call reallocate? Either a
            // direct Vec/String realloc method (the receiver), or a callee
            // summarised as `reallocs_param` (a wrapper like
            // BitVec::into_boxed_slice → Vec::into_boxed_slice).
            let realloc_recv: Option<Local> =
                if callee.is_some_and(|id| is_reallocating_method(&tcx.def_path_str(id))) {
                    args.first().and_then(|a| operand_local(&a.node))
                } else if let Some(n) =
                    callee.and_then(|id| summaries.get(&id)).and_then(|s| s.reallocs_param)
                {
                    crate::analysis::summary::nth_arg_local(args, n)
                } else {
                    None
                };
            if let Some(recv) = realloc_recv {
                // The buffer owner is what the receiver aliases (a `&mut v`
                // reborrow), or the receiver itself when it is the owner value
                // (a by-value `self` passed to a wrapper).
                let owners: Vec<Local> = {
                    let aliased: Vec<Local> = state.owners_of(recv).collect();
                    if aliased.is_empty() { vec![recv] } else { aliased }
                };
                // Record any *parameter* owner so this body itself gets a
                // `reallocs_param` summary (propagating the effect up wrappers).
                for &o in &owners {
                    if is_param(body, o) {
                        state.realloced_params.insert(o);
                    }
                }
                // Mark stale every handle aliasing the reallocated buffer, except
                // reference (`&mut Vec`) handles — the collection itself stays
                // valid; only pointers/handles into its buffer go stale. (Marking
                // a `&mut` handle would let an opaque call's arg-escape corrupt
                // the shared object.)
                let stale: Vec<Local> = state
                    .owner_alias
                    .iter()
                    .filter(|(p, set)| {
                        owners.iter().any(|o| set.contains(o))
                            && !matches!(body.local_decls[**p].ty.kind(), TyKind::Ref(..))
                    })
                    .map(|(p, _)| *p)
                    .collect();
                for p in stale {
                    // Distinct object per stale pointer (namespaced away from
                    // call-site and summary object ids) so they don't share state.
                    let obj = ObjectId(REALLOC_BASE + p.as_u32());
                    state.heap.insert(obj, HeapState::MaybeFreed);
                    state.points_to.insert(p, std::iter::once(obj).collect());
                    state.owner_alias.remove(&p);
                }
            }

            // An accessor that *returns* a pointer into a parameter does not
            // reassign that parameter, so passing it by `&mut` must not break the
            // alias — skip invalidation for that argument.
            let alias_src_arg = callee
                .and_then(|id| summaries.get(&id))
                .and_then(|s| s.returns_alias_of_param);

            // A call may reach (and reassign a field of) any owner passed to it
            // by MUTABLE reference — conservatively break those aliases so a
            // later free isn't flagged on the strength of a now-stale alias.
            // Shared (`&`) borrows can't reassign the field, so they preserve it.
            invalidate_owner_args(state, body, args, alias_src_arg);
            // The destination is being redefined by the call.
            state.invalidate_owner(destination.local);
            state.owner_alias.remove(&destination.local);

            let Some(def_id) = callee else {
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
                let mut reconstructed_from: Option<Local> = None;
                // Accept projected places (e.g. `from_raw(w.ptr)`) by falling back to the
                // base local; same policy as mem::forget.  Using the base is sound: we
                // reconstitute all objects tracked on it, which is conservative (may miss
                // leaks of sibling fields) but never produces spurious leak/double-free.
                let src_local =
                    first_arg_local(args).or_else(|| first_arg_base_local(args));
                if let Some(src) = src_local {
                    let objs: Vec<_> = state.objects_for(src).collect();
                    for id in objs {
                        // Transition RawOwned → Reconstituted so the checker can detect
                        // a second from_raw on the same object.
                        if matches!(state.heap.get(&id), Some(HeapState::RawOwned)) {
                            state.heap.insert(id, HeapState::Reconstituted);
                        }
                    }
                    reconstructed_from = Some(src);
                }
                state.points_to.remove(&dest);
                state.local_proto.remove(&dest);
                // The reconstructed container (e.g. the `Vec` from
                // `Vec::from_raw_parts(ptr, ..)`) owns the same buffer the input
                // pointer pointed into, so it aliases whatever that pointer did.
                // This lets `BitVec::into_vec` be summarised as returning a value
                // aliasing `self`'s buffer.
                state.owner_alias.remove(&dest);
                if let Some(src) = reconstructed_from {
                    if let Some(owners) = state.owner_alias.get(&src).cloned() {
                        state.owner_alias.insert(dest, owners);
                    }
                }
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
                // assume_init / assume_init_read: extract the inner value from MaybeUninit.
                // Clear init tracking on the source (the MaybeUninit is consumed / read).
                // Propagate points_to from src to dest so ownership tracks through: two
                // assume_init calls on the same MaybeUninit<*mut T> yield two locals
                // pointing to the same allocation, enabling double-free detection.
                if let Some(src) = first_arg_local(args) {
                    state.init.remove(&src);
                    if let Some(objs) = state.points_to.get(&src).cloned() {
                        if !objs.is_empty() {
                            state.points_to.insert(dest, objs);
                        } else {
                            state.points_to.remove(&dest);
                        }
                    } else {
                        state.points_to.remove(&dest);
                    }
                } else {
                    state.points_to.remove(&dest);
                }
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if is_maybe_uninit_init(&path) {
                // MaybeUninit::new(val): wraps `val` in a MaybeUninit — propagate points_to
                // so ownership of raw pointers inside tracks through the wrapper.
                // Also marks the destination as initialized.
                if let Some(src) = first_arg_local(args) {
                    if let Some(objs) = state.points_to.get(&src).cloned() {
                        if !objs.is_empty() {
                            state.points_to.insert(dest, objs);
                        } else {
                            state.points_to.remove(&dest);
                        }
                    } else {
                        state.points_to.remove(&dest);
                    }
                } else {
                    state.points_to.remove(&dest);
                }
                state.init.insert(dest, InitState::Initialized);
                state.buf_written.remove(&dest);
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
            } else if is_ptr_read(&path) {
                if let Some(src) = first_arg_local(args) {
                    if let Some(objs) = state.points_to.get(&src).cloned() {
                        if !objs.is_empty() {
                            state.points_to.insert(dest, objs);
                        } else {
                            state.points_to.remove(&dest);
                        }
                    } else {
                        state.points_to.remove(&dest);
                    }
                } else {
                    state.points_to.remove(&dest);
                }
                state.local_proto.remove(&dest);
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else if let Some(summary) = summaries.get(&def_id) {
                // Known local function: apply its pre-computed interprocedural summary.
                apply_fn_summary(state, body, args, dest, bb, summary);
                // For provenance-preserving wrapper functions (NonNull::as_ptr, ptr::cast, etc.)
                // that have a computed summary, the summary may not set returns_ptr_of_param
                // (e.g. because self: NonNull<T> is not seeded as a raw-ptr param).
                // Apply the is_owned_buffer_accessor heuristic as a fallback to recover
                // points_to tracking that the summary cleared.
                if crate::is_owned_buffer_accessor(&path) && !state.points_to.contains_key(&dest) {
                    if let Some(arg0) = first_arg_local(args) {
                        let arg0_pts = state.points_to.get(&arg0).cloned();
                        if std::env::var_os("SAN_DBG2").is_some() && path.contains("as_ptr") {
                            eprintln!("FALLBACK as_ptr in {:?} arg0={:?} pts={:?}",
                                tcx.def_path_str(body.source.def_id()), arg0, arg0_pts);
                        }
                        if let Some(objs) = arg0_pts {
                            if !objs.is_empty() {
                                state.points_to.insert(dest, objs);
                            }
                        }
                    }
                }
                state.init.remove(&dest);
                state.buf_written.remove(&dest);
                state.lt_facts.remove(&dest);
                state.ge_facts.remove(&dest);
                state.bounded.remove(&dest);
            } else {
                // Unrecognized call: for known pointer-arithmetic / provenance-preserving
                // functions (ptr::add, ptr::sub, ptr::offset, NonNull transforms), propagate
                // the owner_alias from arg 0 to dest instead of escaping. These functions
                // have `is_owned_buffer_accessor = true` but their MIR may not be available
                // to compute a proper summary, causing the normal path to fail.
                if crate::is_owned_buffer_accessor(&path) {
                    if let Some(arg0) = first_arg_local(args) {
                        // Propagate owner_alias (for stale-detection) and points_to (for freed state).
                        if let Some(owners) = state.owner_alias.get(&arg0).cloned() {
                            if !owners.is_empty() {
                                state.owner_alias.insert(dest, owners);
                            }
                        }
                        if let Some(objs) = state.points_to.get(&arg0).cloned() {
                            if !objs.is_empty() {
                                state.points_to.insert(dest, objs);
                            }
                        }
                    }
                    // Don't escape the source arg — it's being read, not consumed.
                } else {
                    // Truly unknown call: escape tracked raw-pointer args, clear dest.
                    escape_raw_ptr_args(state, body, args);
                }
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

/// Is `local` a reference-typed parameter (`&self` / `&mut self`-style)? Such
/// parameters are the "owners" whose interior a returned pointer may alias.
/// By-value (owned) params are excluded — those are the consume pattern.
pub fn is_reference_param<'tcx>(body: &Body<'tcx>, local: Local) -> bool {
    let idx = local.as_usize();
    idx >= 1
        && idx <= body.arg_count
        && matches!(body.local_decls[local].ty.kind(), TyKind::Ref(..))
}

/// Is `local` any parameter (by-value or by-reference)?
fn is_param<'tcx>(body: &Body<'tcx>, local: Local) -> bool {
    let idx = local.as_usize();
    idx >= 1 && idx <= body.arg_count
}

/// Break owner-aliases reachable through a call's arguments. An argument that
/// is itself an owner (passed e.g. as `&mut self`), or that aliases an owner's
/// interior (a reborrow handed to the callee), lets the callee reassign that
/// owner's field — so any alias to it is conservatively dropped.
fn invalidate_owner_args<'tcx>(
    state: &mut BlockState,
    body: &Body<'tcx>,
    args: &[rustc_span::Spanned<Operand<'tcx>>],
    skip_arg: Option<usize>,
) {
    let live_owners: std::collections::BTreeSet<Local> =
        state.owner_alias.values().flat_map(|s| s.iter().copied()).collect();
    let mut to_invalidate = std::collections::BTreeSet::new();
    for (i, arg) in args.iter().enumerate() {
        // Don't invalidate the argument the callee returns an alias of — an
        // accessor does not reassign what it hands back.
        if Some(i) == skip_arg {
            continue;
        }
        if let Operand::Move(p) | Operand::Copy(p) = &arg.node {
            // Only a mutable reference argument can reassign the owner's field;
            // a shared borrow leaves it intact and must not break aliases.
            if !is_mutable_ref_ty(body.local_decls[p.local].ty) {
                continue;
            }
            let l = p.local;
            to_invalidate.extend(state.owners_of(l));
            if live_owners.contains(&l) {
                to_invalidate.insert(l);
            }
        }
    }
    for o in to_invalidate {
        state.invalidate_owner(o);
    }
}

/// `&mut T` — the only argument shape through which a callee can reassign the
/// owner's field (a `*mut` value passed by value cannot).
fn is_mutable_ref_ty<'tcx>(ty: rustc_middle::ty::Ty<'tcx>) -> bool {
    matches!(ty.kind(), TyKind::Ref(_, _, rustc_middle::ty::Mutability::Mut))
}

/// `Vec`/`String` methods that may reallocate (and thus move) the backing
/// buffer, invalidating any raw pointer previously taken into it. Restricted to
/// Vec/String so unrelated `push`/`insert` (e.g. on maps) are not matched.
pub fn is_reallocating_method(path: &str) -> bool {
    let on_buffer = path.contains("vec::Vec") || path.contains("string::String");
    if !on_buffer {
        return false;
    }
    path.ends_with("::reserve")
        || path.ends_with("::reserve_exact")
        || path.ends_with("::try_reserve")
        || path.ends_with("::try_reserve_exact")
        || path.ends_with("::shrink_to_fit")
        || path.ends_with("::shrink_to")
        || path.ends_with("::into_boxed_slice")
        || path.ends_with("::push")
        || path.ends_with("::push_str")
        || path.ends_with("::insert")
        || path.ends_with("::append")
        || path.ends_with("::extend_from_slice")
        || path.ends_with("::resize")
        || path.ends_with("::resize_with")
        || path.ends_with("::extend_from_within")
        || path.ends_with("::insert_str")
}

/// Recompute `owner_alias[dst]` from the assigned rvalue. A pointer aliases an
/// owner's interior when it is loaded by dereferencing a reference-typed
/// parameter (or a value already known to alias one), and that provenance
/// propagates through copies, casts, field projections and aggregates.
fn update_owner_alias<'tcx>(
    state: &mut BlockState,
    body: &Body<'tcx>,
    dst: Local,
    rvalue: &Rvalue<'tcx>,
) {
    // Aggregate (e.g. building the `(ptr, len, cap)` tuple): union operand owners.
    if let Rvalue::Aggregate(_, operands) = rvalue {
        let mut owners = std::collections::BTreeSet::new();
        for op in operands.iter() {
            if let Some(l) = operand_local(op) {
                owners.extend(state.owners_of(l));
            }
        }
        if owners.is_empty() {
            state.owner_alias.remove(&dst);
        } else {
            state.owner_alias.insert(dst, owners);
        }
        return;
    }

    let place = match rvalue {
        Rvalue::Use(Operand::Copy(p) | Operand::Move(p), _) => Some(p),
        Rvalue::Ref(_, _, p) => Some(p),
        Rvalue::RawPtr(_, p) => Some(p),
        Rvalue::Cast(_, Operand::Copy(p) | Operand::Move(p), _) => Some(p),
        _ => None,
    };
    let Some(place) = place else {
        state.owner_alias.remove(&dst);
        return;
    };
    let root = place.local;
    let has_deref = place.projection.iter().any(|e| matches!(e, ProjectionElem::Deref));
    let has_field = place.projection.iter().any(|e| matches!(e, ProjectionElem::Field(..)));
    // Only pointer-like types (raw pointer, reference, struct/enum — e.g. NonNull)
    // can alias a buffer. Never track integer, float, bool, or char locals: reading
    // a `len: usize` field via `*self` would otherwise spuriously get owner_alias.
    let dst_ty = body.local_decls[dst].ty;
    if matches!(dst_ty.kind(), TyKind::Int(..) | TyKind::Uint(..) | TyKind::Float(..) | TyKind::Bool | TyKind::Char) {
        state.owner_alias.remove(&dst);
        return;
    }

    let owners: std::collections::BTreeSet<Local> = if let Some(existing) = state.owner_alias.get(&root) {
        // Source is already owner-aliased — propagate through copy / field / deref.
        existing.clone()
    } else if has_deref && is_reference_param(body, root) {
        // Dereferencing a reference parameter yields a pointer into its interior.
        std::iter::once(root).collect()
    } else if has_field && is_param(body, root) {
        // Reading a field of a by-value parameter (e.g. `let p = self.pointer`
        // where `self` is taken by value): the field handle aliases the
        // parameter's buffer. Only meaningful for pointer-typed fields, but the
        // type guard above already excludes integers/booleans/floats.
        std::iter::once(root).collect()
    } else {
        std::collections::BTreeSet::new()
    };
    if owners.is_empty() {
        state.owner_alias.remove(&dst);
    } else {
        state.owner_alias.insert(dst, owners);
    }
}

/// Track which concrete fn a fn-pointer local was reified from, so an indirect
/// call through it can be resolved. Established by a `ReifyFnPointer` cast of a
/// fn item; propagated through plain copies/moves; cleared otherwise.
fn update_fn_ptr_target<'tcx>(state: &mut BlockState, dst: Local, rvalue: &Rvalue<'tcx>) {
    match rvalue {
        Rvalue::Cast(CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_), _), op, _) => {
            if let Some((did, _)) = op.const_fn_def() {
                state.fn_ptr_targets.insert(dst, did);
            } else {
                state.fn_ptr_targets.remove(&dst);
            }
        }
        Rvalue::Use(Operand::Copy(p) | Operand::Move(p), _) if p.projection.is_empty() => {
            match state.fn_ptr_targets.get(&p.local).copied() {
                Some(did) => {
                    state.fn_ptr_targets.insert(dst, did);
                }
                None => {
                    state.fn_ptr_targets.remove(&dst);
                }
            }
        }
        _ => {
            state.fn_ptr_targets.remove(&dst);
        }
    }
}

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
        || path.contains("::Weak<")
        || path.contains("::CString::")
        || path.contains("::CStr::");
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
            || path.contains("::Thread::")
            || path.contains("::CString::")
            || path.contains("::CStr::"));
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
    // Raw allocator dealloc: when a tracked pointer (from into_raw) is cast to *mut u8
    // and passed to alloc::dealloc or Allocator::deallocate, that constitutes a free
    // of the tracked allocation.
    let raw_dealloc = matches!(path,
        "std::alloc::dealloc" | "core::alloc::dealloc" | "alloc::alloc::dealloc"
        | "__rust_dealloc")
        || path.ends_with("Allocator::deallocate");
    direct || from_raw_in || from_non_null || vec_parts || raw_dealloc
}

pub fn is_mem_forget(path: &str) -> bool {
    matches!(path, "std::mem::forget" | "core::mem::forget")
}

/// Matches `ptr::read`, `ptr::read_unaligned`, and the inherent method forms on
/// `*const T`, `*mut T`, and `NonNull<T>`. Excludes `read_volatile` — it is used
/// for hardware I/O and not for ownership-transfer patterns.
pub fn is_ptr_read(path: &str) -> bool {
    path.ends_with("ptr::read") || path.ends_with("ptr::read_unaligned")
        || ((path.contains("const_ptr") || path.contains("mut_ptr") || path.contains("NonNull"))
            && (path.ends_with("::read") || path.ends_with("::read_unaligned")))
        // ManuallyDrop::new wraps a value without consuming its raw-pointer provenance;
        // ::take and ::into_inner are bitwise copies of the inner value — same aliasing
        // semantics as ptr::read. Two into_inner/take calls yield two owners of the same
        // allocation. We propagate points_to for all three so ownership tracks through.
        || (path.contains("ManuallyDrop")
            && (path.ends_with("::new")
                || path.ends_with("::take")
                || path.ends_with("::into_inner")))
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
