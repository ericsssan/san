/// Detects calls to `get_unchecked`/`get_unchecked_mut` on slices and str,
/// `Pin::get_unchecked_mut`, and the deprecated `str::slice_unchecked` /
/// `str::slice_mut_unchecked` (deprecated since 1.29 in favour of `get_unchecked`).
///
/// **Slice variants** skip bounds checking. The caller must guarantee:
///   • The index is strictly in-bounds (`index < slice.len()`)
///   • For `get_unchecked_mut`: no other reference to the indexed element
///     exists for the lifetime of the returned reference
///
/// Out-of-bounds access is immediate undefined behaviour (LLVM may assume the
/// branch is unreachable and miscompile). Unlike a panicking bounds check, there
/// is no safety net — the program may silently corrupt memory or execute
/// attacker-controlled data.
///
/// **`Pin::get_unchecked_mut`** bypasses the pinning guarantee. The caller must:
///   • Not move out of the returned `&mut T` (use `mem::swap`, `ptr::write`, etc.)
///   • Not invalidate the pinned value's memory location
///   • Uphold all invariants of the `Unpin`-locked type
///
/// For `split_at_unchecked` and `split_at_mut_unchecked` see the `split_at_unchecked` rule.
///
/// Common bugs: off-by-one errors, stale length values after mutations, index
/// computed from unvalidated external input; Pin: moving the value via the
/// returned mutable reference (self-referential struct corruption).
///
/// RustSec: RUSTSEC-2021-0068 (iced-x86), RUSTSEC-2026-0123 (rustdx),
/// RUSTSEC-2025-0113 (shaman), RUSTSEC-2025-0063 (fast-able).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceGetUnchecked;

impl Checker for SliceGetUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            // Suppress non-Pin get_unchecked* when the index is proven bounded.
            if (path.ends_with("get_unchecked_mut") || path.ends_with("get_unchecked"))
                && !path.contains("pin::Pin")
            {
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    let recv_local = args.first().and_then(|a| match &a.node {
                        Operand::Move(p) | Operand::Copy(p) => Some(state.deref_base(p.local)),
                        _ => None,
                    });
                    let idx_local = args.get(1).and_then(|a| match &a.node {
                        Operand::Move(p) | Operand::Copy(p) => Some(p.local),
                        _ => None,
                    });
                    if let (Some(recv), Some(idx)) = (recv_local, idx_local) {
                        // Precise check: index proven < THIS slice's len on all paths.
                        if state.index_is_bounded_for(idx, recv) {
                            continue;
                        }
                    }
                    // Fallback: index was compared against some bound (may differ from this slice).
                    if let Some(idx) = idx_local {
                        if state.local_is_bounded(idx) {
                            continue;
                        }
                    }
                    // Special case: get_unchecked(0) when the collection is proven non-empty.
                    // A constant index of 0 is always valid if len >= 1. Proved by:
                    //   • The len() result being in `nonzero` (from `if len != 0` / `if !is_empty()`)
                    //   • idx being a constant 0 (idx_local = None)
                    // This suppresses `if !coll.is_empty() { coll.get_unchecked(0) }`.
                    if idx_local.is_none() {
                        let idx_is_zero = args.get(1).map_or(false, |a| {
                            if let Operand::Constant(c) = &a.node {
                                c.const_.try_to_scalar_int()
                                    .and_then(|si| si.to_bits(si.size()).try_into().ok())
                                    .map_or(false, |v: u64| v == 0)
                            } else {
                                false
                            }
                        });
                        if idx_is_zero {
                            if let Some(recv) = recv_local {
                                let coll_nonempty = state.len_of.iter()
                                    .any(|(len_l, &c)| c == recv && state.nonzero.contains(len_l));
                                if coll_nonempty {
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            let message = if path.ends_with("get_unchecked_mut") && path.contains("pin::Pin") {
                "`Pin::get_unchecked_mut` — must not move out of or invalidate the \
                 returned &mut T; moving the value violates pinning (self-referential \
                 structs will corrupt their internal pointers)"
                    .to_string()
            } else if path.ends_with("get_unchecked_mut") {
                "`get_unchecked_mut` — index must be strictly in-bounds (< len); \
                 out-of-bounds access is UB (no panic, silent memory corruption)"
                    .to_string()
            } else if path.ends_with("get_unchecked") {
                "`get_unchecked` — index must be strictly in-bounds (< len); \
                 out-of-bounds access is UB (no panic, silent memory corruption)"
                    .to_string()
            } else if path.ends_with("::slice_mut_unchecked") {
                "`str::slice_mut_unchecked` (deprecated since 1.29 — use `get_unchecked_mut`) \
                 — begin and end must be on valid UTF-8 boundaries within the string; \
                 out-of-bounds or misaligned offsets are UB"
                    .to_string()
            } else if path.ends_with("::slice_unchecked") {
                "`str::slice_unchecked` (deprecated since 1.29 — use `get_unchecked`) \
                 — begin and end must be on valid UTF-8 boundaries within the string; \
                 out-of-bounds or misaligned offsets are UB"
                    .to_string()
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "slice_get_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
