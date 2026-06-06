/// Detects calls to any function that returns N simultaneous mutable references
/// without checking that the keys/indices are pairwise distinct.
///
/// Covers all container types regardless of crate:
///   • `get_disjoint_unchecked_mut([i, j, …])` — slice, HashMap, slotmap, and
///     any other type with this API: indices/keys must be in-bounds (for slices)
///     and pairwise distinct
///   • `get2_unchecked_mut(k1, k2)` — two-argument variant (slab, etc.): both
///     keys must be valid entries and distinct
///   • `get_many_unchecked_mut([&k1, &k2, …])` / `get_many_key_value_unchecked_mut`
///     — N-key variants: all keys must be pairwise distinct
///
/// In every case, duplicate keys produce two `&mut T` references aliasing the
/// same memory location — immediate UB. The optimizer exploits the `noalias`
/// annotation on mutable references and may silently miscompile code that
/// violates this invariant.
///
/// Flow-sensitive suppression:
///   • For slice `get_disjoint_unchecked_mut`: suppress when all index components
///     are provably in-bounds (bounded domain) AND pairwise distinct (keys_are_ne)
///   • For key-based variants: suppress when all keys are pairwise distinct
///     (keys_are_ne domain — populated by `if k1 != k2` / `if k1 == k2 { return }`
///     guards; looks through integer casts and reference indirection)
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceDisjointUnchecked;

impl Checker for SliceDisjointUnchecked {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let is_disjoint_mut = path.ends_with("get_disjoint_unchecked_mut");
            let is_key_disjoint = path.ends_with("::get2_unchecked_mut")
                || path.ends_with("::get_many_unchecked_mut")
                || path.ends_with("::get_many_key_value_unchecked_mut");

            if !is_disjoint_mut && !is_key_disjoint {
                continue;
            }

            let arg_local = |idx: usize| -> Option<rustc_middle::mir::Local> {
                args.get(idx).and_then(|a| match &a.node {
                    Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                    _ => None,
                })
            };

            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                // Array-based: arg[1] is [K; N] — covers slice, slotmap, hashmap get_many.
                // For integer index types (usize/isize), require bounds AND ne (OOB possible).
                // For opaque key types (struct keys), ne alone is sufficient.
                let array_suppressed = arg_local(1)
                    .and_then(|arr| state.array_components_of(arr))
                    .map(|comps| {
                        if comps.len() <= 1 { return false; }
                        let all_ne = comps.iter().enumerate().all(|(i, &a)| {
                            comps[..i].iter().all(|&b| state.locals_are_ne(a, b))
                        });
                        if !all_ne { return false; }
                        // Check if components are integer types (require bounds for those).
                        let any_int = comps.iter().any(|&c| {
                            matches!(body.local_decls[c].ty.kind(),
                                rustc_middle::ty::TyKind::Uint(_) | rustc_middle::ty::TyKind::Int(_))
                        });
                        if any_int {
                            comps.iter().all(|&c| state.index_is_fully_bounded(c))
                        } else {
                            true // struct keys: ne is sufficient
                        }
                    })
                    .unwrap_or(false);

                // Individual-arg: get2_unchecked_mut(self, k1, k2) — arg[1] and arg[2].
                let individual_suppressed = is_key_disjoint && !array_suppressed
                    && arg_local(1).zip(arg_local(2))
                        .map_or(false, |(a, b)| state.locals_are_ne(a, b));

                if array_suppressed || individual_suppressed {
                    continue;
                }
            }

            let message = if is_disjoint_mut {
                "all indices must be in-bounds (< self.len()) and pairwise distinct; \
                 duplicate indices produce aliased `&mut T` references (immediate UB); \
                 use the checked variant (returns Err/None on overlap)"
            } else {
                "all keys must be pairwise distinct; duplicate keys produce aliased \
                 `&mut T` references (immediate UB); use the checked variant (returns \
                 Err/None on duplicate keys)"
            };

            findings.push(Finding {
                rule_id: "disjoint_unchecked_mut",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{}` — {message}", path.rsplit("::").next().unwrap_or(&path)),
            });
        }

        findings
    }
}
