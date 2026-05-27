/// Detects `unsafe impl Send`/`unsafe impl Sync` on generic types where the
/// generic type parameters lack the corresponding `Send`/`Sync` bounds.
///
/// Without those bounds, non-Send/non-Sync types (e.g. Rc, Cell) can be
/// smuggled across thread boundaries, causing data races.
/// Real-world CVE: RUSTSEC-2020-0099 (aovec), and many similar crates.
use crate::{Checker, Finding, Severity};
use rustc_hir as hir;
use rustc_hir::{GenericBound, GenericParamKind, ItemKind, Safety, WherePredicateKind};
use rustc_middle::ty::TyCtxt;

pub struct MissingSendSyncBounds;

impl Checker for MissingSendSyncBounds {
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item_id in tcx.hir_free_items() {
            let item = tcx.hir_item(item_id);
            let ItemKind::Impl(impl_block) = &item.kind else { continue };

            // `safety` lives on TraitImplHeader, not on Impl itself.
            let Some(trait_impl) = impl_block.of_trait else { continue };
            if trait_impl.safety != Safety::Unsafe { continue }

            // Resolve the implemented trait.
            let Some(trait_def_id) = trait_impl.trait_ref.trait_def_id() else { continue };
            let trait_path = tcx.def_path_str(trait_def_id);

            let (is_send, trait_name) = if trait_path.contains("marker::Send") {
                (true, "Send")
            } else if trait_path.contains("marker::Sync") {
                (false, "Sync")
            } else {
                continue
            };
            let required_bound = trait_name;

            // Collect type parameters declared on this impl block.
            let ty_params: Vec<_> = impl_block
                .generics
                .params
                .iter()
                .filter_map(|p| {
                    matches!(p.kind, GenericParamKind::Type { .. })
                        .then(|| p.name.ident().name)
                })
                .collect();

            if ty_params.is_empty() {
                continue;
            }

            // Collect type params that already have a Send/Sync where-clause bound.
            let bounded: Vec<_> = impl_block
                .generics
                .predicates
                .iter()
                .filter_map(|pred| {
                    let WherePredicateKind::BoundPredicate(bp) = pred.kind else {
                        return None;
                    };
                    // Bounded type must resolve to a plain type param.
                    let hir::TyKind::Path(hir::QPath::Resolved(None, path)) =
                        &bp.bounded_ty.kind
                    else {
                        return None;
                    };
                    let param_name = path.segments.last()?.ident.name;

                    let has_bound = bp.bounds.iter().any(|bound| {
                        let GenericBound::Trait(poly) = bound else { return false };
                        let Some(bound_did) = poly.trait_ref.trait_def_id() else {
                            return false;
                        };
                        let p = tcx.def_path_str(bound_did);
                        if is_send { p.contains("marker::Send") } else { p.contains("marker::Sync") }
                    });

                    has_bound.then_some(param_name)
                })
                .collect();

            // Flag every type param that is missing the bound.
            for param in &ty_params {
                if bounded.contains(param) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: "missing_send_sync_bounds",
                    severity: Severity::Warning,
                    span: item.span,
                    message: format!(
                        "`unsafe impl {trait_name}` is missing `{param}: {required_bound}` — \
                         non-{trait_name} types can cross thread boundaries"
                    ),
                });
            }
        }

        findings
    }
}
