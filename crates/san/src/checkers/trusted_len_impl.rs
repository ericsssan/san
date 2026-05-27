/// Detects `unsafe impl TrustedLen` implementations (nightly `#[feature(trusted_len)]`).
///
/// `TrustedLen` is an unsafe marker trait that asserts `Iterator::size_hint` returns
/// an *exact* upper bound: `size_hint().1 == Some(remaining_count)` must hold at
/// every step. Callers such as `Vec::extend` and `Iterator::collect::<Vec<_>>`
/// use this guarantee to call `Vec::reserve(upper_bound)` exactly once and then
/// write that many elements without re-checking bounds.
///
/// The implementer must guarantee:
///   • `size_hint().1` is always `Some(n)` where `n` equals the exact number of
///     remaining `next()` calls that return `Some`
///   • The bound must not be an over-estimate — an over-estimate causes `Vec::extend`
///     to believe there is space for more elements than were actually reserved,
///     writing past the end of the Vec's allocation (out-of-bounds write → UB)
///   • The bound must not be an under-estimate — an under-estimate causes the Vec
///     to grow mid-extend (wasted allocation, but typically safe)
///
/// Common bugs: returning `(0, None)` or `(n, Some(n))` where the iterator yields
/// more than n elements after resizing an underlying collection during iteration,
/// or forgetting to decrement the claimed count when `next()` returns early.
///
/// Real-world: RUSTSEC-2025-0138 (rend) involves TrustedLen over-count; similar
/// patterns in arrow2, polars, and other data-frame crates that implement custom
/// chunk iterators.
///
/// Nightly-only: `#![feature(trusted_len)]`.
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct TrustedLenImpl;

impl Checker for TrustedLenImpl {
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item_id in tcx.hir_free_items() {
            let item = tcx.hir_item(item_id);
            let ItemKind::Impl(impl_block) = &item.kind else { continue };
            let Some(trait_impl) = impl_block.of_trait else { continue };
            if trait_impl.safety != Safety::Unsafe {
                continue;
            }
            let Some(trait_def_id) = trait_impl.trait_ref.trait_def_id() else { continue };
            let trait_path = tcx.def_path_str(trait_def_id);
            if !trait_path.contains("TrustedLen") {
                continue;
            }

            findings.push(Finding {
                rule_id: "trusted_len_impl",
                severity: Severity::Warning,
                span: item.span,
                message: "`unsafe impl TrustedLen` — `size_hint().1` must be `Some(n)` where \
                          `n` equals the exact number of remaining items; an over-count allows \
                          `Vec::extend` to write past the allocation (OOB write UB); \
                          verify the count stays correct across all iterator states"
                    .to_string(),
            });
        }

        findings
    }
}
