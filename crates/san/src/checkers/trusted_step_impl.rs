/// Detects `unsafe impl TrustedStep` implementations (nightly `#[feature(step_trait)]`).
///
/// `TrustedStep` is an unsafe marker trait on top of `Step` that asserts:
///   • `Step::steps_between(start, end)` returns `Some(n)` if and only if
///     `start <= end` and the range contains exactly `n` elements
///   • `Step::forward_checked(start, count)` produces the correct successor
///   • `Step::backward_checked(start, count)` produces the correct predecessor
///
/// These invariants are used by range iterators and `(start..=end).nth(n)` to
/// perform direct indexing arithmetic. An incorrect implementation causes:
///   • `(0u8..=255).nth(256)` style calls to produce out-of-bounds accesses
///   • Range-based for loops to skip or repeat elements
///   • `Iterator::zip` specializations to read past the end of one iterator
///
/// The default implementations for built-in integer types are correct; this
/// checker fires on custom `Step` + `TrustedStep` implementations where the
/// arithmetic must be manually verified.
///
/// Nightly-only: `#![feature(step_trait)]`.
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct TrustedStepImpl;

impl Checker for TrustedStepImpl {
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
            if !trait_path.contains("TrustedStep") {
                continue;
            }

            findings.push(Finding {
                rule_id: "trusted_step_impl",
                severity: Severity::Warning,
                span: item.span,
                message: "`unsafe impl TrustedStep` — `steps_between(start, end)` must return \
                          `Some(n)` with exactly the right count; an incorrect count enables \
                          range-iterator indexing UB (out-of-bounds reads, skipped elements); \
                          verify arithmetic wraps and boundary conditions are handled correctly"
                    .to_string(),
            });
        }

        findings
    }
}
