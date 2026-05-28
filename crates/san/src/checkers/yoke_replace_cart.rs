/// Detects calls to `yoke::Yoke::replace_cart`.
///
/// `Yoke<Y, C>` is a self-referential container: `Y` (the "yokeable") holds
/// references into the data owned by `C` (the "cart"). `replace_cart` swaps the
/// cart for a new one via a closure:
///
/// ```ignore
/// pub unsafe fn replace_cart<C2>(self, f: impl FnOnce(C) -> C2) -> Yoke<Y, C2>
/// ```
///
/// The safety contract requires that the closure **transfer ownership of the data
/// the yokeable references into the new cart** before the old cart is dropped. If
/// the new cart does not contain the same data (e.g., the closure creates a fresh
/// allocation), the yokeable's internal references become dangling — use-after-free
/// (immediate UB).
///
/// Common bugs:
///   • The closure allocates a new buffer and copies content, but the yokeable
///     still holds pointers into the *old* allocation
///   • The closure wraps the old cart in a new type but the new type moves the
///     underlying allocation, invalidating interior pointers
///   • Panicking inside the closure leaks the yokeable (mitigated by `ManuallyDrop`
///     in the implementation) but the cart is still dropped, potentially freeing
///     memory the yokeable references
///
/// No safe alternative: if you need to change the cart type, consider
/// `Yoke::map_project` / `Yoke::map_project_cloned` for transforming the yokeable
/// while keeping the original cart, or restructure to avoid self-referential storage.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct YokeReplaceCart;

impl Checker for YokeReplaceCart {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("yoke") || !path.ends_with("::replace_cart") {
                continue;
            }

            findings.push(Finding {
                rule_id: "yoke_replace_cart",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`Yoke::replace_cart` — the closure must transfer ownership of all \
                     data the yokeable references into the new cart before the old cart is \
                     dropped; any dangling interior reference after cart replacement is \
                     use-after-free (immediate UB)"
                    .to_string(),
            });
        }

        findings
    }
}
