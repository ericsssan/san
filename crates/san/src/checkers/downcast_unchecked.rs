/// Detects calls to `Box::downcast_unchecked`, `Rc::downcast_unchecked`,
/// `Arc::downcast_unchecked`, and the reference variants `downcast_unchecked_ref`
/// / `downcast_unchecked_mut` on `dyn Any` (nightly `#![feature(downcast_unchecked)]`).
///
/// These methods cast a `dyn Any` reference/smart-pointer to a concrete type
/// without checking whether the actual runtime type matches the requested type.
/// The checked variants return `Err`/`None` on mismatch; the unchecked variants
/// skip that check.
///
/// The caller must guarantee:
///   • The concrete type behind the `dyn Any` is exactly `T` — if it is any
///     other type, the returned `Box<T>` / `Rc<T>` / `Arc<T>` holds a value
///     of the wrong type; reading or dropping it is type-confusion UB
///   • After downcasting, the `dyn Any` must not be used again (ownership
///     is transferred for `Box`; reference-count bookkeeping transfers for
///     `Rc`/`Arc`)
///
/// Common bugs: type-erased plugin registries where the type ID of a registered
/// value is mismatched with the expected type at lookup time, or transmutation
/// of type IDs across crate boundaries.
///
/// Safe alternative: `Box::downcast::<T>()` returns `Ok(Box<T>)` or
/// `Err(Box<dyn Any>)` — use the unchecked form only when a prior type check
/// guarantees the type.
///
/// Nightly-only: `#![feature(downcast_unchecked)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct DowncastUnchecked;

impl Checker for DowncastUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let is_downcast = path.ends_with("downcast_unchecked")
                || path.ends_with("downcast_unchecked_ref")
                || path.ends_with("downcast_unchecked_mut");
            if !is_downcast {
                continue;
            }

            let fn_name = if path.ends_with("downcast_unchecked_ref") {
                "downcast_unchecked_ref"
            } else if path.ends_with("downcast_unchecked_mut") {
                "downcast_unchecked_mut"
            } else {
                "downcast_unchecked"
            };

            let container = if path.contains("Rc") {
                "Rc<dyn Any>"
            } else if path.contains("Arc") {
                "Arc<dyn Any>"
            } else {
                "Box<dyn Any>"
            };

            findings.push(Finding {
                rule_id: "downcast_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` on `{container}` (or `dyn Any`) — caller must guarantee \
                     the actual runtime type is exactly T; a type mismatch produces a \
                     reference to the wrong type (type-confusion UB); use the checked \
                     downcast or `Any::is::<T>()` guard first"
                ),
            });
        }

        findings
    }
}
