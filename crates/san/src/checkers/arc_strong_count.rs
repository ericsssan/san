/// Detects calls to `Arc::increment_strong_count`, `Arc::decrement_strong_count`,
/// `Rc::increment_strong_count`, `Rc::decrement_strong_count`, and their allocator-aware
/// `_in` variants.
///
/// These functions bypass the normal Arc/Rc ownership model by directly
/// manipulating the internal reference count:
///
///   • `increment_strong_count(ptr)` — creates a new Arc/Rc **clone** from a raw
///     pointer without going through `Arc::from_raw`; the pointer must be valid and
///     currently owned by a live Arc/Rc, or the count increment is meaningless and
///     may outlive the allocation
///   • `decrement_strong_count(ptr)` — drops one strong reference; if this brings the
///     count to zero the value is **destroyed** (dropped + freed) while the raw pointer
///     still exists — any subsequent access is use-after-free
///   • Mismatched increment/decrement pairs or calling after `Arc::from_raw` retakes
///     ownership lead to double-free or memory leak
///   • The `_in` variants carry the same risks but the allocator `A` must also match
///     the one used to create the Arc/Rc
///
/// Requirements:
///   • `ptr` must have been produced by `Arc::into_raw` (or `Arc::as_ptr`) on a
///     live Arc<T> backed by the same allocator
///   • After `decrement_strong_count` the pointer must not be used unless another
///     strong reference exists that will keep the allocation alive
///   • Count changes must be exactly balanced: every manual increment needs a
///     corresponding decrement (or `Arc::from_raw`) and vice versa
///
/// Common bugs: forgetting to balance counts in async or multi-threaded FFI code,
/// dropping the last Arc before all raw pointers are retired, incrementing after
/// the last Arc has already been dropped.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ArcStrongCount;

impl Checker for ArcStrongCount {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::increment_strong_count")
                && (path.contains("Arc") || path.contains("Rc"))
            {
                let type_name = if path.contains("Arc") { "Arc" } else { "Rc" };
                let fn_name = if path.contains("Arc") {
                    "Arc::increment_strong_count"
                } else {
                    "Rc::increment_strong_count"
                };
                (
                    fn_name,
                    format!(
                        "manually increments the strong count of a raw `{type_name}` pointer; \
                         ptr must be valid and owned by a live `{type_name}`, and every manual \
                         increment must be balanced by a matching decrement or `{type_name}::from_raw`; \
                         an unbalanced increment causes a memory leak; an increment after the last \
                         `{type_name}` was dropped is use-after-free"
                    ),
                )
            } else if path.ends_with("::decrement_strong_count")
                && (path.contains("Arc") || path.contains("Rc"))
            {
                let type_name = if path.contains("Arc") { "Arc" } else { "Rc" };
                let fn_name = if path.contains("Arc") {
                    "Arc::decrement_strong_count"
                } else {
                    "Rc::decrement_strong_count"
                };
                (
                    fn_name,
                    format!(
                        "manually decrements the strong count of a raw `{type_name}` pointer; \
                         if this brings the count to zero, the value is **dropped and freed** while \
                         the raw pointer still exists — any subsequent access is use-after-free; \
                         must be exactly balanced with prior increments or clones"
                    ),
                )
            } else if path.ends_with("::increment_strong_count_in")
                && (path.contains("Arc") || path.contains("Rc"))
            {
                let type_name = if path.contains("Arc") { "Arc" } else { "Rc" };
                let fn_name = if path.contains("Arc") {
                    "Arc::increment_strong_count_in"
                } else {
                    "Rc::increment_strong_count_in"
                };
                (
                    fn_name,
                    format!(
                        "allocator-aware variant of `{type_name}::increment_strong_count`; \
                         all the same rules apply, and additionally the allocator `A` must \
                         exactly match the one used when the `{type_name}` was created"
                    ),
                )
            } else if path.ends_with("::decrement_strong_count_in")
                && (path.contains("Arc") || path.contains("Rc"))
            {
                let type_name = if path.contains("Arc") { "Arc" } else { "Rc" };
                let fn_name = if path.contains("Arc") {
                    "Arc::decrement_strong_count_in"
                } else {
                    "Rc::decrement_strong_count_in"
                };
                (
                    fn_name,
                    format!(
                        "allocator-aware variant of `{type_name}::decrement_strong_count`; \
                         if count reaches zero the value is dropped and freed; allocator `A` \
                         must match the one used at creation"
                    ),
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "arc_strong_count",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
