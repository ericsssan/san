/// Detects calls to `Arc::from_raw`, `Arc::increment_strong_count`,
/// `Arc::decrement_strong_count`, `Rc::from_raw`, related reference-counted
/// pointer reconstitution functions, `Arc::get_mut_unchecked` / `Rc::get_mut_unchecked`,
/// and `Thread::from_raw`.
///
/// `Arc::from_raw(ptr)` reconstructs an Arc from a raw pointer. The caller must:
///   • The pointer must have been obtained from `Arc::into_raw` (same T, same allocator)
///   • The strong count must be correctly managed — `from_raw` does NOT increment
///     the count; the count was effectively "reserved" by `into_raw`
///   • Calling `from_raw` multiple times on the same pointer results in multiple
///     Arcs sharing the same strong-count slot — when all are dropped, the
///     reference count reaches zero multiple times → use-after-free
///   • The pointer must not be used after `from_raw` reconstitutes the Arc
///
/// The `increment_strong_count`/`decrement_strong_count` pair is the manual
/// reference-counting API — mismatched calls cause premature free (underflow)
/// or memory leaks (overflow).
///
/// `Arc::get_mut_unchecked` / `Rc::get_mut_unchecked` return `&mut T` without
/// checking if other Arc/Rc or Weak references exist. The caller must guarantee
/// no other strong or weak references are alive — if multiple owners exist,
/// this creates aliasing &mut T references, which is immediate UB.
/// (Nightly: `#![feature(get_mut_unchecked)]`)
///
/// RustSec: appears in FFI boundary code that exports Arc-backed C objects;
/// common pattern in Python/Node.js bindings to Rust.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ArcFromRaw;

impl Checker for ArcFromRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("Arc::<T>::from_raw")
                || path.ends_with("Arc::from_raw")
            {
                (
                    "Arc::from_raw",
                    "pointer must come from Arc::into_raw; does NOT increment the count; \
                     calling twice on the same pointer creates two Arcs that will \
                     double-free on drop",
                )
            } else if path.ends_with("Rc::<T>::from_raw") || path.ends_with("Rc::from_raw") {
                (
                    "Rc::from_raw",
                    "pointer must come from Rc::into_raw; does NOT increment the count; \
                     calling twice on the same pointer causes double-free on drop",
                )
            } else if path.ends_with("Arc::<T>::increment_strong_count")
                || path.ends_with("Arc::increment_strong_count")
            {
                (
                    "Arc::increment_strong_count",
                    "pointer must be valid for the lifetime of the call; every increment \
                     must be paired with exactly one decrement or from_raw — mismatches \
                     cause premature free (underflow) or memory leak (overflow)",
                )
            } else if path.ends_with("Arc::<T>::decrement_strong_count")
                || path.ends_with("Arc::decrement_strong_count")
            {
                (
                    "Arc::decrement_strong_count",
                    "pointer must still be valid; decrement to zero frees the allocation; \
                     must be paired with a corresponding increment or into_raw",
                )
            } else if path.ends_with("Rc::<T>::increment_strong_count")
                || path.ends_with("Rc::increment_strong_count")
            {
                (
                    "Rc::increment_strong_count",
                    "pointer must be valid; every increment must be paired with exactly one \
                     decrement or from_raw — mismatches cause premature free or memory leak; \
                     Rc is not thread-safe, this operation must be on the creating thread",
                )
            } else if path.ends_with("Rc::<T>::decrement_strong_count")
                || path.ends_with("Rc::decrement_strong_count")
            {
                (
                    "Rc::decrement_strong_count",
                    "pointer must still be valid; decrement to zero frees the allocation; \
                     must be paired with a corresponding increment or into_raw; \
                     Rc is not thread-safe, this operation must be on the creating thread",
                )
            } else if path.ends_with("::get_mut_unchecked") && path.contains("Arc") {
                (
                    "Arc::get_mut_unchecked",
                    "caller must ensure no other Arc or Weak references to this allocation \
                     exist; if any do, the returned &mut T aliases with shared references — UB; \
                     use Arc::get_mut for the safe checked version",
                )
            } else if path.ends_with("::get_mut_unchecked") && path.contains("Rc") {
                (
                    "Rc::get_mut_unchecked",
                    "caller must ensure no other Rc or Weak references to this allocation \
                     exist; if any do, the returned &mut T aliases with shared references — UB; \
                     use Rc::get_mut for the safe checked version",
                )
            } else if path.ends_with("::from_raw") && path.contains("sync::Weak") {
                (
                    "Arc::Weak::from_raw",
                    "pointer must have been obtained from Arc::Weak::into_raw; the control \
                     block must still be live; calling twice on the same pointer \
                     double-decrements the weak count and may free the control block prematurely",
                )
            } else if path.ends_with("::from_raw") && path.contains("rc::Weak") {
                (
                    "Rc::Weak::from_raw",
                    "pointer must have been obtained from Rc::Weak::into_raw; the control \
                     block must still be live; calling twice on the same pointer \
                     double-decrements the weak count; Rc is not thread-safe",
                )
            } else if path.ends_with("::from_raw_in") && path.contains("Box") {
                (
                    "Box::from_raw_in",
                    "pointer must have been returned by Box::into_raw_with_allocator (or \
                     Box::into_raw with the same allocator); the allocator must be the same \
                     one used for the original allocation; calling twice on the same pointer \
                     causes double-free",
                )
            } else if path.ends_with("::from_raw_in") && path.contains("Arc") {
                (
                    "Arc::from_raw_in",
                    "pointer must have been obtained from Arc::into_raw_with_allocator; \
                     does NOT increment the strong count; calling twice on the same pointer \
                     causes double-free when both Arcs are dropped",
                )
            } else if path.ends_with("::from_raw_in") && path.contains("Rc") {
                (
                    "Rc::from_raw_in",
                    "pointer must have been obtained from Rc::into_raw_with_allocator; \
                     does NOT increment the strong count; calling twice on the same pointer \
                     causes double-free when both Rcs are dropped",
                )
            } else if path.ends_with("Thread::from_raw") {
                (
                    "Thread::from_raw",
                    "pointer must have been obtained from Thread::into_raw; reconstructs \
                     ownership of the Thread handle; calling twice on the same pointer \
                     causes double-free when both handles are dropped \
                     (nightly: #![feature(thread_raw)])",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "arc_from_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
