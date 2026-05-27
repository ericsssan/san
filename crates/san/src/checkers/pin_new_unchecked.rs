/// Detects calls to `Pin::new_unchecked`, `Pin::map_unchecked`,
/// `Pin::map_unchecked_mut`, `Pin::get_unchecked_mut`, and
/// `Pin::into_inner_unchecked`.
///
/// `Pin::new_unchecked(ptr)` pins the pointed-to value without checking whether
/// it is safe to do so. The caller must guarantee ALL of the following:
///   • The pointee must not be moved or invalidated for the entire lifetime of
///     the Pin (and all Pins derived from it)
///   • If the pointee implements `Drop`, it must guarantee not to move the value
///     after the first call to `pin()` (structural pinning)
///   • `Pin::new_unchecked` on a stack variable is almost always wrong — the
///     variable can be moved before `new_unchecked` is called
///
/// `Pin::into_inner_unchecked(pin) -> Ptr` extracts the inner pointer.
/// Safety: if `Ptr::Target` does not implement `Unpin`, the extracted value must
/// remain pinned — the compiler may have made optimizations based on the invariant
/// that the pinned location is stable, so moving the value afterwards is UB.
///
/// Common bugs:
///   • Pinning a value that is later moved (stack slot reassigned)
///   • Calling on a `&mut T` obtained from a non-pinned context
///   • In async code: moving a future that was already polled (all polls after
///     the first must receive the same pin address)
///   • `into_inner_unchecked` on a `!Unpin` future and then moving it
///
/// The `std::pin::pin!` macro is the safe alternative for stack pinning.
/// For heap pinning, `Box::pin(T)` is safe and idiomatic.
///
/// Seen in: manually implemented future poll loops, custom async runtimes,
/// and FFI layers that wrap async Rust for C callers.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PinNewUnchecked;

impl Checker for PinNewUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("Pin") {
                continue;
            }

            let message = if path.ends_with("::new_unchecked") && path.contains("pin::Pin") {
                "`Pin::new_unchecked` — pointee must not be moved or invalidated \
                 for the Pin's lifetime; use `std::pin::pin!` for stack pinning \
                 or `Box::pin` for heap pinning instead"
                    .to_string()
            } else if path.ends_with("::map_unchecked_mut") && path.contains("Pin") {
                "`Pin::map_unchecked_mut` — the closure must only project to a \
                 structurally-pinned field; if the field is not structurally pinned, \
                 using the returned Pin<&mut Field> to move the value violates pinning"
                    .to_string()
            } else if path.ends_with("::map_unchecked") && path.contains("Pin") {
                "`Pin::map_unchecked` — the closure must only project to a \
                 structurally-pinned field; the returned Pin<&Field> must not outlive \
                 the original pin"
                    .to_string()
            } else if path.ends_with("::get_unchecked_mut") && path.contains("Pin") {
                "`Pin::get_unchecked_mut` — caller must not move out of the returned \
                 `&mut T` if T does not implement Unpin; moving a previously-pinned \
                 value breaks the pinning guarantee (async futures, self-referential structs)"
                    .to_string()
            } else if path.ends_with("::into_inner_unchecked") && path.contains("Pin") {
                "`Pin::into_inner_unchecked` — if `Ptr::Target` does not implement Unpin, \
                 the extracted value must remain pinned; moving it after extraction violates \
                 the pinning invariant and may cause UB in code that relied on address stability"
                    .to_string()
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "pin_new_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
