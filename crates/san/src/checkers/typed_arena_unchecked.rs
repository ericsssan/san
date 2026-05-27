/// Detects calls to `typed_arena::Arena::alloc_uninitialized`.
///
/// `Arena::alloc_uninitialized(n: usize) -> &mut [MaybeUninit<T>]`:
///   • Allocates space for `n` elements of type `T` without initializing them
///   • Returns a mutable slice of `MaybeUninit<T>` that the caller must fully
///     initialize before any reads; reading from any element before it has been
///     written is immediate undefined behaviour (uninitialized memory read)
///   • If `n == 0`, the returned slice is empty but valid
///   • The lifetime of the returned slice is tied to the arena; the arena must
///     not be dropped while references to the allocation exist
///
/// Common bugs:
///   • Partially initializing the slice (writing only some elements) then casting
///     to `&mut [T]` or iterating past the initialized prefix — reads UB memory
///   • Forgetting that `MaybeUninit<T>::assume_init_ref()` is itself unsafe;
///     must only be called after the element has been written
///   • Calling `alloc_uninitialized(0)` with the intent to conditionally populate
///     later, then accessing the "empty" slice after a logic error that allows
///     non-zero element access
///
/// The safe alternative is `Arena::alloc_extend(iter)` which takes an iterator
/// of initialized values, or `Arena::alloc(value)` for a single element.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct TypedArenaUnchecked;

impl Checker for TypedArenaUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("typed_arena") || !path.ends_with("::alloc_uninitialized") {
                continue;
            }

            findings.push(Finding {
                rule_id: "typed_arena_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`Arena::alloc_uninitialized` — allocates n elements of MaybeUninit<T>; \
                          every element must be fully initialized before any read; reading from \
                          uninitialized elements is UB; use alloc_extend(iter) or alloc(value) \
                          for the safe alternatives"
                    .to_string(),
            });
        }

        findings
    }
}
