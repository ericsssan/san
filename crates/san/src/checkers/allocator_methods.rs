/// Detects calls to the unsafe methods of the `Allocator` trait:
/// `Allocator::deallocate`, `Allocator::grow`, and `Allocator::shrink`.
/// (Nightly: `#![feature(allocator_api)]`)
///
/// The `Allocator` trait is the nightly-only abstraction over memory allocators.
/// `allocate` and `allocate_zeroed` are safe (return `Result`), but the
/// following methods are `unsafe fn` with strict caller invariants:
///
/// `Allocator::deallocate(ptr, layout)`:
///   • `ptr` must have been returned by a previous `allocate`/`allocate_zeroed`
///     call on the **same allocator**
///   • `layout` must be the **exact layout** used for the original allocation
///   • Calling with a different layout or a pointer from a different allocator
///     instance is immediate UB
///   • Calling twice on the same pointer is double-free
///
/// `Allocator::grow(ptr, old_layout, new_layout)`:
///   • `ptr` must have been allocated by the same allocator with `old_layout`
///   • `new_layout.size() >= old_layout.size()` must hold
///   • `old_layout.align() == new_layout.align()` must hold on many allocators
///   • The allocation is semantically moved — the old `ptr` must not be used
///     after a successful grow
///
/// `Allocator::shrink(ptr, old_layout, new_layout)`:
///   • `ptr` must have been allocated by the same allocator with `old_layout`
///   • `new_layout.size() <= old_layout.size()` must hold
///   • The allocation is semantically moved — the old `ptr` must not be used
///     after a successful shrink
///
/// The low-level `alloc::alloc` / `alloc::dealloc` C-style API is flagged by
/// the `raw_allocator` rule.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AllocatorMethods;

impl Checker for AllocatorMethods {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("Allocator::deallocate") {
                (
                    "Allocator::deallocate",
                    "ptr must have been returned by this same allocator with the exact same \
                     layout; wrong allocator, wrong layout, or double-free is immediate UB; \
                     the allocation is consumed — do not use ptr after this call",
                )
            } else if path.ends_with("Allocator::grow")
                || path.ends_with("Allocator::grow_zeroed")
            {
                (
                    "Allocator::grow",
                    "ptr must come from this allocator with old_layout; new_layout.size() \
                     must be >= old_layout.size(); the old ptr is consumed on success — \
                     do not use it after a successful grow",
                )
            } else if path.ends_with("Allocator::shrink") {
                (
                    "Allocator::shrink",
                    "ptr must come from this allocator with old_layout; new_layout.size() \
                     must be <= old_layout.size(); the old ptr is consumed on success — \
                     do not use it after a successful shrink",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "allocator_methods",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
