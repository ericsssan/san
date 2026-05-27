/// Detects `unsafe impl GlobalAlloc` implementations.
///
/// `GlobalAlloc` is the trait for the global Rust allocator. Implementing it
/// incorrectly causes silent memory corruption for the entire program.
/// The implementer must guarantee:
///
/// For `alloc(layout)`:
///   • Must return a null pointer if allocation fails (never panic or abort)
///   • The returned pointer must be unique, non-null if non-null, and aligned
///     to `layout.align()`
///   • The returned allocation must be at least `layout.size()` bytes
///   • If `layout.size() == 0`, the behavior is undefined — callers use
///     `Layout::dangling()` for ZSTs; consider checking for zero-size explicitly
///
/// For `dealloc(ptr, layout)`:
///   • `ptr` must have been returned by `alloc` with the SAME `layout`
///   • After `dealloc`, `ptr` must never be read or written again
///   • Must not be called twice on the same pointer (double-free)
///
/// For `realloc(ptr, layout, new_size)`:
///   • Same ownership requirements as `dealloc` — the old pointer is invalid
///     after the call regardless of success
///   • Returns null pointer on failure; old pointer is still valid on failure
///     (Rust's GlobalAlloc differs from C's realloc here)
///
/// Common bugs: integer overflow in allocation size computations, incorrect
/// alignment (returning under-aligned pointers), off-by-one in capacity tracking.
///
/// RustSec: RUSTSEC-2022-0070 (secp256k1), RUSTSEC-2022-0004 (bumpalo).
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct GlobalAllocImpl;

impl Checker for GlobalAllocImpl {
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
            if !trait_path.contains("GlobalAlloc") {
                continue;
            }

            findings.push(Finding {
                rule_id: "global_alloc_impl",
                severity: Severity::Warning,
                span: item.span,
                message: "`unsafe impl GlobalAlloc` — verify: alloc returns null on failure \
                          (never panics), returned pointer is correctly aligned, dealloc \
                          receives the exact layout used for alloc, realloc invalidates old \
                          pointer on both success and failure; incorrect impl corrupts all \
                          heap allocations in the process"
                    .to_string(),
            });
        }

        findings
    }
}
