/// Detects `unsafe impl Allocator` implementations (nightly `#[feature(allocator_api)]`).
///
/// `Allocator` is the per-collection allocator trait, distinct from `GlobalAlloc`.
/// It is used as a type parameter in collections: `Vec<T, A: Allocator>`,
/// `Box<T, A: Allocator>`, etc.
///
/// The implementer must guarantee:
///   • `allocate(layout)` returns a valid, properly aligned memory block for the
///     given layout; returning a block smaller than layout.size() is UB for callers
///     that write layout.size() bytes
///   • `deallocate(ptr, layout)` may only be called with a pointer previously
///     returned by `allocate` (or `grow`/`shrink`) on the same allocator instance,
///     with a layout compatible with the one used to allocate; calling with a foreign
///     pointer or mismatched layout is immediate UB
///   • `grow(ptr, old_layout, new_layout)` must produce a block of at least
///     new_layout.size() bytes; the old block must remain valid until grow returns;
///     after a successful grow, the old pointer must not be used or freed
///   • `shrink(ptr, old_layout, new_layout)` — same ownership transfer as grow;
///     the first old_layout.size() bytes are preserved and the old pointer is
///     invalidated after return
///   • All returned pointers must be non-null; return Err to signal allocation failure
///   • The allocator must not use `deallocate` or `shrink` with pointers it did not
///     allocate — mixing allocator instances (e.g. one arena per thread) is a
///     common bug that causes silent heap corruption
///
/// Common bugs: double-free (calling deallocate twice on the same pointer),
/// use-after-free via a raw pointer kept after deallocate, mismatched layouts
/// between grow/shrink and the original allocation.
///
/// Nightly-only: `#![feature(allocator_api)]`.
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct AllocatorImpl;

impl Checker for AllocatorImpl {
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
            // Match core::alloc::Allocator / alloc::alloc::Allocator (the nightly per-collection allocator).
            // Use ends_with so we don't accidentally match custom crate types named Allocator.
            if !trait_path.ends_with("alloc::Allocator") {
                continue;
            }

            findings.push(Finding {
                rule_id: "allocator_impl",
                severity: Severity::Warning,
                span: item.span,
                message: "`unsafe impl Allocator` — `allocate` must return a valid, \
                          aligned block; `deallocate` must only be called with pointers \
                          from this allocator and a compatible layout; `grow`/`shrink` \
                          invalidate the old pointer on success — using it afterward is \
                          use-after-free; mixing allocator instances causes silent heap \
                          corruption"
                    .to_string(),
            });
        }

        findings
    }
}
