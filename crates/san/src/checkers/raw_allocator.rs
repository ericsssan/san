/// Detects calls to the raw global allocator functions:
/// `alloc::alloc`, `alloc::alloc_zeroed`, `alloc::dealloc`, `alloc::realloc`,
/// and the `GlobalAlloc` trait methods: `GlobalAlloc::alloc`, `GlobalAlloc::dealloc`,
/// `GlobalAlloc::realloc`, `GlobalAlloc::alloc_zeroed`.
///
/// These are the lowest-level Rust allocation APIs, analogous to malloc/free.
/// The caller must satisfy ALL of the following:
///   • `layout` must satisfy `layout.size() > 0` (zero-size is UB for alloc)
///   • `alloc` returns a null pointer on failure — the caller must check
///   • `dealloc`: pointer must have been returned by the same allocator with the
///     same layout, and must not be used again (use-after-free), and must be
///     called exactly once (double-free)
///   • `realloc`: same ownership rules as dealloc; the old pointer is invalid
///     after the call regardless of success or failure
///
/// Common bugs: using a pointer after dealloc/realloc, mismatched layouts between
/// alloc and dealloc, not checking for null after alloc.
///
/// Seen in: RUSTSEC-2022-0070 (secp256k1), custom arena allocators, and
/// any crate implementing its own memory management layer.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RawAllocator;

impl Checker for RawAllocator {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("alloc::realloc")
                || path.ends_with("GlobalAlloc::realloc")
            {
                ("realloc", "old pointer is invalid after call; check return for null; \
                 new_size must not overflow when rounded up for alignment")
            } else if path.ends_with("alloc::dealloc")
                || path.ends_with("GlobalAlloc::dealloc")
            {
                ("dealloc", "pointer must have been allocated by this allocator with the \
                 exact same layout; must not be used after this call (use-after-free); \
                 must be called exactly once (double-free)")
            } else if path.ends_with("alloc::alloc_zeroed")
                || path.ends_with("GlobalAlloc::alloc_zeroed")
                || path.ends_with("alloc::alloc")
                || path.ends_with("GlobalAlloc::alloc")
            {
                ("alloc", "layout.size() must be > 0; check return value for null; \
                 returned pointer must be deallocated with the same layout")
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "raw_allocator",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — {note}"
                ),
            });
        }

        findings
    }
}
