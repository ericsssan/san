/// Detects calls to `ptr::from_raw_parts` and `ptr::from_raw_parts_mut`
/// (stable since Rust 1.84).
///
/// These functions reconstruct a wide (fat) pointer — a `*const dyn Trait` or
/// `*const [T]` — from a thin data pointer and its associated metadata (a vtable
/// pointer or a slice length). Requirements:
///
/// For slice fat pointers (`*const [T]` / `*mut [T]`):
///   • `data_pointer` must be non-null, aligned, and valid for `len` elements of T
///   • `metadata` (the slice length) must not exceed the allocation size
///
/// For trait-object fat pointers (`*const dyn Trait` / `*mut dyn Trait`):
///   • `data_pointer` must point to an object that actually implements `Trait`
///   • `metadata` must be the vtable pointer for the *same concrete type* as the
///     data pointer — mixing vtable and data pointer from different types is
///     immediate undefined behaviour (type confusion / invalid virtual dispatch)
///   • The vtable must come from the same version of the crate that produced the
///     data pointer (across crate boundaries with mismatched vtable layouts is UB)
///
/// Common bugs: constructing a trait-object pointer from a vtable obtained from
/// a different type, or from a vtable that was itself cast out of a raw integer.
///
/// Stable since Rust 1.84 as part of the strict-provenance stabilization.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrFromRawParts;

impl Checker for PtrFromRawParts {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("ptr::from_raw_parts_mut") {
                (
                    "ptr::from_raw_parts_mut",
                    "for trait objects: vtable metadata must match the concrete type behind \
                     the data pointer exactly — type confusion is immediate UB; \
                     for slices: len must not exceed the backing allocation",
                )
            } else if path.ends_with("ptr::from_raw_parts") {
                (
                    "ptr::from_raw_parts",
                    "for trait objects: vtable metadata must match the concrete type behind \
                     the data pointer exactly — type confusion is immediate UB; \
                     for slices: len must not exceed the backing allocation",
                )
            } else if path.contains("NonNull") && path.ends_with("::from_raw_parts") {
                (
                    "NonNull::from_raw_parts",
                    "data pointer must be non-null and properly aligned; \
                     for trait objects: vtable metadata must match the concrete type exactly \
                     (type confusion is immediate UB); \
                     for slices: len must not exceed the backing allocation",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_from_raw_parts",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
