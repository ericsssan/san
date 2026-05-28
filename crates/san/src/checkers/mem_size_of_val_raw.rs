/// Detects calls to `mem::size_of_val_raw` and `mem::align_of_val_raw`.
/// (Nightly: `#![feature(layout_for_ptr)]`)
///
/// These functions compute the size or alignment of the value behind a raw
/// pointer, including proper handling of fat (wide) pointers:
///   • For `*const [T]`: returns the size/alignment of the slice, using the
///     length embedded in the fat pointer
///   • For `*const dyn Trait`: uses the vtable metadata to look up the
///     concrete type's size/alignment
///
/// Safety requirements:
///   • The pointer must be non-null
///   • For fat pointers, the metadata must be valid (slice length must not
///     exceed the backing allocation; vtable must come from the correct
///     concrete type)
///   • The value does NOT need to be initialized (unlike ptr::read), but the
///     pointer must still point to an allocation that is valid for the T layout
///   • Calling with a dangling thin pointer or an invalid vtable is UB
///
/// The safe alternative is `mem::size_of_val`/`mem::align_of_val` which takes
/// a reference (`&T`) and requires the value to be initialized and accessible.
///
/// Nightly feature: `layout_for_ptr` (tracking issue #69835).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MemSizeOfValRaw;

impl Checker for MemSizeOfValRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("size_of_val_raw") {
                (
                    "mem::size_of_val_raw",
                    "pointer must be non-null; for fat pointers (slices, dyn Trait), \
                     the metadata must be valid — invalid slice length or wrong vtable \
                     is UB; prefer mem::size_of_val(&*ptr) when the value is accessible",
                )
            } else if path.ends_with("align_of_val_raw") {
                (
                    "mem::align_of_val_raw",
                    "pointer must be non-null; for fat pointers (slices, dyn Trait), \
                     the metadata must be valid — invalid slice length or wrong vtable \
                     is UB; prefer mem::align_of_val(&*ptr) when the value is accessible",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "mem_size_of_val_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
