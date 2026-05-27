/// Detects calls to `Layout::for_value_raw`, `mem::size_of_val_raw`, and
/// `mem::align_of_val_raw` — all behind `#![feature(layout_for_ptr)]`.
///
/// Each function reads the metadata half of a fat pointer (`*const T` where T: ?Sized)
/// to determine the size or alignment of the pointed-to value. This is the unsafe
/// companion to the safe `Layout::for_value(&T)` / `mem::size_of_val(&T)` APIs.
///
/// The caller must guarantee:
///   • For `*const [T]`: the slice length metadata must be accurate (not a byte count)
///   • For `*const dyn Trait`: the vtable metadata must be valid and correspond to
///     the concrete type behind the data pointer
///   • The data pointer does NOT need to be valid (the functions only read metadata),
///     but the metadata itself must not be garbage
///   • Incorrect metadata produces wrong sizes/alignments — any subsequent allocation
///     using the resulting Layout may over- or under-allocate, causing heap corruption
///
/// Common bugs: constructing a fat pointer with the wrong length (byte count vs
/// element count), or mixing vtable and data pointer from different types.
///
/// Nightly-only: `#![feature(layout_for_ptr)]` (tracking issue #69835).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct LayoutForValueRaw;

impl Checker for LayoutForValueRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let fn_name = if path.ends_with("Layout::for_value_raw") {
                "Layout::for_value_raw"
            } else if path.ends_with("mem::size_of_val_raw") {
                "mem::size_of_val_raw"
            } else if path.ends_with("mem::align_of_val_raw") {
                "mem::align_of_val_raw"
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "layout_for_value_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — the pointer's metadata must be valid for the concrete \
                     type (correct vtable for trait objects, correct length for slices); \
                     invalid metadata produces wrong size/alignment and can corrupt allocations"
                ),
            });
        }

        findings
    }
}
