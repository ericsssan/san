/// Detects calls to `slice::from_raw_parts`, `slice::from_raw_parts_mut`,
/// `slice::from_ptr_range`, and `slice::from_mut_ptr_range`.
/// (`str::from_raw_parts` / `str::from_raw_parts_mut` are handled by `str_from_utf8_unchecked`.)
///
/// The caller must guarantee ALL of the following (any violation is UB):
///   • `ptr` is non-null and properly aligned for `T`
///   • `ptr..ptr+len` points to `len` consecutive, fully-initialized `T` values
///   • The memory is valid for the returned slice's lifetime
///   • No mutable alias exists for the range (from_raw_parts_mut: no other ref)
///
/// Common bugs: wrong length (byte count vs element count), dangling pointer
/// after reallocation, lifetime extension past the allocation.
///
/// Seen across dozens of RustSec advisories (arrow, abomonation, and many FFI
/// boundary crates).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceFromRawParts;

impl Checker for SliceFromRawParts {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            // NonNull::slice_from_raw_parts — stable 1.70
            if path.ends_with("::slice_from_raw_parts") && path.contains("NonNull") {
                findings.push(Finding {
                    rule_id: "slice_from_raw_parts",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`NonNull::slice_from_raw_parts` — data pointer must be non-null \
                               (guaranteed), properly aligned for T, and valid for `len` \
                               consecutive initialized elements; len must not exceed the \
                               backing allocation"
                        .to_string(),
                });
                continue;
            }

            // from_ptr_range / from_mut_ptr_range (nightly `slice_from_ptr_range`)
            if path.ends_with("from_ptr_range") || path.ends_with("from_mut_ptr_range") {
                let fn_name = if path.ends_with("from_mut_ptr_range") {
                    "slice::from_mut_ptr_range"
                } else {
                    "slice::from_ptr_range"
                };
                let extra = if path.ends_with("from_mut_ptr_range") {
                    " with exclusive mutable access"
                } else {
                    ""
                };
                findings.push(Finding {
                    rule_id: "slice_from_raw_parts",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: format!(
                        "`{fn_name}` — both pointers must be derived from the same allocation, \
                         properly aligned, and the range [start, end) must be valid for \
                         the returned lifetime{extra}; stable since Rust 1.73"
                    ),
                });
                continue;
            }

            let is_mut = path.ends_with("from_raw_parts_mut");
            if !is_mut && !path.ends_with("from_raw_parts") {
                continue;
            }
            // Exclude false positives from unrelated from_raw_parts (e.g. on other types)
            // str::from_raw_parts is handled by str_from_utf8_unchecked checker
            if !path.contains("slice::") {
                continue;
            }

            let fn_name = if is_mut { "from_raw_parts_mut" } else { "from_raw_parts" };
            findings.push(Finding {
                rule_id: "slice_from_raw_parts",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` requires: non-null aligned ptr, {}'s `len` initialized \
                     elements of the correct type, and a valid lifetime — verify all \
                     three invariants",
                    if is_mut { "mutably exclusive" } else { "immutably accessible" }
                ),
            });
        }

        findings
    }
}
