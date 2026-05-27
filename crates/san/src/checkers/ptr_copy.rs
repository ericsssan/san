/// Detects calls to `ptr::copy`, `ptr::copy_nonoverlapping`,
/// `NonNull::copy_to`, and `NonNull::copy_to_nonoverlapping`.
///
/// Both functions are the Rust equivalent of `memmove`/`memcpy`.
/// The caller must guarantee:
///   • `src` and `dst` are non-null and properly aligned for `T`
///   • `src` is valid for `count * size_of::<T>()` bytes of reads
///   • `dst` is valid for `count * size_of::<T>()` bytes of writes
///   • For `copy_nonoverlapping`: `src` and `dst` do not overlap
///   • `T` is `Copy`, or the caller manually manages the dropped values
///
/// Common bugs: byte-count vs element-count confusion, overlapping regions
/// passed to `copy_nonoverlapping`, dangling pointers after reallocation.
///
/// Seen in: custom Vec/String implementations, low-level buffer managers,
/// FFI boundary code across dozens of RustSec advisories.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, NonDivergingIntrinsic, StatementKind, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrCopy;

impl Checker for PtrCopy {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            // In optimized/release builds, copy_nonoverlapping may lower to a
            // StatementKind::Intrinsic rather than a TerminatorKind::Call.
            for stmt in &block_data.statements {
                let StatementKind::Intrinsic(intrinsic) = &stmt.kind else { continue };
                let NonDivergingIntrinsic::CopyNonOverlapping(_) = intrinsic.as_ref() else { continue };
                findings.push(Finding {
                    rule_id: "ptr_copy",
                    severity: Severity::Warning,
                    span: stmt.source_info.span,
                    message: "`ptr::copy_nonoverlapping` — verify src and dst are non-null, \
                              aligned, each backed by at least count*size_of::<T>() valid bytes, \
                              and that the ranges do not overlap"
                        .to_string(),
                });
            }

            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let is_mut_ptr = path.contains("mut_ptr");
            let is_const_ptr = path.contains("const_ptr");
            let is_nonnull = path.contains("NonNull");
            let is_raw_ptr = is_nonnull || is_mut_ptr || is_const_ptr;

            let is_nonoverlapping = path.ends_with("ptr::copy_nonoverlapping")
                || path.ends_with("intrinsics::copy_nonoverlapping")
                || (path.ends_with("::copy_to_nonoverlapping") && is_raw_ptr)
                || (path.ends_with("::copy_from_nonoverlapping") && is_raw_ptr);
            let is_copy = is_nonoverlapping
                || path.ends_with("ptr::copy")
                || (path.contains("intrinsics") && path.ends_with("::copy"))
                || (path.ends_with("::copy_to") && is_raw_ptr)
                || (path.ends_with("::copy_from") && is_raw_ptr);
            if !is_copy {
                continue;
            }

            let fn_name = if is_nonnull {
                match () {
                    _ if path.ends_with("::copy_to_nonoverlapping") => "NonNull::copy_to_nonoverlapping",
                    _ if path.ends_with("::copy_from_nonoverlapping") => "NonNull::copy_from_nonoverlapping",
                    _ if path.ends_with("::copy_to") => "NonNull::copy_to",
                    _ if path.ends_with("::copy_from") => "NonNull::copy_from",
                    _ if is_nonoverlapping => "ptr::copy_nonoverlapping",
                    _ => "ptr::copy",
                }
            } else if is_nonoverlapping {
                "ptr::copy_nonoverlapping"
            } else {
                "ptr::copy"
            };
            let extra = if is_nonoverlapping {
                " and that src..src+count*size_of::<T>() and dst..dst+count*size_of::<T>() do not overlap"
            } else {
                ""
            };

            findings.push(Finding {
                rule_id: "ptr_copy",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — verify src and dst are non-null, aligned, and \
                     each backed by at least count*size_of::<T>() valid bytes{extra}"
                ),
            });
        }

        findings
    }
}
