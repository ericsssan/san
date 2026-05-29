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
///
/// Flow extension: if `src` or `dst` is a pointer whose allocation was freed
/// or invalidated by a reallocation (stale pointer), the copy is a
/// use-after-free — emitted as `use_after_free` in that case.
use crate::analysis::state::FreedKind;
use crate::analysis::transfer::first_arg_local;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Location, NonDivergingIntrinsic, Operand, StatementKind, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrCopy;

/// For a `ptr::copy(src, dst, count)` or `copy_nonoverlapping(src, dst, count)`:
/// check whether `src` or `dst` is a stale pointer, emitting `use_after_free`
/// if so, and falling through to the generic `ptr_copy` audit finding otherwise.
fn check_for_uaf<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    flow: &crate::analysis::FlowResults,
    location: Location,
    span: rustc_span::Span,
    src: Option<rustc_middle::mir::Local>,
    dst: Option<rustc_middle::mir::Local>,
    findings: &mut Vec<Finding>,
) -> bool {
    let Some(state) = flow.state_at_location(tcx, body, location) else { return false };
    let mut found_uaf = false;
    for (local, dir) in [(src, "read"), (dst, "write")] {
        let Some(l) = local else { continue };
        match state.freed_kind(l) {
            FreedKind::Definite => {
                findings.push(uaf_finding(span, dir, false));
                found_uaf = true;
            }
            FreedKind::Potential => {
                findings.push(uaf_finding(span, dir, true));
                found_uaf = true;
            }
            FreedKind::NotFreed => {}
        }
    }
    found_uaf
}

impl Checker for PtrCopy {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            // In optimized/release builds, copy_nonoverlapping may lower to a
            // StatementKind::Intrinsic rather than a TerminatorKind::Call.
            for (si, stmt) in block_data.statements.iter().enumerate() {
                let StatementKind::Intrinsic(intrinsic) = &stmt.kind else { continue };
                let NonDivergingIntrinsic::CopyNonOverlapping(cnc) = intrinsic.as_ref() else { continue };
                let span = stmt.source_info.span;
                let location = Location { block: bb, statement_index: si };
                let src = if let Operand::Copy(p) | Operand::Move(p) = &cnc.src {
                    if p.projection.is_empty() { Some(p.local) } else { None }
                } else { None };
                let dst = if let Operand::Copy(p) | Operand::Move(p) = &cnc.dst {
                    if p.projection.is_empty() { Some(p.local) } else { None }
                } else { None };
                if check_for_uaf(tcx, body, flow, location, span, src, dst, &mut findings) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: "ptr_copy",
                    severity: Severity::Warning,
                    span,
                    message: "`ptr::copy_nonoverlapping` — verify src and dst are non-null, \
                              aligned, each backed by at least count*size_of::<T>() valid bytes, \
                              and that the ranges do not overlap"
                        .to_string(),
                });
            }

            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
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

            // For ptr::copy(src, dst, count): arg 0 = src, arg 1 = dst.
            // For NonNull copy variants the receiver is src or dst — use arg 0 conservatively.
            let src_local = first_arg_local(args);
            let dst_local = if !is_nonnull { args.get(1).and_then(|a| {
                if let Operand::Copy(p) | Operand::Move(p) = &a.node {
                    if p.projection.is_empty() { Some(p.local) } else { None }
                } else { None }
            })} else { None };
            let term_location = Location { block: bb, statement_index: block_data.statements.len() };
            if check_for_uaf(tcx, body, flow, term_location, terminator.source_info.span, src_local, dst_local, &mut findings) {
                continue;
            }

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
