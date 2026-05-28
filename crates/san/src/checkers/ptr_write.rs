/// Detects calls to `ptr::write`, `ptr::write_unaligned`, `ptr::write_bytes`,
/// `ptr::replace`, `NonNull::write`, `NonNull::replace`, `NonNull::write_bytes`,
/// `NonNull::write_volatile`, and `NonNull::write_unaligned`.
/// (For `ptr::swap` and `ptr::swap_nonoverlapping` see the `ptr_swap` rule.)
///
/// `ptr::write` overwrites memory at a raw pointer without reading the old value,
/// so it does NOT drop the previous contents. The caller must:
///   • Ensure `dst` is non-null and valid for writes of size_of::<T>() bytes
///   • Ensure `dst` is properly aligned for T (`write` only; `write_unaligned` relaxes this)
///   • Accept that the previous value at `dst` is not dropped — leaks if it was initialized
///   • For `write_bytes`: all bytes in the written range become the given byte pattern,
///     which may leave typed values in an invalid state
///
/// Common bugs: writing to already-initialized memory without dropping first
/// (leak), misaligned writes (SIGBUS on some targets, silent UB on others),
/// out-of-range writes past the end of an allocation.
///
/// Seen across: RUSTSEC-2020-0071 (bumpalo), custom allocators, FFI buffers.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrWrite;

impl Checker for PtrWrite {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, message) = if path.ends_with("::write_volatile") && path.contains("mut_ptr") {
                (
                    "ptr::write_volatile",
                    "`ptr::write_volatile` — dst must be non-null, aligned, and a valid \
                     hardware address; does NOT provide atomic ordering — not safe for \
                     concurrent access without additional synchronization; previous value \
                     at dst is NOT dropped"
                        .to_string(),
                )
            } else if path.ends_with("ptr::write_bytes") {
                (
                    "ptr::write_bytes",
                    "`ptr::write_bytes` — verify dst is non-null, aligned, and valid for \
                     count*size_of::<T>() bytes; leaves typed values in potentially invalid \
                     states — only safe to use on MaybeUninit or to zero-init plain-data types"
                        .to_string(),
                )
            } else if path.ends_with("ptr::write_unaligned") {
                (
                    "ptr::write_unaligned",
                    "`ptr::write_unaligned` — verify dst is non-null and valid for \
                     size_of::<T>() bytes; previous value at dst is NOT dropped (memory leak \
                     if initialized)"
                        .to_string(),
                )
            } else if path.ends_with("ptr::write") {
                (
                    "ptr::write",
                    "`ptr::write` — verify dst is non-null, properly aligned, and valid for \
                     size_of::<T>() bytes; previous value at dst is NOT dropped (memory leak \
                     if initialized)"
                        .to_string(),
                )
            } else if path.ends_with("ptr::replace") {
                (
                    "ptr::replace",
                    "`ptr::replace` — dst must be non-null, aligned, and valid; returns the \
                     old value (ownership transferred to caller — must be dropped or used)"
                        .to_string(),
                )
            } else if path.ends_with("::write") && path.contains("NonNull") {
                (
                    "NonNull::write",
                    "`NonNull::write` — dst must be properly aligned for T and valid for \
                     size_of::<T>() bytes; previous value at dst is NOT dropped (leak if initialized)"
                        .to_string(),
                )
            } else if path.ends_with("::replace") && path.contains("NonNull") {
                (
                    "NonNull::replace",
                    "`NonNull::replace` — dst must be non-null, aligned, and valid; \
                     returns the old value (caller owns it and must drop it)"
                        .to_string(),
                )
            } else if path.ends_with("::write_bytes") && path.contains("NonNull") {
                (
                    "NonNull::write_bytes",
                    "`NonNull::write_bytes` — verify dst is non-null and valid for \
                     count*size_of::<T>() bytes; leaves typed values in potentially \
                     invalid states — only safe on MaybeUninit or for zero-init of plain-data types"
                        .to_string(),
                )
            } else if path.ends_with("::write_volatile") && path.contains("NonNull") {
                (
                    "NonNull::write_volatile",
                    "`NonNull::write_volatile` — pointer must be non-null (guaranteed), properly \
                     aligned, and a valid hardware address; does NOT provide atomic ordering; \
                     previous value at dst is NOT dropped"
                        .to_string(),
                )
            } else if path.ends_with("::write_unaligned") && path.contains("NonNull") {
                (
                    "NonNull::write_unaligned",
                    "`NonNull::write_unaligned` — pointer must be non-null (guaranteed) and valid \
                     for size_of::<T>() bytes; previous value at dst is NOT dropped (leak if initialized)"
                        .to_string(),
                )
            } else if path.ends_with("::write_bytes")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "ptr::write_bytes",
                    "`ptr::write_bytes` — verify dst is non-null, aligned, and valid for \
                     count*size_of::<T>() bytes; leaves typed values in potentially invalid \
                     states — only safe to use on MaybeUninit or to zero-init plain-data types"
                        .to_string(),
                )
            } else if path.ends_with("::write_unaligned")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "ptr::write_unaligned",
                    "`ptr::write_unaligned` — verify dst is non-null and valid for \
                     size_of::<T>() bytes; previous value at dst is NOT dropped (memory leak \
                     if initialized)"
                        .to_string(),
                )
            } else if path.ends_with("::replace")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "ptr::replace",
                    "`ptr::replace` — dst must be non-null, aligned, and valid; returns the \
                     old value (ownership transferred to caller — must be dropped or used)"
                        .to_string(),
                )
            } else if path.ends_with("::write")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "ptr::write",
                    "`ptr::write` — verify dst is non-null, properly aligned, and valid for \
                     size_of::<T>() bytes; previous value at dst is NOT dropped (memory leak \
                     if initialized)"
                        .to_string(),
                )
            } else {
                continue;
            };

            let _ = fn_name;
            findings.push(Finding {
                rule_id: "ptr_write",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
