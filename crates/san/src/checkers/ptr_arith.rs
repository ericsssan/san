/// Detects pointer arithmetic: `ptr::add`, `ptr::sub`, `ptr::offset`,
/// `ptr::byte_add`, `ptr::byte_sub`, `ptr::byte_offset`,
/// `NonNull::add`, `NonNull::sub`, `NonNull::offset`,
/// `ptr::wrapping_add`, `ptr::wrapping_sub`, `ptr::wrapping_offset`,
/// `ptr::wrapping_byte_add`, `ptr::wrapping_byte_sub`, `ptr::wrapping_byte_offset`,
/// pointer distance measurement: `ptr::offset_from`, `ptr::byte_offset_from`,
/// `ptr::sub_ptr`, `ptr::offset_from_unsigned`, `ptr::byte_offset_from_unsigned`,
/// and `ptr::mask` (nightly `ptr_mask`).
///
/// All non-wrapping advancing variants (`add`, `sub`, `offset`) have strict requirements:
///   • Both the original pointer and the resulting pointer must be within the
///     same allocation (or one byte past its end)
///   • The offset, when multiplied by size_of::<T>(), must not overflow isize
///   • The computed address must not wrap around the address space
///
/// `offset_from(origin)` measures the signed distance between two pointers:
///   • Both self and origin must be derived from the same allocated object
///   • If they belong to different allocations, it is immediate UB
///   • The result is the distance in units of T (not bytes)
///
/// Violating any condition is immediate UB — the compiler may assume it doesn't
/// happen and miscompile the surrounding code.
///
/// The wrapping variants (`wrapping_add`, `wrapping_sub`) compute addresses that
/// may leave the allocation — they are defined in terms of pointer value only
/// and must not be dereferenced unless in-bounds.
///
/// Real-world: RUSTSEC-2026-0133 (auto_vec), RUSTSEC-2022-0079 (elf_rs),
/// RUSTSEC-2025-0106 (orx-pinned-vec) — all involved `sub` going before the
/// start of the allocation.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrArith;

impl Checker for PtrArith {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            // Match raw pointer arithmetic and NonNull::add/sub/offset variants.
            let is_ptr_type = path.contains("const_ptr")
                || path.contains("mut_ptr")
                || path.contains("NonNull");
            if !is_ptr_type {
                continue;
            }

            let message = if path.ends_with("::wrapping_byte_offset") {
                "`ptr::wrapping_byte_offset` (wrapping, byte) — result may be outside the \
                 allocation; must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::wrapping_byte_add") {
                "`ptr::wrapping_byte_add` (wrapping, byte) — result may be outside the \
                 allocation; must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::wrapping_byte_sub") {
                "`ptr::wrapping_byte_sub` (wrapping, byte) — result may be outside the \
                 allocation; must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::wrapping_add") {
                "`ptr::wrapping_add` (wrapping) — result may be outside the allocation; \
                 must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::wrapping_sub") {
                "`ptr::wrapping_sub` (wrapping) — result may be outside the allocation; \
                 must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::wrapping_offset") {
                "`ptr::wrapping_offset` (wrapping) — result may be outside the allocation; \
                 must not be dereferenced unless provably within bounds"
                    .to_string()
            } else if path.ends_with("::add") {
                "`ptr::add` — both original and result must stay within the same \
                 allocation; offset*size_of::<T>() must not overflow isize; \
                 going before the start of an allocation is UB"
                    .to_string()
            } else if path.ends_with("::sub") {
                "`ptr::sub` — both original and result must stay within the same \
                 allocation; offset*size_of::<T>() must not overflow isize; \
                 going before the start of an allocation is UB"
                    .to_string()
            } else if path.ends_with("::offset") {
                "`ptr::offset` — both original and result must stay within the same \
                 allocation; offset*size_of::<T>() must not overflow isize; \
                 going before the start of an allocation is UB"
                    .to_string()
            } else if path.ends_with("::offset_from") {
                "`ptr::offset_from` — both self and origin must point into the same \
                 allocated object; cross-allocation offset_from is immediate UB; \
                 result is in units of T, not bytes"
                    .to_string()
            } else if path.ends_with("::byte_add") {
                "`ptr::byte_add` — result must stay within the same allocation; \
                 byte offset must not overflow isize; going past the end (or before start) is UB"
                    .to_string()
            } else if path.ends_with("::byte_sub") {
                "`ptr::byte_sub` — result must stay within the same allocation; \
                 byte offset must not overflow isize; going before the start of an allocation is UB"
                    .to_string()
            } else if path.ends_with("::byte_offset") {
                "`ptr::byte_offset` — result must stay within the same allocation; \
                 signed byte offset must not overflow isize; going outside the allocation is UB"
                    .to_string()
            } else if path.ends_with("::byte_offset_from") {
                "`ptr::byte_offset_from` — both self and origin must point into the same \
                 allocated object; cross-allocation comparison is immediate UB; \
                 result is in bytes (not T elements)"
                    .to_string()
            } else if path.ends_with("::sub_ptr") {
                "`ptr::sub_ptr` — self must be >= origin and both must point into the same \
                 allocation; cross-allocation subtraction is UB; result is in units of T"
                    .to_string()
            } else if path.ends_with("::offset_from_unsigned") {
                "`ptr::offset_from_unsigned` — self must be >= origin and both must point into \
                 the same allocated object; cross-allocation comparison is UB; result is the \
                 distance in units of T (unsigned)"
                    .to_string()
            } else if path.ends_with("::byte_offset_from_unsigned") {
                "`ptr::byte_offset_from_unsigned` — self must be >= origin and both must point \
                 into the same allocated object; cross-allocation comparison is UB; result is \
                 the distance in bytes (unsigned)"
                    .to_string()
            } else if path.ends_with("::mask") {
                "`ptr::mask` — the resulting pointer must still point into the same allocation \
                 as the original; masking bits that cross allocation boundaries produces a \
                 dangling pointer — any dereference would be UB \
                 (nightly feature `ptr_mask`)"
                    .to_string()
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_arith",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
