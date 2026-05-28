/// Detects calls to `nix::sys::mman` memory-mapping and memory-protection functions.
///
/// These are thin, type-safe wrappers around POSIX syscalls, but remain `unsafe fn`
/// because all memory-safety invariants are the caller's responsibility:
///
/// `mmap(addr, length, prot, flags, fd, offset)`:
///   • The returned pointer must not alias any existing Rust reference
///   • For file-backed mappings: `fd` must be valid and opened with permissions
///     consistent with `prot`; mapping a closed or invalidated fd is UB
///   • Caller is responsible for calling `munmap` before the backing resource is freed
///
/// `mprotect(addr, len, prot)`:
///   • `addr` must be aligned to the page size and within a live mapping
///   • Stripping `PROT_READ` from a page that contains live Rust references makes
///     all subsequent reads immediate UB (SIGSEGV or silent data corruption)
///   • Stripping `PROT_WRITE` while a `&mut T` exists in the range is also UB
///
/// `munmap(addr, len)`:
///   • Any reference into the unmapped range becomes a dangling pointer (use-after-free)
///   • The length must exactly match the original mapping or a contiguous sub-range
///
/// `mlock(addr, len)` / `munlock(addr, len)`:
///   • Addr must be within a valid mapping; locking/unlocking freed pages is UB
///
/// Common bugs: using the mapped pointer after `munmap`, extending a mapping's
/// lifetime past the `fd` that backs it, aliasing `mmap` output with a `Box<T>`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NixMman;

impl Checker for NixMman {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("nix") || !path.contains("mman") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::mmap") {
                (
                    "nix::sys::mman::mmap",
                    "returned pointer must not alias any Rust reference; for file-backed \
                     mappings, fd must remain valid and compatible with prot for the \
                     mapping's lifetime; call munmap before the backing resource is freed",
                )
            } else if path.ends_with("::mprotect") {
                (
                    "nix::sys::mman::mprotect",
                    "addr must be page-aligned and within a live mapping; stripping \
                     PROT_READ/PROT_WRITE while a live Rust reference covers the range \
                     is immediate UB (dangling reference on next access)",
                )
            } else if path.ends_with("::munmap") {
                (
                    "nix::sys::mman::munmap",
                    "all references and pointers into the unmapped range become dangling \
                     after this call; any subsequent access is use-after-free; ensure no \
                     live Rust borrows cover the range at the time of unmap",
                )
            } else if path.ends_with("::mlock") {
                (
                    "nix::sys::mman::mlock",
                    "addr and len must correspond to a valid live mapping; \
                     locking pages outside an active mapping is UB",
                )
            } else if path.ends_with("::munlock") {
                (
                    "nix::sys::mman::munlock",
                    "addr and len must correspond to a previously locked live mapping; \
                     unlocking pages that were not locked or are already freed is UB",
                )
            } else if path.ends_with("::madvise") {
                (
                    "nix::sys::mman::madvise",
                    "addr must be within a valid mapping; MADV_DONTNEED on a range \
                     covered by live Rust references effectively frees the pages — \
                     subsequent accesses are reads from zero-filled or recycled pages",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "nix_mman",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
