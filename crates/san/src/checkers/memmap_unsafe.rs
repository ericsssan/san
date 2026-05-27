/// Detects calls to `memmap2::Mmap::map`, `MmapMut::map_mut`,
/// `MmapOptions::map`, `MmapOptions::map_exec`, `MmapOptions::map_copy`,
/// `MmapOptions::map_copy_read_only`, `Mmap::remap`, `MmapMut::remap`,
/// `Mmap::unchecked_advise`, `Mmap::unchecked_advise_range`,
/// `MmapMut::unchecked_advise`, and `MmapMut::unchecked_advise_range`.
///
/// Memory-mapped files are inherently unsound in Rust when the underlying file
/// can be concurrently modified. The Rust memory model guarantees that `&[u8]`
/// is immutable — but a file-backed mmap can be changed by another process or
/// thread without Rust's knowledge, silently invalidating this guarantee.
///
/// All `memmap2` constructors are `unsafe` for this reason.
///
/// **Safety requirements for all file-backed maps:**
///   • The mapped file must not be written by any other process, thread, or I/O
///     operation for the entire lifetime of the `Mmap`/`MmapMut` object
///   • The file must not be truncated while the map is open — accessing bytes
///     beyond the new EOF triggers SIGBUS on Linux (UB in Rust)
///   • The file descriptor must remain valid (not closed) for the map's lifetime
///
/// **Additional requirements for `map_exec`:**
///   • The mapped file must not be writable by any untrusted principal — if an
///     attacker can modify the mapped file, they can inject arbitrary code
///
/// **`remap` (Linux-only `mremap`):**
///   • Extending past the current file size maps unmapped memory → SIGBUS / UB
///   • The new length must be within the backing file's size
///
/// **`unchecked_advise` / `unchecked_advise_range`:**
///   • Uses `madvise(2)` flags that the checked variants reject (e.g., MADV_FREE,
///     MADV_WIPEONFORK); MADV_FREE silently invalidates pages — subsequent reads
///     may return zeros even if the data was previously written
///   • `unchecked_advise_range(offset, len)`: offset + len must not exceed the
///     map's length; out-of-bounds advise is UB
///
/// Canonical misuse pattern (RUSTSEC-2025-0132): wrapping a `memmap2` constructor
/// in a function not marked `unsafe`, omitting the file-stability requirement
/// from the safety invariant.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MemmapUnsafe;

impl Checker for MemmapUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("memmap2") && !path.contains("Mmap") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::unchecked_advise_range")
                && (path.contains("Mmap") || path.contains("memmap2"))
            {
                (
                    "Mmap::unchecked_advise_range",
                    "offset + len must not exceed the map length (UB otherwise); unchecked \
                     madvise flags like MADV_FREE can silently zero pages on subsequent read",
                )
            } else if path.ends_with("::unchecked_advise")
                && (path.contains("Mmap") || path.contains("memmap2"))
            {
                (
                    "Mmap::unchecked_advise",
                    "allows madvise flags rejected by the safe variant (e.g., MADV_FREE); \
                     MADV_FREE silently discards dirty pages — subsequent reads may return zeros \
                     even for previously-written data",
                )
            } else if path.ends_with("::remap")
                && (path.contains("Mmap") || path.contains("memmap2"))
            {
                (
                    "Mmap::remap",
                    "new length must not exceed the backing file's size — mapping past EOF \
                     triggers SIGBUS (UB) on access; Linux-only mremap call",
                )
            } else if path.ends_with("::map_copy_read_only")
                && (path.contains("Mmap") || path.contains("MmapOptions") || path.contains("memmap2"))
            {
                (
                    "MmapOptions::map_copy_read_only",
                    "copy-on-write read-only map — if the file is modified before a CoW fault, \
                     mapped bytes may change; the file must not be concurrently truncated",
                )
            } else if path.ends_with("::map_copy")
                && (path.contains("Mmap") || path.contains("MmapOptions") || path.contains("memmap2"))
            {
                (
                    "MmapOptions::map_copy",
                    "copy-on-write writable map — file must not be concurrently modified or \
                     truncated for the lifetime of the mapping",
                )
            } else if path.ends_with("::map_exec")
                && (path.contains("Mmap") || path.contains("MmapOptions") || path.contains("memmap2"))
            {
                (
                    "MmapOptions::map_exec",
                    "executable map — if the file is writable by an untrusted principal, an \
                     attacker can inject arbitrary code; file must not be modified or truncated \
                     while the map is live",
                )
            } else if path.ends_with("::map_mut")
                && (path.contains("Mmap") || path.contains("MmapMut") || path.contains("memmap2"))
            {
                (
                    "MmapMut::map_mut",
                    "writable file-backed map — another process or thread writing to the same \
                     file concurrently creates a data race (Rust assumes &mut [u8] is exclusively \
                     owned); file must not be truncated while the map is open",
                )
            } else if (path.ends_with("Mmap::map") || path.ends_with("::map"))
                && (path.contains("Mmap") || path.contains("MmapOptions") || path.contains("memmap2"))
                && !path.ends_with("::map_mut")
                && !path.ends_with("::map_exec")
                && !path.ends_with("::map_copy")
            {
                (
                    "Mmap::map",
                    "file-backed read-only map — another process modifying the underlying file \
                     silently changes the bytes seen through the &[u8] slice, violating Rust's \
                     immutability guarantee; file must not be truncated while the map is open",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "memmap_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
