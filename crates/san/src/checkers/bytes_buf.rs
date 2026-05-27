/// Detects unsafe operations on `bytes::BytesMut` and related buffer types.
///
/// **`BufMut::advance_mut(cnt)`**: marks `cnt` uninitialized bytes as initialized without
/// writing them. The first `cnt` bytes of the unfilled region must be written before this
/// call; `cnt` must be <= remaining_mut(). Violating either is UB.
/// Found in: RUSTSEC-2020-0059 (SegFault in bytes when len > capacity).
///
/// **`BytesMut::set_len(len)`**: sets the logical length of the buffer without
/// initializing any bytes. If `len > capacity`, the buffer is extended into unallocated
/// memory (OOB write, UB). If `len > current_len` without initializing the new bytes,
/// subsequent reads access uninitialized memory (UB).
///
/// **`UninitSlice::from_raw_parts_mut(ptr, len)`**: creates an `&mut UninitSlice` from
/// a raw pointer and length without any validity checks. The caller must ensure:
///   • `ptr` is non-null, properly aligned for `u8`, and valid for `len` bytes of writes
///   • The memory is not aliased by any other reference for the lifetime of the slice
///   • `ptr..ptr+len` is within a single allocated object
///
/// **`UninitSlice::as_uninit_slice_mut(&mut self)`**: returns the underlying
/// `&mut [MaybeUninit<u8>]`; reading unwritten bytes from this slice is UB.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BytesBuf;

impl Checker for BytesBuf {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::advance_mut") && path.contains("bytes") {
                (
                    "BufMut::advance_mut",
                    "the first cnt bytes of the unfilled region must be fully initialized BEFORE \
                     this call; unwritten bytes become visible to buffer readers (UB); \
                     cnt must be <= remaining_mut(); prefer put_slice/put_bytes which write and \
                     advance atomically",
                )
            } else if path.ends_with("::set_len") && path.contains("bytes") {
                (
                    "BytesMut::set_len",
                    "sets buffer length without initializing bytes; if len > capacity this \
                     writes into unallocated memory (OOB, UB); if len > current_len without \
                     initialization, future reads access uninitialized memory (UB)",
                )
            } else if path.ends_with("::from_raw_parts_mut") && path.contains("UninitSlice") {
                (
                    "UninitSlice::from_raw_parts_mut",
                    "creates a mutable uninit byte slice from a raw pointer without validity \
                     checks; ptr must be non-null, aligned, valid for len bytes of writes, and \
                     not aliased by any other reference for the slice's lifetime",
                )
            } else if path.ends_with("::as_uninit_slice_mut") && path.contains("UninitSlice") {
                (
                    "UninitSlice::as_uninit_slice_mut",
                    "returns the underlying &mut [MaybeUninit<u8>]; reading any byte that has \
                     not been written is UB — only write through this slice, then call advance_mut",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "bytes_buf",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
