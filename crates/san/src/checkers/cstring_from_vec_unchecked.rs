/// Detects calls to `CString::from_vec_unchecked` and
/// `CString::from_vec_with_nul_unchecked`.
///
/// Both functions construct a `CString` from a byte vector without validating
/// the C-string invariants, making them `unsafe`:
///
///   • `CString::from_vec_unchecked(v)` — appends a nul terminator and takes
///     ownership; the caller must guarantee that `v` contains **no interior nul
///     bytes** (0x00); if any interior nul is present, C APIs that receive the
///     resulting pointer will silently truncate the string at the first 0x00,
///     leading to logic bugs or security vulnerabilities (e.g., path truncation
///     in file-system calls)
///
///   • `CString::from_vec_with_nul_unchecked(v)` — does NOT append a nul byte;
///     the caller must guarantee BOTH:
///       (a) The last byte is exactly 0x00 (the terminating nul)
///       (b) No interior nul bytes exist before the final 0x00
///     Violating either condition produces a `CString` with an incorrect or
///     missing terminator, which is UB when passed to any C API that reads until
///     the first nul.
///
/// Contrast with the safe `CString::new` (checks for interior nuls and appends
/// terminator) and `CString::from_vec_with_nul` (validates and returns `Result`).
///
/// Common bugs: converting user-supplied or network-received bytes without
/// scanning for embedded nuls, forgetting that `from_vec_with_nul_unchecked`
/// requires the final byte to already be 0x00.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CStringFromVecUnchecked;

impl Checker for CStringFromVecUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("CString::from_vec_unchecked") {
                (
                    "CString::from_vec_unchecked",
                    "the byte vector must contain no interior nul bytes (0x00); any embedded \
                     nul will silently truncate the string when passed to C APIs, causing \
                     logic errors or path-traversal vulnerabilities; use `CString::new` for \
                     the checked alternative",
                )
            } else if path.ends_with("CString::from_vec_with_nul_unchecked") {
                (
                    "CString::from_vec_with_nul_unchecked",
                    "the vector must end with exactly one 0x00 byte and have no interior nuls; \
                     missing or misplaced terminator produces a `CString` that violates C-string \
                     invariants, causing UB in any C API that reads until the first nul; \
                     use `CString::from_vec_with_nul` for the checked alternative",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "cstring_from_vec_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
