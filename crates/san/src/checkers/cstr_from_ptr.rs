/// Detects calls to `CStr::from_ptr` and `CStr::from_bytes_with_nul_unchecked`.
///
/// `CStr::from_ptr(ptr)` creates a &CStr from a C string pointer. The caller must:
///   • `ptr` is non-null and aligned
///   • The memory starting at `ptr` contains a valid, null-terminated C string
///   • The memory must remain valid for the lifetime of the returned &CStr
///   • No mutation of the memory must occur during the lifetime of the &CStr
///
/// Common bugs:
///   • Null pointer from a C API that returns NULL on failure (→ nullptr deref)
///   • Lifetime extension past the allocation (dangling reference)
///   • Strings with embedded null bytes — the CStr ends at the first null,
///     which may silently truncate the data (RUSTSEC-2021-0123 pattern)
///   • Using the returned &CStr after the C API frees the backing buffer
///
/// `CStr::from_bytes_with_nul_unchecked(bytes)`:
///   • Bytes must be null-terminated (last byte must be b'\0')
///   • Bytes must not contain interior null bytes
///
/// `CString::from_vec_unchecked(bytes)`:
///   • Bytes must not contain any null bytes (interior or trailing)
///   • The CString constructor will append the null terminator automatically
///
/// `CString::from_vec_with_nul_unchecked(bytes)`:
///   • Bytes must contain exactly one null byte and it must be the final byte
///
/// `CString::from_raw(ptr)`:
///   • `ptr` must have been returned by `CString::into_raw` from the same allocator
///   • The CString must not be double-freed (calling from_raw twice on the same ptr is UB)
///   • The original CString must have transferred ownership via `into_raw` beforehand
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CStrFromPtr;

impl Checker for CStrFromPtr {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("CStr::from_ptr") {
                (
                    "CStr::from_ptr",
                    "ptr must be non-null, point to a valid null-terminated C string, and \
                     remain valid for the returned &CStr's lifetime; embedded null bytes \
                     silently truncate the string (path injection risk)",
                )
            } else if path.ends_with("CStr::from_bytes_with_nul_unchecked") {
                (
                    "CStr::from_bytes_with_nul_unchecked",
                    "bytes must end with exactly one b'\\0' and contain no interior null bytes; \
                     use CStr::from_bytes_with_nul (returns Result) instead",
                )
            } else if path.ends_with("CString::from_vec_unchecked") {
                (
                    "CString::from_vec_unchecked",
                    "bytes must contain no null bytes (interior or trailing); \
                     use CString::new (returns Result) instead",
                )
            } else if path.ends_with("CString::from_vec_with_nul_unchecked") {
                (
                    "CString::from_vec_with_nul_unchecked",
                    "bytes must contain exactly one null byte and it must be the last byte; \
                     use CString::from_vec_with_nul (returns Result) instead",
                )
            } else if path.ends_with("CString::from_raw") {
                (
                    "CString::from_raw",
                    "ptr must have been returned by CString::into_raw from the same allocator; \
                     calling from_raw twice on the same pointer is double-free UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "cstr_from_ptr",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
