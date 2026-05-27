/// Detects calls to `CStr::from_bytes_with_nul_unchecked`.
///
/// `CStr::from_bytes_with_nul_unchecked(bytes)` creates a `&CStr` from a byte
/// slice without validating the nul-terminator invariant. The caller must:
///   • Ensure the byte slice ends with exactly one `\0` byte (nul terminator);
///     if it does not, any code that traverses or prints the CStr will read past
///     the end of the slice until it finds a `\0` in adjacent memory (buffer overread)
///   • Ensure there are no interior `\0` bytes before the final one; interior nuls
///     cause C functions to treat the string as shorter than intended, silently
///     truncating it — this can bypass input validation or cause logic errors
///   • The returned `&CStr` must not outlive the backing byte slice
///
/// Common bugs: constructing strings from network input with embedded nuls,
/// omitting the trailing `\0`, or creating a CStr from a `&[u8]` that is
/// one byte too short to include the terminator.
///
/// The safe alternative is `CStr::from_bytes_with_nul` which returns a Result.
///
/// RustSec: interior nul bugs appear in RUSTSEC-2022-0055 (libssh2-sys) and
/// various FFI-boundary string handling crates.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CStrFromBytesUnchecked;

impl Checker for CStrFromBytesUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("CStr::from_bytes_with_nul_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "cstr_from_bytes_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`CStr::from_bytes_with_nul_unchecked` — bytes must end with exactly \
                          one \\0 byte and contain no interior nuls; missing terminator causes \
                          buffer overread, interior nuls silently truncate C strings; \
                          use `CStr::from_bytes_with_nul` (returns Result) instead"
                    .to_string(),
            });
        }

        findings
    }
}
