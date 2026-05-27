/// Detects calls to `OsStr::from_encoded_bytes_unchecked` and
/// `OsString::from_encoded_bytes_unchecked`.
///
/// These functions create an OS string from a raw byte slice without
/// checking platform encoding invariants:
///
///   • **Unix**: the encoding is arbitrary bytes (all sequences valid), so
///     any byte slice is safe on Unix; however, the safety contract is
///     *platform-specific* and code may be used on Windows.
///   • **Windows**: the encoding is WTF-8 (a superset of UTF-8 that allows
///     unpaired surrogates). Bytes that are not valid WTF-8 produce an
///     `OsStr`/`OsString` whose contents violate the encoding invariant;
///     any subsequent operation that relies on WTF-8 validity (conversion
///     to `&str`, printing, path operations) is undefined behaviour.
///
/// The caller must guarantee that the bytes were produced by
/// `OsStr::as_encoded_bytes` on the same platform, or are otherwise known
/// to satisfy the platform's encoding contract.
///
/// Stable since Rust 1.74.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct OsStrEncodedBytes;

impl Checker for OsStrEncodedBytes {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::from_encoded_bytes_unchecked") {
                continue;
            }

            let fn_name = if path.contains("OsString") {
                "OsString::from_encoded_bytes_unchecked"
            } else {
                "OsStr::from_encoded_bytes_unchecked"
            };

            findings.push(Finding {
                rule_id: "osstr_encoded_bytes",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — bytes must satisfy the platform encoding contract \
                     (arbitrary bytes on Unix; WTF-8 on Windows); violating this on \
                     Windows causes UB in any operation that assumes valid WTF-8; \
                     prefer building via OsStr::new or OsString::from"
                ),
            });
        }

        findings
    }
}
