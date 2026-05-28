/// Detects calls to `http::HeaderValue::from_maybe_shared_unchecked`.
///
/// `HeaderValue::from_maybe_shared_unchecked<T: AsRef<[u8]> + 'static>(src: T)`:
///   • Creates an HTTP header value without validating that the bytes contain
///     only visible ASCII characters and SP/HTAB (RFC 7230 §3.2.6)
///   • Bytes outside the valid range (`\x00–\x08`, `\x0A–\x1F`, `\x7F–\xFF`)
///     can be injected into HTTP headers
///   • A `\r\n` sequence in the value enables HTTP header injection — an attacker
///     can append arbitrary headers or split the HTTP response (CRLF injection)
///   • In debug builds the function panics on invalid bytes; in release builds
///     the validation is completely skipped — a security-relevant divergence
///
/// Safe alternatives:
///   • `HeaderValue::from_bytes(&[u8])` — validates on every call, returns `Err`
///   • `HeaderValue::from_str(&str)` — same, accepts only visible ASCII
///   • `HeaderValue::from_static(&'static str)` — compile-time checked constant
///
/// References: RUSTSEC-2021-0018 (HTTP response splitting in `hyper`), CVE-2023-45311.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HttpUnchecked;

impl Checker for HttpUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if path != "http::HeaderValue::from_maybe_shared_unchecked"
                && !(path.ends_with("::from_maybe_shared_unchecked")
                    && path.contains("HeaderValue"))
            {
                continue;
            }

            findings.push(Finding {
                rule_id: "http_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`HeaderValue::from_maybe_shared_unchecked` — skips byte validation; \
                     bytes outside visible ASCII or containing \\r\\n enable HTTP header \
                     injection (CRLF injection / response splitting); in release builds the \
                     debug-mode panic is silently absent; use from_bytes() or from_str() instead"
                    .to_string(),
            });
        }

        findings
    }
}
