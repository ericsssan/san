/// Detects calls to `str::from_utf8_unchecked`, `str::from_utf8_unchecked_mut`,
/// `String::from_utf8_unchecked`, `str::from_boxed_utf8_unchecked`,
/// `str::from_raw_parts`, and `str::from_raw_parts_mut`.
///
/// All of these create `&str`/`&mut str`/`Box<str>` without validating UTF-8.
/// The caller must guarantee:
///   • The bytes contain valid UTF-8 (all Rust code assumes this invariant)
///   • Violating this is immediate undefined behaviour — rustc and LLVM assume
///     &str always contains valid UTF-8 and may exploit this for optimizations
///
/// `str::from_raw_parts` / `str::from_raw_parts_mut` additionally require:
///   • The pointer must be non-null, properly aligned, and valid for `len` bytes
///   • The memory must remain valid and unmodified for the lifetime of the &str
///   (Nightly: `#![feature(str_from_raw_parts)]`)
///
/// Common bugs:
///   • Passing bytes from untrusted input (FFI, network, files) without validation
///   • Slicing at byte offsets that fall inside a multi-byte UTF-8 sequence
///   • Assuming ASCII-only inputs are safe without enforcing it at the API boundary
///
/// The safe alternative is `str::from_utf8` which returns a Result.
///
/// RustSec: RUSTSEC-2021-0079 (through various FFI string conversion crates).
use crate::analysis::state::FreedKind;
use crate::analysis::transfer::first_arg_local;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct StrFromUtf8Unchecked;

impl Checker for StrFromUtf8Unchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let fn_name = if path.ends_with("str::from_utf8_unchecked_mut")
                || (path.ends_with("from_utf8_unchecked_mut") && path.contains("str"))
            {
                "str::from_utf8_unchecked_mut"
            } else if path.ends_with("str::from_utf8_unchecked")
                || (path.ends_with("from_utf8_unchecked") && path.contains("str")
                    && !path.contains("String"))
            {
                "str::from_utf8_unchecked"
            } else if path.ends_with("String::from_utf8_unchecked")
                || (path.ends_with("::from_utf8_unchecked") && path.contains("String"))
            {
                "String::from_utf8_unchecked"
            } else if path.ends_with("str::from_boxed_utf8_unchecked") {
                "str::from_boxed_utf8_unchecked"
            } else if path.ends_with("str::from_raw_parts_mut")
                || (path.ends_with("from_raw_parts_mut") && path.contains("str::"))
            {
                "str::from_raw_parts_mut"
            } else if path.ends_with("str::from_raw_parts")
                || (path.ends_with("from_raw_parts") && path.contains("str::")
                    && !path.contains("slice::"))
            {
                "str::from_raw_parts"
            } else {
                continue;
            };

            let message = if fn_name.starts_with("str::from_raw_parts") {
                format!(
                    "`{fn_name}` — ptr must be non-null, aligned for u8, valid for `len` bytes, \
                     and the byte sequence must be valid UTF-8; invalid UTF-8 is immediate UB; \
                     the lifetime must not outlive the allocation \
                     (nightly: `#![feature(str_from_raw_parts)]`)"
                )
            } else {
                format!(
                    "`{fn_name}` — bytes must be valid UTF-8; use `str::from_utf8` \
                     (returns Result) unless provably ASCII or already validated upstream"
                )
            };

            // For the `from_raw_parts` variants (which take a raw `*const u8` /
            // `*mut u8`), escalate to a precise UAF when that pointer was already
            // reconstituted/freed on a reaching path. The byte-slice variants take
            // an owned/borrowed slice, not a freeable raw pointer, so they keep the
            // UTF-8-validity audit finding.
            if fn_name.starts_with("str::from_raw_parts") {
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    if let Some(arg_local) = first_arg_local(args) {
                        match state.freed_kind(arg_local) {
                            FreedKind::Definite => {
                                findings.push(crate::checkers::uaf::uaf_finding(
                                    terminator.source_info.span, "read", false));
                                continue;
                            }
                            FreedKind::Potential => {
                                findings.push(crate::checkers::uaf::uaf_finding(
                                    terminator.source_info.span, "read", true));
                                continue;
                            }
                            FreedKind::NotFreed => {}
                        }
                    }
                }
            }

            findings.push(Finding {
                rule_id: "str_from_utf8_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
