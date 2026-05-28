/// Detects calls to `extern "C"` (and other ABI) foreign functions declared
/// within the current workspace crate.
///
/// Every call to a foreign function is unconditionally `unsafe`. The caller must:
///   • Match the C ABI exactly: argument types, sizes, sign, alignment, and
///     calling convention must agree with the foreign declaration; ABI mismatch
///     silently corrupts registers and the stack
///   • Satisfy all preconditions of the foreign API: null-check pointers before
///     passing, ensure buffers are large enough, respect required initialization
///     order (e.g. calling `SSL_library_init` before `SSL_new`)
///   • Manage ownership correctly: C functions that return heap-allocated memory
///     require a paired free call via the *same* allocator; mixing allocators
///     causes mismatched-free crashes
///   • Ensure thread-safety: many C libraries require external locking or are
///     not safe to call concurrently without explicit synchronization
///   • Handle error codes: C conventions return error codes (not Rust Results);
///     ignoring `errno` or return values is a common source of logic errors
///
/// Note: this checker only flags foreign functions declared directly in the
/// workspace crate (`extern "C" { fn ... }` blocks in your code). Calls to
/// foreign functions in dependencies (e.g. libc) are not flagged to avoid noise.
///
/// Common bugs: passing `*mut T` where `*const T` is expected (implicit C const),
/// off-by-one in buffer-size arguments, calling after the C library is torn down,
/// forgetting to null-terminate strings passed to C.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ForeignFn;

impl Checker for ForeignFn {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            if !tcx.is_foreign_item(def_id) {
                continue;
            }
            // Only flag foreign functions declared in the current crate to
            // avoid noise from libc / system-call wrappers in dependencies.
            if !def_id.is_local() {
                continue;
            }

            let path = tcx.def_path_str(def_id);
            findings.push(Finding {
                rule_id: "foreign_fn",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{path}` is a foreign (`extern`) function — verify ABI match, pointer \
                     validity, buffer sizes, ownership transfer, error-code handling, and \
                     thread-safety per the foreign API contract"
                ),
            });
        }

        findings
    }
}
