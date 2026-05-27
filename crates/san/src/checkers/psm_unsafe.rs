/// Detects calls to `psm::on_stack` and `psm::replace_stack` — low-level
/// stack-switching primitives that execute code on a caller-provided memory region.
///
/// `psm::on_stack(base, size, callback) -> R`:
///   • Switches the CPU stack pointer to `[base, base + size)` for the
///     duration of `callback`, then restores the original stack on return
///   • Safety requirements:
///     - `base` must point to a valid, writable, exclusively-owned memory region
///       of at least `size` bytes aligned to the platform's stack alignment
///       (typically 16 bytes on x86-64/aarch64)
///     - `size` must be large enough for the deepest call frame inside `callback`
///       plus any OS/signal handler overhead — undersized stacks silently corrupt
///       adjacent memory or trigger a segfault
///     - The memory region must remain valid for the entire duration of the call
///     - No other thread may read or write the region while it is used as a stack
///   • Stack overflow within `callback` is undetectable and causes silent UB
///     (the overflow writes over whatever follows the buffer in memory)
///
/// `psm::replace_stack(base, size, callback) -> !`:
///   • Like `on_stack` but never returns — the original stack is abandoned
///   • Any data owned by the caller (local variables, heap allocations via RAII)
///     that lives beyond the call point will leak because destructors are skipped
///   • If `callback` itself returns, behavior is undefined
///
/// These functions are used to implement green-thread runtimes, coroutine
/// libraries (e.g., `stacker`, `corosensei`, `context`), and recursive descent
/// parsers that need bounded stack depth. Direct use by application code is rare
/// and almost always indicates a need for rigorous stack-size analysis.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PsmUnsafe;

impl Checker for PsmUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.starts_with("psm::") {
                continue;
            }

            let (fn_name, note) = if path == "psm::on_stack" {
                (
                    "psm::on_stack",
                    "executes `callback` on a caller-provided stack region; `base` must point \
                     to a valid, exclusively-owned, properly-aligned buffer of at least `size` \
                     bytes; undersized or misaligned stacks silently corrupt adjacent memory; \
                     stack overflow within the callback is undetectable and causes UB",
                )
            } else if path == "psm::replace_stack" {
                (
                    "psm::replace_stack",
                    "switches to the provided stack and never returns — all RAII destructors \
                     on the original stack are skipped (leaking owned resources); `callback` \
                     must not return (doing so is UB); `base` must point to a valid, \
                     exclusively-owned, aligned buffer of at least `size` bytes",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "psm_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
