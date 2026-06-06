/// Detects calls to the `ctlz_nonzero` and `cttz_nonzero` intrinsics.
///
/// `ctlz_nonzero(x)` counts leading zeros and `cttz_nonzero(x)` counts
/// trailing zeros in the bit representation of `x`, but both carry the
/// hard precondition that **`x` must not be zero**:
///
///   • On most ISAs (x86/64, AArch64, RISC-V) the hardware instruction
///     (`BSR`, `LZCNT`, `CLZ`, `CTZ`) has implementation-defined or
///     architecture-undefined behaviour when the input is 0
///   • LLVM models the nonzero precondition as a `nneg`/poison-producing
///     intrinsic — passing 0 produces **LLVM poison**, which propagates
///     through any subsequent operation that uses the result, silently
///     corrupting program state
///
/// The safe alternatives:
///   • `u32::leading_zeros(x)` / `u64::leading_zeros(x)` — always
///     well-defined, returns the type bit-width when `x == 0`
///   • `NonZeroU32::leading_zeros(&self)` / `NonZeroU64::leading_zeros` —
///     safe because the NonZero type statically prevents 0
///   • `u32::trailing_zeros(x)` / `u64::trailing_zeros(x)` — analogous
///
/// These are nightly intrinsics available via `#![feature(core_intrinsics)]`.
///
/// Common bugs: computing `ctlz_nonzero(bitmask)` where the bitmask can
/// be zero when no bits are set (e.g., in event-loop or bitset iteration
/// code), or computing `cttz_nonzero(round_up(x))` without verifying `x > 0`.
use crate::analysis::transfer::first_arg_local;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CtlzNonzero;

impl Checker for CtlzNonzero {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("ctlz_nonzero") {
                (
                    "ctlz_nonzero",
                    "input must be non-zero; passing 0 produces LLVM poison that propagates \
                     silently through subsequent computations; safe alternative: \
                     `u32::leading_zeros()` or `NonZeroU32::leading_zeros()` \
                     (nightly `core_intrinsics`)",
                )
            } else if path.ends_with("cttz_nonzero") {
                (
                    "cttz_nonzero",
                    "input must be non-zero; passing 0 produces LLVM poison; \
                     safe alternative: `u32::trailing_zeros()` or `NonZeroU32::trailing_zeros()` \
                     (nightly `core_intrinsics`)",
                )
            } else {
                continue;
            };

            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(arg) = first_arg_local(args) {
                    if state.local_is_nonzero(arg) { continue; }
                }
            }

            findings.push(Finding {
                rule_id: "ctlz_nonzero",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
