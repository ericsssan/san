/// Detects calls to the "fast" floating-point arithmetic intrinsics:
/// `fadd_fast`, `fsub_fast`, `fmul_fast`, `fdiv_fast`, and `frem_fast`.
///
/// These intrinsics correspond to LLVM's `fast` floating-point flag set,
/// which tells the optimizer to assume:
///   • No NaN inputs or outputs (`nnan`)
///   • No Infinity inputs or outputs (`ninf`)
///   • No negative-zero inputs or outputs (`nsz`)
///   • Plus additional algebraic reassociation and reciprocal approximation rights
///
/// Violating these assumptions is **undefined behaviour**: the optimizer may
/// eliminate branches, hoist operations out of loops, fuse multiply-add pairs,
/// or produce poison values that propagate silently through subsequent
/// computations.  Notably:
///   • `fadd_fast(f64::NAN, 1.0)` — UB: operand is NaN
///   • `fdiv_fast(1.0, 0.0)` — UB: result is Inf; the optimizer may assume
///     the division is always finite and produce wrong results elsewhere
///   • `fsub_fast(0.0, 0.0)` — UB: result is negative zero in IEEE 754 but
///     `nsz` allows the optimizer to treat it as positive zero
///
/// These are nightly intrinsics, available via `#![feature(core_intrinsics)]`.
/// The stable alternative is `f32::fadd_fast` / `f64::fadd_fast` from the
/// unstable `float_algebraic` feature, or simply using regular `+`/`-`/`*`/`/`
/// and relying on `#[allow(clippy::float_arithmetic)]`.
///
/// Common bugs: using with user-supplied inputs that may be NaN/Inf,
/// reading from FFI or network data without range-checking, sensor noise
/// producing NaN in embedded systems code.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct FastFloatArith;

impl Checker for FastFloatArith {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("fadd_fast") {
                (
                    "fadd_fast",
                    "both operands must be finite and non-NaN; uses LLVM `fast` flags \
                     (nnan + ninf + nsz), allowing the optimizer to assume finite results; \
                     NaN or Inf inputs are UB (nightly `core_intrinsics`)",
                )
            } else if path.ends_with("fsub_fast") {
                (
                    "fsub_fast",
                    "both operands must be finite and non-NaN; the optimizer may assume \
                     the result is never ±Inf or NaN; UB if either operand violates this \
                     (nightly `core_intrinsics`)",
                )
            } else if path.ends_with("fmul_fast") {
                (
                    "fmul_fast",
                    "both operands must be finite and non-NaN; multiplicative overflow to ±Inf \
                     is UB because the optimizer assumes finite results \
                     (nightly `core_intrinsics`)",
                )
            } else if path.ends_with("fdiv_fast") {
                (
                    "fdiv_fast",
                    "both operands must be finite and non-NaN, divisor must be non-zero; \
                     a zero divisor produces ±Inf which is UB under the `ninf` assumption; \
                     the optimizer may miscompile surrounding code on this assumption \
                     (nightly `core_intrinsics`)",
                )
            } else if path.ends_with("frem_fast") {
                (
                    "frem_fast",
                    "both operands must be finite and non-NaN, divisor must be non-zero; \
                     `rem` of a zero divisor is NaN which violates the `nnan` assumption — \
                     UB (nightly `core_intrinsics`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "fast_float_arith",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
