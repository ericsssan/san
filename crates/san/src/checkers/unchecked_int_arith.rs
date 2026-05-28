/// Detects calls to unchecked integer arithmetic operations:
/// `unchecked_add`, `unchecked_sub`, `unchecked_mul`, `unchecked_shl`,
/// `unchecked_shr`, `unchecked_neg`, `unchecked_div`, `unchecked_rem`,
/// `unchecked_div_exact`, `unchecked_shl_exact`, `unchecked_shr_exact`,
/// `unchecked_disjoint_bitor`, `unchecked_funnel_shl`, and `unchecked_funnel_shr`.
///
/// Unlike their checked or wrapping counterparts, these functions are
/// `unsafe` because overflow or an out-of-range shift is **undefined
/// behaviour**, not a panic or a wrapped result:
///
///   • `unchecked_add/sub/mul`: overflow of any signed or unsigned value
///     is UB — the optimizer may assume it cannot happen and eliminate
///     safety-critical branches that follow
///   • `unchecked_shl/shr`: shifting by ≥ bit-width is UB; shifting a
///     zero-sized integer (where bit-width == 0) by any amount is UB
///   • `unchecked_neg`: negating `T::MIN` is UB (no positive counterpart)
///   • `unchecked_div_exact`: divisor must be non-zero AND divide evenly AND
///     not be the `T::MIN / -1` overflow case (nightly `exact_div`)
///   • `unchecked_shl_exact` / `unchecked_shr_exact`: shift amount in range AND
///     no 1-bits in the shifted-out portion (nightly `exact_bitshifts`)
///   • `unchecked_disjoint_bitor`: both operands must have no overlapping 1-bits,
///     i.e. `self & rhs == 0` (nightly `disjoint_bitor`)
///
/// Stable since Rust 1.79 (unsigned) / 1.81 (signed/neg).
/// Analogous to unchecked arithmetic builtins in LLVM IR (`nuw`/`nsw` flags).
///
/// Common bugs: off-by-one that causes unsigned underflow (`unchecked_sub`),
/// multiplicative size computations that overflow on large inputs, forgetting
/// that `i8::MIN.unchecked_neg()` == UB not just "big".
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UncheckedIntArith;

impl Checker for UncheckedIntArith {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("num") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::unchecked_add") {
                (
                    "unchecked_add",
                    "overflow is UB (not a panic or wrap); the optimizer may \
                     eliminate branches guarded by the assumption that addition cannot overflow",
                )
            } else if path.ends_with("::unchecked_sub") {
                (
                    "unchecked_sub",
                    "underflow is UB; unsigned underflow (lhs < rhs) and signed overflow \
                     are both immediate UB — use `checked_sub` or `wrapping_sub` if unsure",
                )
            } else if path.ends_with("::unchecked_mul") {
                (
                    "unchecked_mul",
                    "overflow is UB; multiplicative overflow on size/length values is a \
                     frequent source of allocator bugs (CVE-class: integer overflow → heap OOB)",
                )
            } else if path.ends_with("::unchecked_shl") {
                (
                    "unchecked_shl",
                    "shift amount must be < bit-width of the type; any larger shift is UB \
                     (not masked like `<<` in C — LLVM may produce poison)",
                )
            } else if path.ends_with("::unchecked_shr") {
                (
                    "unchecked_shr",
                    "shift amount must be < bit-width of the type; any larger shift is UB",
                )
            } else if path.ends_with("::unchecked_neg") {
                (
                    "unchecked_neg",
                    "negating T::MIN is UB (no positive counterpart); for i8: \
                     `(-128i8).unchecked_neg()` is immediately undefined behaviour",
                )
            } else if path.ends_with("::unchecked_div") {
                (
                    "unchecked_div",
                    "divisor must be non-zero; dividing by zero is UB (not a panic); \
                     for signed types T::MIN / -1 is also UB (nightly feature `division_unchecked`)",
                )
            } else if path.ends_with("::unchecked_rem") {
                (
                    "unchecked_rem",
                    "divisor must be non-zero; remainder with zero divisor is UB; \
                     for signed types T::MIN % -1 is also UB (nightly feature `division_unchecked`)",
                )
            } else if path.ends_with("::unchecked_div_exact") {
                (
                    "unchecked_div_exact",
                    "divisor must be non-zero, self must be exactly divisible by rhs (no remainder), \
                     and for signed types T::MIN / -1 is UB; all three conditions must hold simultaneously \
                     (nightly feature `exact_div`)",
                )
            } else if path.ends_with("::unchecked_shl_exact") {
                (
                    "unchecked_shl_exact",
                    "shift amount must be < bit-width; additionally the shifted-out bits must all \
                     be zero (no 1-bits lost); both conditions are UB if violated \
                     (nightly feature `exact_bitshifts`)",
                )
            } else if path.ends_with("::unchecked_shr_exact") {
                (
                    "unchecked_shr_exact",
                    "shift amount must be < bit-width; the shifted-out low bits must all be zero; \
                     both conditions are UB if violated \
                     (nightly feature `exact_bitshifts`)",
                )
            } else if path.ends_with("::unchecked_disjoint_bitor") {
                (
                    "unchecked_disjoint_bitor",
                    "self and rhs must have no overlapping set bits (self & rhs == 0); \
                     if any bit is set in both, the result is UB; the compiler uses this \
                     to emit a single OR without masking (nightly feature `disjoint_bitor`)",
                )
            } else if path.ends_with("::unchecked_funnel_shl") {
                (
                    "unchecked_funnel_shl",
                    "shift amount `n` must be < bit-width of the type; a funnel shift \
                     combines two integers `(self, low)` shifted left by `n` bits, \
                     taking the high bits from self and low bits from low; if n >= bit-width, \
                     the result is UB (nightly feature `funnel_shifts`, issue #145686)",
                )
            } else if path.ends_with("::unchecked_funnel_shr") {
                (
                    "unchecked_funnel_shr",
                    "shift amount `n` must be < bit-width of the type; a funnel shift \
                     combines two integers `(self, low)` shifted right by `n` bits; \
                     if n >= bit-width, the result is UB (nightly feature `funnel_shifts`, \
                     issue #145686)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "unchecked_int_arith",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
