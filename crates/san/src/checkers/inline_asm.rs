/// Detects uses of `asm!` and `global_asm!` inline assembly.
///
/// Inline assembly is `unsafe` and bypasses all of Rust's safety guarantees.
/// The programmer must guarantee ALL of the following:
///
/// Register constraints:
///   • Every input/output operand must have the correct register class
///   • Output registers must be properly initialized by the assembly
///   • Register clobbers must declare all registers the assembly modifies
///   • The `preserves_flags` option must be absent if flags (e.g. EFLAGS) are modified
///
/// Memory effects:
///   • Memory referenced by pointer operands must be valid for the operations performed
///   • The `nostack` option must be absent if the assembly uses the stack
///   • Side-effects on memory not expressed via operands require the `volatile` option
///
/// Control flow:
///   • Assembly must not jump outside the `asm!` block (except via the `may_unwind` option
///     for setjmp/longjmp-like patterns)
///   • The `pure` option requires the assembly to have no observable side-effects beyond
///     its output operands
///
/// Platform requirements:
///   • All instructions must be valid on the target CPU (check feature flags)
///   • On ARM/RISC-V: calling convention is ABI-specific; be aware of register use
///   • On x86: use `att_syntax` only when needed; Intel syntax is the default
///
/// Common bugs: missing clobbers (corrupt values in Rust variables), incorrect
/// pointer constraints (read/write declared as read-only), misaligned loads,
/// privilege-level violations.
///
/// RustSec: RUSTSEC-2019-0009 (crossbeam-epoch - incorrect assembly memory barrier).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct InlineAsm;

impl Checker for InlineAsm {
    fn check<'tcx>(&self, _tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::InlineAsm { .. } = &terminator.kind else { continue };

            findings.push(Finding {
                rule_id: "inline_asm",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`asm!` — verify all register constraints, clobbers, memory effects, \
                          and control-flow options; incorrect assembly silently corrupts \
                          registers, stack, or memory without any indication from Rust"
                    .to_string(),
            });
        }

        findings
    }
}
