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
use crate::analysis::state::FreedKind;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, InlineAsmOperand, Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};

pub struct InlineAsm;

impl Checker for InlineAsm {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::InlineAsm { operands, .. } = &terminator.kind else { continue };

            // Check In/InOut operands for freed raw pointers.
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                let mut uaf_found = false;
                for op in operands.iter() {
                    let value = match op {
                        InlineAsmOperand::In { value, .. } => Some(value),
                        InlineAsmOperand::InOut { in_value, .. } => Some(in_value),
                        _ => None,
                    };
                    let Some(val) = value else { continue };
                    let Some(local) = (match val {
                        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                        _ => None,
                    }) else { continue };
                    if !matches!(body.local_decls[local].ty.kind(), TyKind::RawPtr(..)) {
                        continue;
                    }
                    match state.freed_kind(local) {
                        FreedKind::Definite => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", false));
                            uaf_found = true;
                        }
                        FreedKind::Potential => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", true));
                            uaf_found = true;
                        }
                        FreedKind::NotFreed => {}
                    }
                }
                if uaf_found { continue; }
            }

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
