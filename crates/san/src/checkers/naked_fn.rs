/// Detects functions annotated with `#[unsafe(naked)]` (stable since Rust 1.88).
///
/// A naked function suppresses the compiler-generated prologue and epilogue.
/// The `naked_asm!` body must manually implement the FULL calling convention:
///
///   • Arguments are in the exact registers/stack locations dictated by the
///     ABI declared by the `extern "ABI"` qualifier (e.g. "C", "sysv64",
///     "win64"). The programmer must load them correctly.
///   • Return values must be placed in the correct register(s) before the
///     return instruction (e.g. `ret` on x86/aarch64).
///   • Callee-saved registers (e.g. rbx, rbp, r12-r15 on x86-64 SysV ABI;
///     x19-x28, x29, x30 on AArch64) must be saved and restored by the asm.
///   • The stack must be 16-byte aligned at the call site on most ABIs.
///   • No stack probe is emitted — functions that use large local buffers
///     in the inline asm must probe the stack manually (Windows requirement).
///
/// Incorrect implementation causes undefined behaviour at the call site —
/// corrupted registers, wrong return values, stack misalignment, or crashes.
///
/// The `naked_asm!` block inside is also flagged by the `inline_asm` rule;
/// this rule additionally flags the function definition itself to remind
/// callers and authors about the full ABI contract.
///
/// Stable since Rust 1.88. Prior versions required `#![feature(naked_functions)]`.
use crate::{Checker, Finding, Severity};
use rustc_hir::def::DefKind;
use rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags;
use rustc_middle::ty::TyCtxt;

pub struct NakedFn;

impl Checker for NakedFn {
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for &local_def_id in tcx.mir_keys(()).iter() {
            let def_id = local_def_id.to_def_id();
            match tcx.def_kind(def_id) {
                DefKind::Fn | DefKind::AssocFn => {}
                _ => continue,
            }

            let attrs = tcx.codegen_fn_attrs(def_id);
            if !attrs.flags.contains(CodegenFnAttrFlags::NAKED) {
                continue;
            }

            let fn_name = tcx.def_path_str(def_id);
            let span = tcx.def_span(def_id);

            findings.push(Finding {
                rule_id: "naked_fn",
                severity: Severity::Warning,
                span,
                message: format!(
                    "`{fn_name}` is a naked function — `naked_asm!` body must fully \
                     implement the declared ABI ({abi}): place return values in the \
                     correct registers, save/restore callee-saved registers, and \
                     maintain stack alignment; incorrect ABI implementation is UB at \
                     every call site",
                    abi = if tcx.fn_sig(def_id).skip_binder().abi().name() == "Rust" {
                        "Rust ABI".to_string()
                    } else {
                        format!("extern \"{}\" ABI", tcx.fn_sig(def_id).skip_binder().abi().name())
                    }
                ),
            });
        }

        findings
    }
}
