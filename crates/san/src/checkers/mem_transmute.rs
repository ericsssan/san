/// Detects uses of `mem::transmute`.
///
/// `mem::transmute` in MIR is lowered to a `CastKind::Transmute` assignment,
/// not a function call. This checker scans MIR statements for that cast.
///
/// Every transmute is an assertion that two types are layout-compatible
/// (same size, alignment, and valid bit patterns). The compiler checks size,
/// but NOT alignment, validity invariants, or repr-stability.
///
/// Common bugs:
///   • `transmute::<&T, &U>()` — UB if T and U have different alignment
///   • `transmute::<&T, &[u8]>()` — leaks padding bytes, breaks provenance
///   • `transmute::<T, U>()` on `repr(Rust)` types — layout is NOT stable
///   • `transmute::<Fn, usize>()` — function pointer to integer is arch-specific
///
/// Real-world: RUSTSEC-2021-0120 (abomonation), RUSTSEC-2021-0032 (byte_struct),
/// and dozens of FFI boundary crates.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, CastKind, Rvalue, StatementKind};
use rustc_middle::ty::TyCtxt;

pub struct MemTransmute;

impl Checker for MemTransmute {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            for statement in &block_data.statements {
                let StatementKind::Assign(assign) = &statement.kind else { continue };
                let (_, rhs) = &**assign;
                let Rvalue::Cast(CastKind::Transmute, operand, dst_ty) = rhs else { continue };

                let src_ty = operand.ty(&body.local_decls, tcx);
                findings.push(Finding {
                    rule_id: "mem_transmute",
                    severity: Severity::Warning,
                    span: statement.source_info.span,
                    message: format!(
                        "`mem::transmute` (`{src_ty}` → `{dst_ty}`) — verify alignment of \
                         both types, validity of all bit patterns in the target type, and \
                         repr-stability if either type is repr(Rust)"
                    ),
                });
            }
        }

        findings
    }
}
