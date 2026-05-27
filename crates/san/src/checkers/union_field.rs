/// Detects reads and writes to union fields.
///
/// Accessing a union field in Rust is unsafe because the compiler cannot
/// verify that the stored bytes are valid for the type of the field being
/// accessed. The caller must guarantee:
///   • The union was last written through a field whose type is the same size
///     and alignment, OR the bit-pattern currently stored is valid for the
///     type of the field being read
///   • Reading a field whose invariants are violated is immediate UB:
///     - `bool` requires 0 or 1, not any byte value
///     - References must be non-null, aligned, and point to valid, live memory
///     - Enums require a valid discriminant
///     - Any type with padding may leave uninit bytes if a differently-sized
///       field was last written
///
/// Type-confusion pattern: writing an integer field to set bytes, then reading
/// a pointer field as if it were a valid address.
///
/// RustSec: RUSTSEC-2023-0045 (memoffset) shows how incorrect assumptions
/// about union layout leads to reads from uninitialized memory.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, PlaceTy, ProjectionElem, Rvalue, StatementKind};
use rustc_middle::ty::{TyCtxt, TyKind};

pub struct UnionField;

fn is_union_field_place<'tcx>(
    place: rustc_middle::mir::Place<'tcx>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
) -> bool {
    let mut place_ty = PlaceTy::from_ty(body.local_decls[place.local].ty);
    for elem in place.projection.iter() {
        if matches!(elem, ProjectionElem::Field(..)) {
            if let TyKind::Adt(adt_def, _) = place_ty.ty.kind() {
                if adt_def.is_union() {
                    // Ignore unions from the standard library (MaybeUninit, etc.)
                    // which appear as false positives when inlined into user code.
                    let krate_name = tcx.crate_name(adt_def.did().krate);
                    let krate = krate_name.as_str();
                    if matches!(krate, "core" | "alloc" | "std") {
                        return false;
                    }
                    return true;
                }
            }
        }
        place_ty = place_ty.projection_ty(tcx, elem);
    }
    false
}

impl Checker for UnionField {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            for statement in &block_data.statements {
                let StatementKind::Assign(assign) = &statement.kind else { continue };
                let (lhs, rhs) = &**assign;
                let span = statement.source_info.span;

                // Write to a union field
                if is_union_field_place(*lhs, body, tcx) {
                    findings.push(Finding {
                        rule_id: "union_field",
                        severity: Severity::Warning,
                        span,
                        message: "union field write — the stored bytes may be reinterpreted \
                                  through a different field; ensure the written type's bit-pattern \
                                  is valid for all subsequent field reads"
                            .to_string(),
                    });
                }

                // Read from a union field (appears as Copy/Move operand in RHS)
                let read_place = match rhs {
                    Rvalue::Use(operand, _) => match operand {
                        Operand::Copy(p) | Operand::Move(p) => Some(*p),
                        _ => None,
                    },
                    Rvalue::Ref(_, _, p) => Some(*p),
                    Rvalue::RawPtr(_, p) => Some(*p),
                    _ => None,
                };
                if let Some(place) = read_place {
                    if is_union_field_place(place, body, tcx) {
                        findings.push(Finding {
                            rule_id: "union_field",
                            severity: Severity::Warning,
                            span,
                            message: "union field read — verify the stored bytes are valid for \
                                      the accessed field's type; reading a field whose invariants \
                                      are not satisfied is UB (invalid bool, dangling reference, \
                                      invalid enum discriminant, etc.)"
                                .to_string(),
                        });
                    }
                }
            }
        }

        findings
    }
}
