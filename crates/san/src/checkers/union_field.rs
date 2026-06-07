/// Detects reads from union fields, with flow-sensitive variant tracking.
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
/// **Flow precision tiers**:
///   • `Bug` (definite): `active_variant` proves the last write was to a DIFFERENT
///     field — the bytes are certainly not valid for the type being read.
///   • `Warning` (uncertain): no flow evidence about which field is active —
///     traditional audit signal.
///   • Suppressed: `active_variant` proves the last write was to the SAME field
///     (the read is provably safe w.r.t. variant selection).
///
/// Type-confusion pattern: writing an integer field to set bytes, then reading
/// a pointer field as if it were a valid address.
///
/// RustSec: RUSTSEC-2023-0045 (memoffset) shows how incorrect assumptions
/// about union layout leads to reads from uninitialized memory.
use crate::analysis::transfer::direct_union_field_access;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Location, Operand, PlaceTy, ProjectionElem, Rvalue, StatementKind};
use rustc_middle::ty::{TyCtxt, TyKind};

pub struct UnionField;

/// Returns `true` when `place` accesses a field on a user-defined union
/// (i.e. not a stdlib union such as `MaybeUninit` or `ManuallyDrop`).
/// Uses projection-type walking so nested unions (struct.union_field.inner)
/// are also detected.
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
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            for (stmt_idx, statement) in block_data.statements.iter().enumerate() {
                let StatementKind::Assign(assign) = &statement.kind else { continue };
                let (lhs, rhs) = &**assign;
                let span = statement.source_info.span;

                // Write to a union field — always an audit signal regardless of flow.
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

                // Read from a union field: use flow-sensitive active_variant to
                // distinguish definite wrong-variant reads from uncertain ones.
                let read_place = match rhs {
                    Rvalue::Use(operand, _) => match operand {
                        Operand::Copy(p) | Operand::Move(p) => Some(*p),
                        _ => None,
                    },
                    Rvalue::Ref(_, _, p) => Some(*p),
                    Rvalue::RawPtr(_, p) => Some(*p),
                    _ => None,
                };
                let Some(place) = read_place else { continue };
                if !is_union_field_place(place, body, tcx) {
                    continue;
                }

                // Try to look up the flow state just before this statement.
                // If active_variant is known, use it to suppress or escalate.
                let state = flow.state_at_location(
                    tcx,
                    body,
                    Location { block: bb, statement_index: stmt_idx },
                );
                let maybe_active = state.as_ref().and_then(|s| {
                    direct_union_field_access(place, body, tcx)
                        .map(|(base, read_idx)| (s.active_variant.get(&base).copied(), read_idx))
                });

                match maybe_active {
                    Some((Some(active_idx), read_idx)) if active_idx == read_idx => {
                        // Provably reading the same field that was last written — safe.
                        continue;
                    }
                    Some((Some(active_idx), read_idx)) => {
                        // Definite mismatch: last write was to a different field.
                        findings.push(Finding {
                            rule_id: "union_wrong_field",
                            severity: Severity::Error,
                            span,
                            message: format!(
                                "union field read of field {read_idx} but field {active_idx} was \
                                 last written — the stored bytes are not valid for the type of \
                                 field {read_idx}; this is immediate UB (type confusion)"
                            ),
                        });
                    }
                    _ => {
                        // No flow evidence: fall back to the unconditional audit signal.
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
