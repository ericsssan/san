/// Detects transmutes from raw pointers to references — a common soundness hole.
///
/// `transmute::<*const T, &T>` and `transmute::<*mut T, &T>` / `&mut T` fabricate
/// a reference from a raw pointer. Unlike `&*ptr` (which the borrow checker
/// validates) these transmutes bypass ALL safety checks:
///   • The pointer may be null, dangling, misaligned, or not live for `'a`.
///   • The fabricated reference's lifetime is unchecked — if the pointer does
///     not point to data that outlives the reference's use site, this is UB.
///   • `*mut T → &mut T` creates an exclusive reference that may alias other
///     `*mut T` or `&T` pointers — violating Rust's aliasing model.
///
/// The canonical lifetime-laundering pattern (`&'a T → &'static T`) is also
/// a transmute but compiles to a plain copy in MIR (lifetimes are erased, the
/// bit representation is identical). That case is invisible here; it is a
/// borrow-checker bypass that only the HIR analysis layer can see. This
/// checker catches the *pointer-to-reference* form, which IS representable
/// in MIR as a distinct type change.
///
/// Safe alternative: `unsafe { &*ptr }` (borrow checker validates the lifetime
/// at the borrow site, at least partially) or `NonNull::as_ref()`/`as_mut()`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, CastKind, Rvalue, StatementKind};
use rustc_middle::ty::{TyCtxt, TyKind};

pub struct TransmuteLifetime;

impl Checker for TransmuteLifetime {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        _flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            for statement in &block_data.statements {
                // Skip macro-synthesized spans.
                if statement.source_info.span.from_expansion() {
                    continue;
                }
                let StatementKind::Assign(assign) = &statement.kind else { continue };
                let (_, rhs) = &**assign;
                let Rvalue::Cast(CastKind::Transmute, operand, dst_ty) = rhs else { continue };

                let src_ty = operand.ty(&body.local_decls, tcx);

                // Source must be a raw pointer (*const T or *mut T).
                let TyKind::RawPtr(src_inner, src_mutbl) = src_ty.kind() else { continue };

                // Destination must be a reference (&T or &mut T).
                let TyKind::Ref(_, dst_inner, dst_mutbl) = dst_ty.kind() else { continue };

                let src_prefix = if src_mutbl.is_mut() { "*mut" } else { "*const" };
                let dst_prefix = if dst_mutbl.is_mut() { "&mut" } else { "&" };

                let note = if dst_mutbl.is_mut() {
                    format!(
                        "creates an exclusive mutable reference from a raw pointer — the pointer \
                         must be non-null, aligned, point to a live, exclusively-owned allocation \
                         valid for `{dst_inner}`, and NOT aliased by any other `&mut`/`*mut` for \
                         the duration of the reference; use `NonNull::as_mut()` instead"
                    )
                } else {
                    format!(
                        "fabricates a shared reference from a raw pointer — the pointer must be \
                         non-null, aligned, and point to a live allocation valid for `{dst_inner}` \
                         for the reference's entire use; this bypasses all borrow-checker lifetime \
                         validation; use `unsafe {{ &*ptr }}` or `NonNull::as_ref()` instead"
                    )
                };

                findings.push(Finding {
                    rule_id: "transmute_lifetime",
                    severity: Severity::Warning,
                    span: statement.source_info.span,
                    message: format!(
                        "`mem::transmute` raw-pointer-to-reference (`{src_prefix} {src_inner}` → \
                         `{dst_prefix} {dst_inner}`) — {note}"
                    ),
                });
            }
        }

        findings
    }
}
