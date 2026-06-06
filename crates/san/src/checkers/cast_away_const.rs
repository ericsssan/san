/// Detects writes through `*mut T` pointers that were cast from `*const T`.
///
/// The pattern:
/// ```rust
/// let p: *const T = shared.as_ptr();   // shared pointer — may be aliased
/// let q = p as *mut T;                 // cast-away-const: still aliased!
/// unsafe { *q = val; }                 // UB: mutating through a shared raw pointer
/// ```
///
/// This is the canonical "shared mutation without UnsafeCell" bug. It appears
/// in practice when:
///   • `Arc::as_ptr()` is cast to `*mut T` and then written through while other
///     `Arc` clones are alive — violates Rust's aliasing model.
///   • A `&T` (non-UnsafeCell) is cast to `*const T` then `*mut T` and mutated.
///   • A `*const T` parameter is transmuted to `*mut T` inside an unsafe function.
///
/// Only writes are flagged, not reads: reading through a cast-away-const pointer
/// is sound (it's just a raw alias of an immutable view).
///
/// The checker uses the `const_ptr_cast` flow domain tracked in `BlockState`,
/// which is set by the `PtrToPtr` cast arm in transfer.rs and propagated through
/// copy/move assignments.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Location, Operand, ProjectionElem, StatementKind, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CastAwayConst;

impl Checker for CastAwayConst {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            // ── statement-level deref-writes: `*ptr = val` ──────────────────
            for (si, stmt) in block_data.statements.iter().enumerate() {
                let StatementKind::Assign(assign) = &stmt.kind else { continue };
                let (dst_place, _rvalue) = &**assign;

                // The LHS must be a deref of a raw pointer: `*ptr = ...`
                if !matches!(dst_place.projection.as_ref(), [ProjectionElem::Deref]) {
                    continue;
                }
                let ptr_local = dst_place.local;

                // Get flow state BEFORE this statement.
                let loc = Location { block: bb, statement_index: si };
                let Some(state) = flow.state_at_location(tcx, body, loc) else { continue };

                if !state.const_ptr_cast.contains(&ptr_local) {
                    continue;
                }

                findings.push(Finding {
                    rule_id: "cast_away_const",
                    severity: Severity::Warning,
                    span: stmt.source_info.span,
                    message: format!(
                        "`*{ptr:?} = ...` writes through a `*mut T` obtained by casting a \
                         `*const T`; if the pointee is not inside an `UnsafeCell`, this is UB \
                         (aliased mutation without interior mutability). Common cause: \
                         `Arc::as_ptr() as *mut T` or `&T as *const T as *mut T`.",
                        ptr = ptr_local,
                    ),
                });
            }

            // ── terminator-level: `ptr::write(ptr, val)` calls ──────────────
            let Some(term) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &term.kind else { continue };
            let Some((callee_def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(callee_def_id);
            // Detect both method-style writes (`p.write(val)` → first arg = self/dst)
            // and the free function (`ptr::write(dst, val)` → first arg = dst).
            let is_write_through_first = crate::analysis::transfer::is_ptr_write_to_first_arg(&path)
                || path.ends_with("ptr::write")
                || path.ends_with("ptr::write_unaligned")
                || path.ends_with("ptr::write_bytes")
                || path.ends_with("ptr::copy_nonoverlapping")
                || path.ends_with("ptr::copy");
            if !is_write_through_first { continue; }

            let Some(ptr_arg) = args.first() else { continue };
            let ptr_local = match &ptr_arg.node {
                Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => p.local,
                _ => continue,
            };

            let Some(state) = flow.state_before_terminator(tcx, body, bb) else { continue };

            if !state.const_ptr_cast.contains(&ptr_local) {
                continue;
            }

            findings.push(Finding {
                rule_id: "cast_away_const",
                severity: Severity::Warning,
                span: term.source_info.span,
                message: format!(
                    "`{fn_short}({ptr:?}, ...)` writes through a `*mut T` obtained by casting a \
                     `*const T`; if the pointee is not inside an `UnsafeCell`, this is UB \
                     (aliased mutation). Common cause: `Arc::as_ptr() as *mut T` or \
                     `&T as *const T as *mut T`.",
                    fn_short = path.rsplit("::").next().unwrap_or(&path),
                    ptr = ptr_local,
                ),
            });
        }

        findings
    }
}
