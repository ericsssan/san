/// Detects dereferences of raw pointers (`*const T` / `*mut T`) written with
/// the `*ptr` syntax — i.e. as a MIR `Deref` projection rather than a call to
/// `ptr::read`/`ptr::write`.
///
/// Dereferencing a raw pointer is *always* an unsafe operation (it requires an
/// `unsafe` block): the compiler cannot prove the pointer is non-null, aligned,
/// pointing to a live allocation, or — for `&mut *p` — uniquely borrowed. The
/// caller must guarantee:
///   • the pointer is non-null and properly aligned for `T`
///   • it points within a single live allocation valid for `size_of::<T>()`
///   • the pointee is initialized and a valid bit-pattern for `T` (for reads)
///   • no aliasing `&`/`&mut` is live in violation of the borrow rules
///
/// This complements `ptr_read`/`ptr_write`/`nonnull_deref`, which only match the
/// *function-call* forms (`ptr::read(p)`, `NonNull::as_ref`). The overwhelming
/// majority of real raw dereferences are written as `*p`, `*p = v`, `(*p).field`
/// or `&mut *p`, none of which are calls — so without this checker they are
/// missed entirely.
///
/// Three classes of *safe* deref are deliberately excluded:
///   • reference (`&T`/`&mut T`) derefs — the base type is `Ref`, not `RawPtr`
///   • `Box` derefs — `*box` is compiler-lowered to a deref of the box's internal
///     `*const T` (extracted from its `Unique`/`NonNull`); we trace the pointer's
///     provenance back to a `Box`-typed local and skip it
///   • derefs inlined from a callee or expanded from a macro — they belong to
///     that other body, not the user code at this site
///
/// Seen in: intrusive linked lists, custom allocators, FFI buffers, and every
/// hand-rolled data structure that stores `*mut T` node pointers.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::visit::{PlaceContext, Visitor};
use rustc_middle::mir::{
    Body, Local, Location, Operand, Place, ProjectionElem, Rvalue, SourceScope, StatementKind,
};
use rustc_middle::ty::{TyCtxt, TyKind};
use std::collections::HashMap;

pub struct RawPtrDeref;

struct DerefVisitor<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body<'tcx>,
    /// Locals assigned exactly once by an `Assign` to a bare local, mapped to
    /// the assigned rvalue. Used to trace a pointer back to its origin.
    defs: HashMap<Local, &'a Rvalue<'tcx>>,
    findings: Vec<Finding>,
}

/// Returns `true` if `scope` (or any of its inlining ancestors) was produced by
/// inlining a callee into this body. Optimized MIR inlines functions such as
/// `Vec::index` and `<[T]>::get`, whose bodies dereference the collection's
/// internal `*const T`; those derefs inherit the *caller's* span and so look
/// like user-written raw dereferences. The deref's real home is the callee's own
/// MIR body — analyzed on its own when local, audited when from a library — so
/// flagging the inlined copy would only misattribute (and duplicate) it.
fn is_inlined(body: &Body<'_>, scope: SourceScope) -> bool {
    let mut cur = Some(scope);
    while let Some(s) = cur {
        let data = &body.source_scopes[s];
        if data.inlined.is_some() {
            return true;
        }
        cur = data.inlined_parent_scope;
    }
    false
}

impl<'a, 'tcx> DerefVisitor<'a, 'tcx> {
    /// Trace `local` back through copy/move/cast chains; return `true` if it
    /// originates from a `Box`-typed local. `*box` lowers to a raw deref of the
    /// box's internal pointer, extracted via a cast of `((box.0: Unique).0:
    /// NonNull)` — a safe operation that must not be flagged.
    fn derives_from_box(&self, mut local: Local) -> bool {
        for _ in 0..8 {
            let Some(rvalue) = self.defs.get(&local) else { return false };
            let src = match rvalue {
                Rvalue::Use(Operand::Copy(p) | Operand::Move(p), _)
                | Rvalue::Cast(_, Operand::Copy(p) | Operand::Move(p), _) => p,
                _ => return false,
            };
            // The source place is rooted at some local; if that local is a Box
            // (the pointer was extracted from a box's fields), this is a box deref.
            if self.body.local_decls[src.local].ty.is_box() {
                return true;
            }
            local = src.local;
        }
        false
    }
}

impl<'a, 'tcx> Visitor<'tcx> for DerefVisitor<'a, 'tcx> {
    fn visit_place(&mut self, place: &Place<'tcx>, context: PlaceContext, location: Location) {
        // Walk each projection step; flag every `Deref` applied to a base whose
        // type is a raw pointer. `iter_projections` yields the base place-ref
        // *before* each element is applied, so its type is the type being deref'd.
        for (base, elem) in place.iter_projections() {
            if !matches!(elem, ProjectionElem::Deref) {
                continue;
            }
            let base_ty = base.ty(&self.body.local_decls, self.tcx).ty;
            if !matches!(base_ty.kind(), TyKind::RawPtr(..)) {
                continue;
            }
            // A `Box` deref is lowered to a raw deref of the box's internal
            // pointer — safe, and not something the user wrote as `*raw`.
            if base.projection.is_empty() && self.derives_from_box(base.local) {
                continue;
            }

            let source_info = self.body.source_info(location);
            let span = source_info.span;
            // A `Deref` synthesised by the compiler (e.g. inside a macro
            // expansion) is the macro author's responsibility, matching how the
            // other unsafe-op checkers treat macro-generated code.
            if span.from_expansion() {
                continue;
            }
            // Skip derefs inlined from a callee — they belong to that callee's
            // body, not the user code at this call site (see `is_inlined`).
            if is_inlined(self.body, source_info.scope) {
                continue;
            }

            let access = if context.is_mutating_use() { "write" } else { "read" };
            self.findings.push(Finding {
                rule_id: "raw_ptr_deref",
                severity: Severity::Warning,
                span,
                message: format!(
                    "raw pointer dereference ({access}) — the pointer must be non-null, \
                     aligned, and point to a live allocation valid for the accessed type; \
                     dereferencing an invalid raw pointer is undefined behavior"
                ),
            });
        }
        self.super_place(place, context, location);
    }
}

impl Checker for RawPtrDeref {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        _flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        // Build the single-assignment map: a local assigned more than once is
        // ambiguous, so drop it from the map (we only trust unique definitions).
        let mut defs: HashMap<Local, &Rvalue<'tcx>> = HashMap::new();
        let mut multiply_assigned: std::collections::HashSet<Local> = Default::default();
        for data in body.basic_blocks.iter() {
            for stmt in &data.statements {
                if let StatementKind::Assign(assign) = &stmt.kind {
                    let (place, rvalue) = &**assign;
                    if place.projection.is_empty() {
                        if defs.insert(place.local, rvalue).is_some() {
                            multiply_assigned.insert(place.local);
                        }
                    }
                }
            }
        }
        for local in multiply_assigned {
            defs.remove(&local);
        }

        let mut visitor = DerefVisitor {
            tcx,
            body,
            defs,
            findings: Vec::new(),
        };
        // Drive the visitor over basic blocks only — not var-debug-info, whose
        // places are not real dereferences in the executed code.
        for (bb, data) in body.basic_blocks.iter_enumerated() {
            visitor.visit_basic_block_data(bb, data);
        }
        visitor.findings
    }
}
