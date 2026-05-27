/// Detects `static mut` declarations.
///
/// `static mut` variables are shared across all threads with no synchronization.
/// Any access (read or write) requires an `unsafe` block. The caller must guarantee:
///   • No two threads access the variable simultaneously without explicit synchronization
///   • No reference to the variable's storage escapes to a longer lifetime
///   • In Rust 2024, creating a reference to `static mut` is denied by default
///
/// Data race via `static mut` is the most common form of undefined behaviour
/// in concurrent Rust programs:
///   • `static mut COUNTER: u32 = 0;` with concurrent `COUNTER += 1` is a
///     data race → UB even if the increments happen to give the right result
///   • Exposing a `static mut` as `&T` across thread boundaries violates aliasing
///
/// Safe alternatives:
///   • `static COUNTER: AtomicU32 = AtomicU32::new(0)` for shared counters
///   • `std::sync::OnceLock` / `LazyLock` for lazily-initialized state
///   • `thread_local!` for per-thread state with no sharing
///
/// RustSec: RUSTSEC-2024-0020 (mio) — `static mut` RUNTIME caused a data race.
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Mutability};
use rustc_middle::ty::TyCtxt;

pub struct StaticMut;

impl Checker for StaticMut {
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item_id in tcx.hir_free_items() {
            let item = tcx.hir_item(item_id);
            let ItemKind::Static(Mutability::Mut, ident, _ty, _body) = &item.kind else { continue };

            let name = ident.name;
            findings.push(Finding {
                rule_id: "static_mut",
                severity: Severity::Warning,
                span: item.span,
                message: format!(
                    "`static mut {name}` — unguarded mutable global; concurrent access \
                     is a data race (UB); use AtomicT, OnceLock, or Mutex instead"
                ),
            });
        }

        findings
    }
}
