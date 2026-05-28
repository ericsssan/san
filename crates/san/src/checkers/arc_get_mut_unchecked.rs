/// Detects calls to `Arc::get_mut_unchecked` and `Rc::get_mut_unchecked`
/// (nightly, feature `get_mut_unchecked`, tracking issue #63292).
///
/// These methods return `&mut T` from a shared-ownership pointer by bypassing
/// the reference-count check. The checked variants (`Arc::get_mut` /
/// `Rc::get_mut`) return `None` if any other pointer to the same allocation
/// exists; the unchecked variants skip that check entirely.
///
/// The caller must guarantee ALL of the following:
///   • No other `Arc`/`Rc` to the same allocation is alive (strong count = 1)
///   • No `Weak` pointer is being upgraded to an `Arc`/`Rc` concurrently (for Arc)
///   • No other `Arc`/`Rc` or `Weak` to the same allocation is **dropped** for the
///     duration of the returned borrow — the destructor of a concurrently-dropped
///     clone writes to the refcount, which aliases the `&mut T` borrow (data race
///     for `Arc` if across threads; for `Rc`, a second `Rc::clone` + drop can
///     invalidate the uniqueness assumption) (Issue #136322)
///   • The returned `&mut T` must not escape the lifetime of `this`
///
/// The "no concurrent drops" requirement was omitted from documentation until
/// January 2025 (rust-lang/rust#136322) — this is a latent soundness hole
/// in the wild in crates that believed single-Arc meant safe exclusive access.
///
/// Nightly: requires `#![feature(get_mut_unchecked)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ArcGetMutUnchecked;

impl Checker for ArcGetMutUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.ends_with("::get_mut_unchecked") {
                continue;
            }

            let (container, extra) = if path.contains("Arc") {
                (
                    "Arc",
                    "also ensure no other Arc/Weak is dropped concurrently — \
                     the refcount write races with the returned &mut T (Issue #136322)",
                )
            } else if path.contains("Rc") {
                (
                    "Rc",
                    "also ensure no Rc clone is dropped for the borrow duration — \
                     a concurrent refcount decrement to zero while the &mut T is live \
                     is unsound (Issue #136322)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "arc_get_mut_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{container}::get_mut_unchecked` — strong count must be exactly 1 \
                     and no Weak must be upgrading; {extra}"
                ),
            });
        }

        findings
    }
}
