/// Detects calls to `UnsafeCell::get`, `UnsafeCell::raw_get`,
/// `SyncUnsafeCell::get`, `SyncUnsafeCell::raw_get`, and `SyncUnsafeCell::get_mut`.
///
/// `UnsafeCell<T>` is the only foundation for legal interior mutability in Rust.
/// `get(&self) -> *mut T` and `raw_get(*const Self) -> *mut T` both return a raw
/// mutable pointer to the contained value, bypassing the borrow checker entirely.
///
/// The caller must guarantee:
///   • If multiple raw pointers exist simultaneously, at most one may be used as
///     `&mut T` at any given time — violating this creates aliased `&mut T`, which
///     is immediate UB (LLVM noalias assumptions will miscompile)
///   • The pointer must not outlive the `UnsafeCell` (dangling reference UB)
///   • Any reads through a shared pointer derived from `get()` must not race with
///     writes through another pointer (data race = UB in Rust's memory model)
///
/// All safe interior-mutability wrappers (`Cell`, `RefCell`, `Mutex`, `RwLock`,
/// `AtomicT`) internally call `UnsafeCell::get` — direct use bypasses all their
/// invariants. If the access pattern is simple, use a safe wrapper instead.
///
/// Common bugs: creating two `&mut T` via two separate `get()` calls, holding
/// a `&T` derived from `get()` while another thread writes via a second `get()`.
///
/// Seen in: RUSTSEC-2023-0004 (ouroboros), RUSTSEC-2023-0023 (rc-event-id),
/// custom arena allocators, and hand-rolled lock-free data structures.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnsafeCellGet;

impl Checker for UnsafeCellGet {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let is_cell = path.contains("UnsafeCell") || path.contains("SyncUnsafeCell");
            if !is_cell {
                continue;
            }

            let is_sync = path.contains("SyncUnsafeCell");
            let cell_name = if is_sync { "SyncUnsafeCell" } else { "UnsafeCell" };

            let (fn_name, note): (&str, String) = if path.ends_with("::raw_get") {
                (
                    "raw_get",
                    format!(
                        "returns *mut T from a raw pointer to the cell — no aliasing or \
                         validity checks; at most one &mut T may exist at a time; reads \
                         and writes through separate pointers without synchronization are \
                         data races (UB) (nightly: #![feature(sync_unsafe_cell)])",
                    ),
                )
            } else if path.ends_with("::get_mut") && is_sync {
                (
                    "get_mut",
                    "returns &mut T from &mut SyncUnsafeCell<T>; the exclusive borrow prevents \
                     concurrent access through the SyncUnsafeCell but any outstanding raw \
                     pointers obtained from earlier get()/raw_get() calls that alias this memory \
                     still cause UB; ensure no such aliasing pointers are live \
                     (nightly: #![feature(sync_unsafe_cell)])"
                        .to_string(),
                )
            } else if path.ends_with("::get") {
                (
                    "get",
                    format!(
                        "returns *mut T, bypassing the borrow checker — at most one &mut T \
                         may be active at a time; unsynchronized concurrent reads+writes are \
                         data races (UB); {extra}",
                        extra = if is_sync {
                            "SyncUnsafeCell implements Sync so get() may be called from multiple \
                             threads — synchronization is entirely the caller's responsibility \
                             (nightly: #![feature(sync_unsafe_cell)])"
                        } else {
                            "prefer Cell/RefCell/Mutex unless direct pointer access is necessary"
                        }
                    ),
                )
            } else {
                continue;
            };
            let fn_name = format!("{cell_name}::{fn_name}");

            findings.push(Finding {
                rule_id: "unsafecell_get",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
