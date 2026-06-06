/// Detects calls to `NonNull::new_unchecked`.
///
/// `NonNull::new_unchecked` creates a `NonNull<T>` from a raw pointer without
/// checking for null. The caller must guarantee:
///   • The pointer is non-null — a null pointer produces immediate UB when
///     `NonNull` invariants are relied upon (LLVM assumes non-null for
///     references derived from it)
///   • The pointer was obtained from a valid allocation or is a valid address
///
/// The safe alternative is `NonNull::new` which returns `Option<NonNull<T>>`.
///
/// Common bugs: using `as *mut T` cast from an integer or a dangling pointer,
/// calling after a failed allocation that returned null, FFI pointers without
/// null checks.
///
/// RustSec: appears in RUSTSEC-2021-0079 and multiple FFI boundary crates
/// that wrap C APIs returning nullable pointers.
use crate::analysis::state::FreedKind;
use crate::analysis::transfer::first_arg_local;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NonNullNewUnchecked;

impl Checker for NonNullNewUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("NonNull::<T>::new_unchecked")
                && !path.ends_with("NonNull::new_unchecked")
            {
                continue;
            }

            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(ptr_local) = first_arg_local(args) {
                    match state.freed_kind(ptr_local) {
                        FreedKind::Definite => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", false));
                            continue;
                        }
                        FreedKind::Potential => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", true));
                            continue;
                        }
                        FreedKind::NotFreed => {}
                    }
                    // Suppress when the pointer provably came from into_raw in this
                    // function — it is non-null by construction.
                    if state.ptr_is_raw_owned(ptr_local) {
                        continue;
                    }
                    // Suppress when the pointer is proven nonzero (e.g. from as_ptr()
                    // / as_mut_ptr() which never return null).
                    if state.local_is_nonzero(ptr_local) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "nonnull_new_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`NonNull::new_unchecked` — pointer must be non-null (null is \
                          immediate UB); use `NonNull::new` (returns Option) unless the \
                          pointer provably comes from a non-null source"
                    .to_string(),
            });
        }

        findings
    }
}
