/// Detects calls to `Atomic*::from_ptr` on std atomic types.
///
/// `from_ptr(p)` creates a shared reference to an atomic variable from a raw
/// pointer. The caller must guarantee:
///   • `p` is non-null and properly aligned for the atomic type
///   • The memory at `p` is valid for reads and writes for the returned
///     reference's lifetime
///   • No other reference to `*p` exists that is not also atomic (aliasing
///     rule violation otherwise)
///   • The pointed-to memory must not be accessed through non-atomic operations
///     while the returned reference is live
///
/// Common bugs:
///   • Creating multiple `&AtomicT` from the same pointer where one is later
///     used non-atomically (TSAN data race)
///   • Misaligned pointer (UB on most platforms, silent corruption on x86)
///   • Dangling pointer after the underlying storage is freed or goes out of scope
///
/// RustSec: RUSTSEC-2019-0013 (spin) demonstrates how incorrect atomic usage
/// leads to data races even in safe-looking code.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AtomicFromPtr;

impl Checker for AtomicFromPtr {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::from_ptr") {
                continue;
            }
            let is_std_atomic = path.contains("sync::atomic");
            let is_portable = path.contains("portable_atomic");
            if !is_std_atomic && !is_portable {
                continue;
            }

            findings.push(Finding {
                rule_id: "atomic_from_ptr",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`Atomic::from_ptr` — pointer must be non-null, aligned, valid for the \
                          reference lifetime, and must not be aliased by non-atomic accesses; \
                          concurrent non-atomic access to the same memory is a data race (UB)"
                    .to_string(),
            });
        }

        findings
    }
}
