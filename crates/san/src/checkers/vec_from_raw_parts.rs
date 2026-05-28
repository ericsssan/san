/// Detects calls to `Vec::from_raw_parts`, `Vec::from_raw_parts_in`,
/// `Vec::from_parts`, and `Vec::from_parts_in`.
///
/// All four functions reconstruct a Vec from its constituent heap components.
/// The caller must guarantee ALL of the following:
///   • The pointer was allocated by the same allocator (global for `from_raw_parts`;
///     matching `A` for the `_in` variants)
///   • `T` must have the same size and alignment as what was allocated
///   • `length` ≤ `capacity`
///   • `capacity` matches the original allocation capacity exactly
///   • The first `length` elements must be initialized
///   • After calling, the Vec owns the allocation — the original pointer
///     must not be used again (use-after-free / double-free if it was a Box)
///
/// `Vec::from_parts` / `Vec::from_parts_in` (nightly `box_vec_non_null`) take a
/// `NonNull<T>` instead of a raw `*mut T` but have identical safety requirements;
/// the NonNull wrapper does not relax any invariant.
///
/// A mismatch between the T used to allocate and the T used to reconstruct
/// is a type confusion vulnerability.
///
/// RustSec: RUSTSEC-2022-0064 (teloxide-core), RUSTSEC-2021-0041 (abi_stable),
/// and several other crates that round-trip Vec through FFI or build Vecs
/// from manually managed allocations.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct VecFromRawParts;

impl Checker for VecFromRawParts {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, extra) = if path.ends_with("Vec::<T>::from_raw_parts")
                || path.ends_with("Vec::from_raw_parts")
            {
                ("Vec::from_raw_parts", "")
            } else if path.ends_with("Vec::<T, A>::from_raw_parts_in")
                || path.ends_with("Vec::from_raw_parts_in")
            {
                (
                    "Vec::from_raw_parts_in",
                    " and the allocator A must match the one that produced the pointer",
                )
            } else if path.contains("Vec") && path.ends_with("::from_parts")
                && !path.contains("raw")
            {
                (
                    "Vec::from_parts",
                    "; takes NonNull<T> instead of *mut T but has identical \
                     safety requirements to `Vec::from_raw_parts` — the NonNull \
                     wrapper does not relax any invariant (nightly `box_vec_non_null`)",
                )
            } else if path.contains("Vec") && path.ends_with("::from_parts_in")
                && !path.contains("raw")
            {
                (
                    "Vec::from_parts_in",
                    "; allocator-aware NonNull variant — allocator A must match \
                     the one used at allocation (nightly `box_vec_non_null`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "vec_from_raw_parts",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — ptr must come from the same allocator, len ≤ cap, \
                     cap must match the allocation exactly, first len elements must be \
                     initialized{extra}, and the pointer must not be used again after this call"
                ),
            });
        }

        findings
    }
}
