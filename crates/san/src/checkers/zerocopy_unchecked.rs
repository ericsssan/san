/// Detects calls to unsafe methods on `zerocopy::Unalign<T>` that create
/// references violating Rust's alignment invariants.
///
/// `zerocopy::Unalign<T>` is a wrapper that allows storing a `T` at any byte
/// address, even one that is not aligned to `align_of::<T>()`. It is often used
/// for parsing network packets or binary file formats where data is packed without
/// padding.
///
/// **`Unalign::deref_mut_unchecked(&mut self) -> &mut T`**:
///   • Creates a `&mut T` pointing to the inner data without checking alignment
///   • If the address of the `Unalign<T>` is not aligned to `align_of::<T>()`,
///     the resulting `&mut T` is an unaligned reference — this is **immediate UB**
///     in Rust (the compiler may emit alignment-assuming instructions for aligned
///     references on many architectures, including x86 SSE, ARM NEON, etc.)
///   • The safe alternative is `Unalign::get_mut()` which returns `Option<&mut T>`,
///     yielding `Some` only when the address is correctly aligned
///
/// Common bugs: calling `deref_mut_unchecked` on data from a `&[u8]` slice that
/// was constructed without alignment guarantees (e.g., a received network buffer),
/// or on a `#[repr(packed)]` struct field where the field's natural alignment
/// requirement is not respected by the packing.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ZerocopyUnchecked;

impl Checker for ZerocopyUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("zerocopy") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::deref_mut_unchecked") {
                (
                    "Unalign::deref_mut_unchecked",
                    "creates &mut T without checking alignment; if the address is not aligned \
                     to align_of::<T>(), the reference is an unaligned mutable reference — \
                     immediate UB on architectures that require aligned loads/stores; \
                     use Unalign::get_mut() → Option<&mut T> for a safe checked version",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "zerocopy_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
