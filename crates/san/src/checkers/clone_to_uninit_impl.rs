/// Detects `unsafe impl CloneToUninit` implementations (stable since Rust 1.81).
///
/// `CloneToUninit` is an `unsafe` trait for cloning a value into uninitialized
/// memory. The implementer must guarantee:
///
/// For `clone_to_uninit(&self, dst: *mut Self)`:
///   • `dst` must be valid for writes of `size_of_val(self)` bytes
///   • `dst` must be properly aligned for `Self`
///   • After the call, `dst` must be fully initialized — all bytes must be valid
///     for the type, not just partially written
///   • If the clone panics, `dst` must remain in a valid state (either fully
///     initialized or unmodified — partial initialization is UB when the caller
///     later calls `assume_init`)
///
/// Common bugs: partially initializing `dst` before a potential panic path,
/// failing to initialize padding bytes in structs that contain them,
/// incorrect size calculation for DSTs (dynamically-sized types like `[T]` or `str`).
///
/// The default implementations for built-in types are correct; this checker
/// only fires on custom implementations where the invariants must be manually upheld.
///
/// Stable since Rust 1.81.0.
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct CloneToUninitImpl;

impl Checker for CloneToUninitImpl {
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item_id in tcx.hir_free_items() {
            let item = tcx.hir_item(item_id);
            let ItemKind::Impl(impl_block) = &item.kind else { continue };
            let Some(trait_impl) = impl_block.of_trait else { continue };
            if trait_impl.safety != Safety::Unsafe {
                continue;
            }
            let Some(trait_def_id) = trait_impl.trait_ref.trait_def_id() else { continue };
            let trait_path = tcx.def_path_str(trait_def_id);
            if !trait_path.contains("CloneToUninit") {
                continue;
            }

            findings.push(Finding {
                rule_id: "clone_to_uninit_impl",
                severity: Severity::Warning,
                span: item.span,
                message: "`unsafe impl CloneToUninit` — `clone_to_uninit` must fully initialize \
                          `dst` (aligned, correct size_of_val); partial initialization followed \
                          by a panic path is UB; the caller will call `assume_init` on `dst`"
                    .to_string(),
            });
        }

        findings
    }
}
