/// Detects calls to functions annotated with `#[target_feature(enable = "...")]`.
///
/// Since Rust 1.86.0 (`target_feature_11` stabilization), calling a function
/// with `#[target_feature]` requires an `unsafe` block in most contexts.
/// The caller must guarantee:
///   • The CPU executing the code supports ALL required features at the point
///     of the call — calling without the feature active causes undefined
///     behaviour (typically SIGILL on x86_64, or silent wrong results elsewhere)
///   • Feature detection must happen at an appropriate scope — a check at
///     program startup does NOT protect against calls after a dynamic feature
///     change (extremely rare but possible with CPU hotplug or emulation)
///   • Coercing a `#[target_feature]` function item to a `fn()` pointer and
///     calling through it from a context that doesn't have the feature is UB
///   • Closures inside a `#[target_feature]` function inherit the parent
///     feature set; they must not escape to a context where the feature is
///     unavailable
///
/// The safe pattern uses `is_x86_feature_detected!("avx2")` (or the
/// equivalent for other architectures) before entering the unsafe call:
///
/// ```rust
/// if is_x86_feature_detected!("avx2") {
///     unsafe { avx2_accelerated_path() }
/// }
/// ```
///
/// Stable since Rust 1.86.0. Prior to 1.86, `#[target_feature]` functions
/// required the `target_feature_11` nightly feature gate to be callable in
/// safe contexts.
///
/// Related: RUSTSEC-2021-0138, RUSTSEC-2021-0087 — misuse of AVX/SSE
/// intrinsics without feature detection caused SIGILL in production.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct TargetFeatureCall;

impl Checker for TargetFeatureCall {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect the target features of the calling function so we can skip
        // calls where the callee's features are a subset of the caller's.
        let caller_features = {
            let caller_def_id = body.source.def_id();
            let attrs = tcx.codegen_fn_attrs(caller_def_id);
            attrs.target_features.clone()
        };

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            // Skip calls to non-local functions (intrinsics, libstd); they are
            // handled by the arch_intrinsic checker if relevant.
            let attrs = tcx.codegen_fn_attrs(def_id);
            if attrs.target_features.is_empty() {
                continue;
            }

            // If the caller already requires all features the callee needs,
            // this is a safe same-feature-level call — do not flag.
            let required: Vec<_> = attrs
                .target_features
                .iter()
                .filter(|tf| !caller_features.iter().any(|cf| cf.name == tf.name))
                .collect();
            if required.is_empty() {
                continue;
            }

            let feature_list: Vec<&str> = required.iter().map(|tf| tf.name.as_str()).collect();
            let features_str = feature_list.join(", ");
            let fn_name = tcx.def_path_str(def_id);

            findings.push(Finding {
                rule_id: "target_feature_call",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` requires CPU feature(s) [{features_str}] — \
                     calling without the feature enabled is UB (SIGILL or wrong results); \
                     guard with `is_x86_feature_detected!(\"{}\")` or equivalent before \
                     this call",
                    feature_list.first().copied().unwrap_or("the feature")
                ),
            });
        }

        findings
    }
}
