/// Detects calls to CPU architecture intrinsics in `std::arch::*`.
///
/// Intrinsics in `std::arch` (e.g. `std::arch::x86_64::_mm_*`,
/// `std::arch::aarch64::v*`, `std::arch::wasm32::*`) are `unsafe fn`s that
/// map directly to hardware instructions. The caller must guarantee:
///
///   • The required CPU feature is available at runtime. Calling an SSE4.2
///     intrinsic on a CPU without SSE4.2 causes `SIGILL` (illegal instruction).
///     Use `#[target_feature(enable = "...")]` or runtime detection via
///     `is_x86_feature_detected!()` / `std::arch::is_aarch64_feature_detected!()`.
///
///   • Alignment: many load/store intrinsics (e.g. `_mm_load_ps`,
///     `vld1q_f32` with aligned variants) require the pointer to be aligned to
///     the SIMD vector width (typically 16 or 32 bytes). Misaligned access
///     causes `SIGBUS` on strict-alignment architectures and silent incorrect
///     results on x86.
///
///   • Lane count and element type: intrinsics operate on fixed-width SIMD
///     types (e.g. `__m128`, `int32x4_t`). Reinterpreting a narrower type
///     as a wider one or vice-versa is immediate UB.
///
///   • Memory validity: pointer-based intrinsics (loads, stores, scatter/gather)
///     have the same validity requirements as `ptr::read` / `ptr::write`.
///
/// Safe alternatives:
///   • `std::simd` (portable SIMD, nightly) abstracts over architectures
///   • Rely on auto-vectorization where performance requirements permit
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ArchIntrinsic;

impl Checker for ArchIntrinsic {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            // Match any call into std::arch:: or core::arch:: namespaces.
            if !path.contains("arch::x86")
                && !path.contains("arch::aarch64")
                && !path.contains("arch::arm")
                && !path.contains("arch::wasm")
                && !path.contains("arch::riscv")
                && !path.contains("arch::mips")
                && !path.contains("arch::powerpc")
                && !path.contains("arch::loongarch")
            {
                continue;
            }

            // Extract the intrinsic name (last path segment).
            let fn_name = path.rsplit("::").next().unwrap_or(&path);
            let arch = if path.contains("x86_64") || path.contains("x86") {
                "x86/x86_64"
            } else if path.contains("aarch64") {
                "AArch64"
            } else if path.contains("arm") {
                "ARM"
            } else if path.contains("wasm") {
                "Wasm"
            } else if path.contains("riscv") {
                "RISC-V"
            } else if path.contains("powerpc") {
                "PowerPC"
            } else if path.contains("loongarch") {
                "LoongArch"
            } else {
                "MIPS"
            };

            findings.push(Finding {
                rule_id: "arch_intrinsic",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` ({arch} intrinsic) — requires the correct CPU feature to be \
                     active (missing feature → SIGILL); pointer-based intrinsics require \
                     correct alignment and valid memory; use `is_x86_feature_detected!()` \
                     or `#[target_feature(enable)]` to guard"
                ),
            });
        }

        findings
    }
}
