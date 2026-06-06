/// Detects calls to rkyv's unchecked zero-copy deserialization functions.
///
/// rkyv provides two access paths:
///   • `rkyv::access::<T, E>(bytes)` — validates alignment and type layout (safe)
///   • `rkyv::access_unchecked::<T>(bytes)` — skips ALL validation (unsafe)
///
/// For rkyv 0.7.x, the analogous unsafe functions are:
///   • `rkyv::archived_root::<T>(bytes)` — unsafe root access
///   • `rkyv::archived_root_mut::<T>(bytes)` — unsafe mutable root access
///
/// Callers of the unchecked variants must guarantee:
///   • `bytes` ends at a position that is properly aligned for `T::Archived`
///   • The byte range contains a valid, fully-initialized archived `T`
///   • No mutable reference to any byte in the range exists simultaneously
///     (for `access_unchecked_mut` / `archived_root_mut`)
///
/// Violating these creates references with invalid provenance or type-confused
/// bit patterns — both are immediate undefined behaviour. Archived data from
/// untrusted sources (network, disk, IPC) must always be validated before access.
///
/// RUSTSEC-2021-0054 (rkyv 0.7): unsound archived value access led to memory
/// corruption in production serialization pipelines.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RkyvUnchecked;

impl Checker for RkyvUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            // access_unchecked* — generalised: any zero-copy deserializer using this naming
            // pattern has the same byte-validity contract regardless of crate.
            let (fn_name, note) = if path.ends_with("::access_unchecked_mut") {
                (
                    path.rsplit("::").next().unwrap_or("access_unchecked_mut"),
                    "bytes must be properly aligned for the archived type and contain valid \
                     initialized data; no concurrent reference to the byte range may exist; \
                     validate with the checked variant (returns Result) before accessing \
                     untrusted archived data",
                )
            } else if path.ends_with("::access_unchecked") {
                (
                    path.rsplit("::").next().unwrap_or("access_unchecked"),
                    "bytes must be properly aligned for the archived type and contain valid \
                     initialized data; misaligned or invalid bytes are immediate UB; validate \
                     with the checked variant (returns Result) before accessing untrusted data",
                )
            // archived_root* — rkyv-specific naming, keep crate guard
            } else if path.ends_with("::archived_root_mut") && path.contains("rkyv") {
                (
                    "rkyv::archived_root_mut",
                    "bytes must be a valid archived T with proper alignment; \
                     mutating through an invalid archived reference is immediate UB",
                )
            } else if path.ends_with("::archived_root") && path.contains("rkyv") {
                (
                    "rkyv::archived_root",
                    "bytes must be a valid archived T starting at the position returned by \
                     `archived_root_offset`; improper alignment or an invalid bit pattern is UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "rkyv_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
