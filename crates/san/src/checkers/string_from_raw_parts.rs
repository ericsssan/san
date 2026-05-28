/// Detects calls to `String::from_raw_parts`.
///
/// `String::from_raw_parts(ptr, length, capacity)` reconstructs a String from
/// its constituent heap parts. The caller must guarantee ALL of the following:
///   • `ptr` was obtained from a String (or Vec<u8>) managed by the global allocator;
///     using a pointer from a different allocator (e.g., a custom arena, C malloc)
///     will cause a double-free or corruption on drop
///   • `length` bytes starting at `ptr` are valid UTF-8; violating this invariant
///     is immediate UB because Rust assumes all `str`/`String` values are UTF-8
///   • `length <= capacity` — the string length must not exceed the allocated size
///   • `capacity` matches the actual allocated capacity of the original buffer;
///     a wrong capacity causes the allocator to free or reallocate with the wrong
///     layout, resulting in heap corruption
///   • The original owner (the String or Vec<u8>) must have been forgotten or had
///     its data pointer extracted via `into_raw_parts` — two live Strings sharing
///     the same buffer will double-free on drop
///
/// Common bugs: byte-count vs character-count confusion, using a pointer obtained
/// from a C string (different allocator), failing to preserve the exact capacity.
///
/// Safe alternative: `String::from_utf8` or `String::from_raw_parts` only after
/// careful accounting of provenance, layout, and UTF-8 validity.
///
/// RustSec: pattern appears in RUSTSEC-2021-0019 (abomonation) and custom
/// serialization crates that reconstruct strings from raw allocations.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct StringFromRawParts;

impl Checker for StringFromRawParts {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let is_from_raw_parts = path.ends_with("String::from_raw_parts")
                || (path.ends_with("::from_raw_parts") && path.contains("String"))
                || (path.ends_with("::from_raw_parts_in") && path.contains("String"));
            if !is_from_raw_parts {
                continue;
            }

            let fn_name = if path.ends_with("::from_raw_parts_in") {
                "String::from_raw_parts_in"
            } else {
                "String::from_raw_parts"
            };

            findings.push(Finding {
                rule_id: "string_from_raw_parts",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — ptr must be valid for the declared capacity, bytes must be \
                     valid UTF-8, length must be <= capacity, and the original buffer must be \
                     forgotten; mismatches cause double-free, heap corruption, or UB from \
                     invalid UTF-8"
                ),
            });
        }

        findings
    }
}
