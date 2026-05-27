/// Detects calls to `mem::transmute_copy`, `mem::transmute_prefix`,
/// `mem::transmute_neo`, and `mem::conjure_zst`.
///
/// `mem::transmute_copy(&src)` copies `size_of::<U>()` bytes out of `src` and
/// reinterprets them as type U. Unlike `transmute`, the compiler does NOT
/// enforce size equality: U can be smaller or larger than T.
///
/// The caller must guarantee:
///   • `src` is valid and properly aligned for T
///   • `size_of::<U>()` ≤ `size_of::<T>()` — reading past the end of T is UB
///   • All bit patterns in the copied bytes are valid for U
///   • If U is a reference type: provenance and alignment invariants must hold
///   • Neither T nor U should be repr(Rust) unless layout stability is proven
///
/// `mem::transmute_prefix` (nightly `transmute_prefix`): transmutes Src to Dst
/// where Dst is a leading-byte prefix of Src (size_of::<Dst>() <= size_of::<Src>()).
/// Compared to transmute, the size-check is enforced, but bit-validity is not.
///
/// `mem::transmute_neo` (nightly `transmute_neo`): like transmute but the
/// compiler checks BOTH size AND alignment. Still unsafe for bit-validity.
///
/// `mem::conjure_zst` (nightly `mem_conjure_zst`): produces a value of type T
/// from thin air. UB if T is not a zero-sized type (size_of::<T>() != 0).
///
/// Common bugs: using transmute_copy to "extract" a smaller type from a larger
/// one without verifying which bytes are extracted (endianness), or using it
/// with U larger than T to read past the end of the allocation.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MemTransmuteCopy;

impl Checker for MemTransmuteCopy {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, args)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, extra_note) = if path.ends_with("mem::transmute_copy") {
                (
                    "mem::transmute_copy",
                    "unlike transmute, the compiler does NOT check size equality; \
                     size_of::<U>() must not exceed size_of::<T>(); \
                     all copied bytes must be valid for U",
                )
            } else if path.ends_with("transmute_prefix") {
                (
                    "mem::transmute_prefix",
                    "compiler enforces size_of::<Dst>() <= size_of::<Src>(); \
                     all Dst-sized leading bytes of Src must be valid for Dst \
                     (nightly feature `transmute_prefix`)",
                )
            } else if path.ends_with("transmute_neo") {
                (
                    "mem::transmute_neo",
                    "compiler checks both size AND alignment (stricter than transmute); \
                     still unsafe — all bit patterns of Src must be valid for Dst \
                     (nightly feature `transmute_neo`)",
                )
            } else if path.ends_with("conjure_zst") {
                (
                    "mem::conjure_zst",
                    "creates a T from thin air — UB if T is not a zero-sized type \
                     (size_of::<T>() != 0); the compiler enforces this only in debug mode \
                     (nightly feature `mem_conjure_zst`)",
                )
            } else {
                continue;
            };

            let type_info = {
                let mut types = args.types();
                match (types.next(), types.next()) {
                    (Some(src), Some(dst)) => format!(" (`{src}` → `{dst}`)"),
                    (Some(src), None) => format!(" (`{src}`)"),
                    _ => String::new(),
                }
            };

            findings.push(Finding {
                rule_id: "mem_transmute_copy",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}`{type_info} — {extra_note}"),
            });
        }

        findings
    }
}
