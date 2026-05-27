/// Detects `mem::zeroed::<T>()` where the zero bit pattern is invalid for T.
///
/// Categories that make zeroed() immediately UB:
///   • Unconstrained generic `T` — callers may supply any type with invariants
///   • Reference types (`&T`, `&mut T`) — zero is a null reference, which Rust
///     guarantees never occurs; the optimizer may exploit this to eliminate
///     null checks and reorder/elide code
///   • Function pointer types (`fn(...)`, `unsafe fn(...)`) — zero is a null
///     function pointer; calling it is instant UB; rustc may optimize under the
///     assumption that fn pointers are non-null
///   • NonZero* types (`NonZeroU8` … `NonZeroUsize`, `NonZeroI*`) — the entire
///     purpose of these types is that the value is never zero; violating this
///     breaks niche-filling optimizations (e.g. `Option<NonZeroU32>` stores
///     `None` as zero, so a zeroed inner value "is" `None`)
///   • `NonNull<T>` — same niche guarantee as NonZero; a null NonNull is UB
///     and corrupts `Option<NonNull<T>>` layout optimizations
///
/// Safe alternative: `MaybeUninit::zeroed()` for types where zeroing is known
/// to produce valid values, or explicit construction.
///
/// Real-world CVE: RUSTSEC-2022-0019 (crossbeam-channel), RUSTSEC-2020-0052.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::{self, TyCtxt};

pub struct MemZeroedGeneric;

impl Checker for MemZeroedGeneric {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, args)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("mem::zeroed") {
                continue;
            }

            let Some(ty) = args.types().next() else { continue };

            let reason = match ty.kind() {
                ty::Param(_) => Some(format!(
                    "generic `{ty}` may have non-zero validity invariants (references, \
                     NonNull, enum discriminants, fn pointers)"
                )),
                ty::Ref(_, inner, _) => Some(format!(
                    "`&{inner}` — null references are immediate UB; the optimizer assumes \
                     Rust references are always non-null"
                )),
                ty::FnPtr(..) => Some(
                    "function pointer — null fn pointers are UB; the optimizer assumes \
                     fn pointers are always non-null"
                        .to_string(),
                ),
                ty::Adt(adt_def, _) => {
                    let adt_path = tcx.def_path_str(adt_def.did());
                    if adt_path.contains("NonZero") {
                        Some(format!(
                            "`{ty}` requires a non-zero value by construction; \
                             zeroing it corrupts niche-filling optimizations"
                        ))
                    } else if adt_path.contains("NonNull") {
                        Some(format!(
                            "`{ty}` requires a non-null pointer by construction; \
                             zeroing it creates a null NonNull which corrupts \
                             `Option<NonNull<T>>` niche layout and is immediate UB"
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let Some(reason) = reason else { continue };

            findings.push(Finding {
                rule_id: "mem_zeroed_generic",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`mem::zeroed::<{ty}>()` — {reason}; use `MaybeUninit` instead"),
            });
        }

        findings
    }
}
