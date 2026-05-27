/// Detects calls to nightly volatile and streaming memory intrinsics:
/// `volatile_load`, `volatile_store`, `volatile_set_memory`,
/// `volatile_copy_nonoverlapping_memory`, `volatile_copy_memory`,
/// `nontemporal_store`, `unaligned_volatile_load`, and `unaligned_volatile_store`.
/// (Nightly: `#![feature(core_intrinsics)]`)
///
/// Volatile operations bypass the optimizer but carry strict safety requirements:
///
/// `volatile_load(src)`:
///   • `src` must be valid for reads and properly aligned for T
///   • Does NOT provide any synchronization — two threads reading/writing the same
///     location concurrently is still a data race (UB); use atomics for sharing
///
/// `volatile_store(dst, val)`:
///   • `dst` must be valid for writes and properly aligned for T
///   • NOT atomic — not suitable for inter-thread signaling without additional
///     synchronization; commonly confused with atomic stores
///
/// `volatile_set_memory(dst, val, count)`:
///   • Like `memset` but volatile; `dst` must be valid for writes of
///     `count * size_of::<T>()` bytes and properly aligned
///   • Does NOT reliably clear sensitive memory on all platforms — the optimizer
///     may still elide later non-volatile reads; use `write_bytes` with `black_box`
///     or a platform `explicit_bzero` equivalent for zeroing secrets
///
/// `volatile_copy_nonoverlapping_memory(dst, src, count)` / `volatile_copy_memory(dst, src, count)`:
///   • Both pointers must be valid for the given count of T
///   • The `_nonoverlapping` variant requires dst and src memory regions do not overlap
///   • NOT atomic — concurrent access to the same range is a data race
///
/// Common mistakes:
///   • Using volatile ops as a substitute for atomics in lock-free code
///   • Trusting that `volatile_set_memory(key_buf, 0, len)` securely wipes a key
///     (the compiler or CPU may reorder or elide the write)
///   • Misaligned pointers for types with alignment > 1 byte
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct VolatileIntrinsics;

impl Checker for VolatileIntrinsics {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("volatile_load") {
                (
                    "volatile_load",
                    "src must be valid for reads and properly aligned; does NOT provide \
                     synchronization — concurrent access from another thread is still a data race; \
                     use atomics for inter-thread communication",
                )
            } else if path.ends_with("volatile_store") {
                (
                    "volatile_store",
                    "dst must be valid for writes and properly aligned; NOT atomic — do not use \
                     for inter-thread signaling without additional synchronization; \
                     use atomics or a mutex instead",
                )
            } else if path.ends_with("volatile_set_memory") {
                (
                    "volatile_set_memory",
                    "dst must be valid for count * size_of::<T>() bytes; does NOT reliably \
                     clear sensitive memory — the compiler may elide subsequent non-volatile reads; \
                     for zeroing secrets use write_bytes + black_box or a platform explicit_bzero",
                )
            } else if path.ends_with("volatile_copy_nonoverlapping_memory") {
                (
                    "volatile_copy_nonoverlapping_memory",
                    "both pointers must be valid for count elements and must NOT overlap; \
                     not atomic — concurrent access to either range is a data race",
                )
            } else if path.ends_with("volatile_copy_memory") {
                (
                    "volatile_copy_memory",
                    "both pointers must be valid for count elements (overlap is allowed unlike \
                     the nonoverlapping variant); not atomic — concurrent access to either range \
                     is a data race",
                )
            } else if path.ends_with("nontemporal_store") {
                (
                    "nontemporal_store",
                    "dst must be valid for writes and properly aligned; streaming stores bypass \
                     the CPU cache — other threads may see stale data without an explicit memory \
                     fence (e.g. SFENCE on x86) after the store sequence; NOT atomic",
                )
            } else if path.ends_with("unaligned_volatile_load") {
                (
                    "unaligned_volatile_load",
                    "src must be valid for reads of size_of::<T>() bytes; alignment is NOT \
                     required (unlike volatile_load), so misaligned access is allowed but \
                     the value must still be initialized; does NOT provide synchronization — \
                     concurrent writes from another thread are still a data race",
                )
            } else if path.ends_with("unaligned_volatile_store") {
                (
                    "unaligned_volatile_store",
                    "dst must be valid for writes of size_of::<T>() bytes; alignment is NOT \
                     required, so misaligned writes are allowed; NOT atomic — do not use for \
                     inter-thread signaling without additional synchronization",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "volatile_intrinsics",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
