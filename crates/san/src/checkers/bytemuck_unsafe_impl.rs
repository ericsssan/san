/// Detects `unsafe impl` for `bytemuck` safety traits: `Pod`, `Zeroable`,
/// `AnyBitPattern`, `NoUninit`, `TransparentWrapper`, and `CheckedBitPattern`.
///
/// These unsafe marker traits allow `bytemuck` to reinterpret the raw bytes
/// of a value as a different type (like `mem::transmute` but through a trait
/// boundary). Implementing them incorrectly is a common source of UB.
///
/// `unsafe impl Pod for T`:
///   • `T` must be plain-old-data: no padding bytes, no invalid bit patterns
///   • All possible byte sequences of `size_of::<T>()` must be valid `T` values
///   • `T` must have no interior references, Box, NonNull, or other pointer types
///   • Implies `Zeroable` and `AnyBitPattern`; all three must hold simultaneously
///
/// `unsafe impl Zeroable for T`:
///   • The all-zeros bit pattern must be a valid `T` (e.g. `0u8` is zeroable,
///     `NonNull<T>` is NOT because null is an invalid `NonNull`)
///   • References (`&T`, `&mut T`) are NOT zeroable — null references are UB
///
/// `unsafe impl AnyBitPattern for T`:
///   • Every possible bit sequence must be a valid `T` — no pointer types,
///     no enums with limited discriminants, no `bool` (only 0/1 are valid)
///
/// `unsafe impl NoUninit for T`:
///   • `T` must have no uninitialized or padding bytes — all byte positions
///     must be initialized and meaningful; required for safe byte-slice reads
///
/// `unsafe impl TransparentWrapper<Inner> for T`:
///   • `T` must be a `#[repr(transparent)]` newtype over `Inner`
///   • The memory layout of `T` and `Inner` must be identical — any difference
///     allows `bytemuck` to produce invalid references
///
/// `unsafe impl CheckedBitPattern for T`:
///   • `T::Bits` must be `AnyBitPattern`; `is_valid_bit_pattern` must return
///     `true` exactly when the bit pattern represents a valid `T` — a false
///     positive allows `bytemuck::checked::from_bytes` to return invalid `T`
///
/// Common bugs:
///   • Implementing `Pod` for a struct that has padding between fields
///   • Implementing `Zeroable` for a type that wraps a reference or NonNull
///   • Implementing `AnyBitPattern` for an enum (only some discriminants valid)
///   • `CheckedBitPattern::is_valid_bit_pattern` has a subtle off-by-one in
///     range checks (e.g. enum variants check `<= max` but `> max` is also invalid)
use crate::{Checker, Finding, Severity};
use rustc_hir::{ItemKind, Safety};
use rustc_middle::ty::TyCtxt;

pub struct BytemuckUnsafeImpl;

impl Checker for BytemuckUnsafeImpl {
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

            if !trait_path.contains("bytemuck") {
                continue;
            }

            let (trait_name, note) = if trait_path.ends_with("::Pod") {
                (
                    "Pod",
                    "T must have no padding bytes and every possible bit sequence must be a \
                     valid T; pointer/reference fields and enums with limited discriminants \
                     cannot implement Pod; use bytemuck::derive(Pod) for struct verification",
                )
            } else if trait_path.ends_with("::Zeroable") {
                (
                    "Zeroable",
                    "the all-zeros bit pattern must be a valid T; references, NonNull, Box, \
                     and types with invalid-zero-value invariants (NonZero*) cannot be Zeroable; \
                     derive with #[derive(Zeroable)] to let bytemuck verify the layout",
                )
            } else if trait_path.ends_with("::AnyBitPattern") {
                (
                    "AnyBitPattern",
                    "every possible bit sequence must be a valid T; enums (limited discriminants), \
                     bool (only 0/1), char (not all u32 values are valid), and pointer types \
                     cannot implement AnyBitPattern without violating the invariant",
                )
            } else if trait_path.ends_with("::NoUninit") {
                (
                    "NoUninit",
                    "T must have no uninitialized or padding bytes; all byte positions must be \
                     initialized by every value of T; add #[repr(C)] or #[repr(packed)] and \
                     verify there are no padding fields between struct members",
                )
            } else if trait_path.ends_with("::TransparentWrapper") {
                (
                    "TransparentWrapper",
                    "T must be #[repr(transparent)] over Inner with identical memory layout; \
                     any layout difference allows bytemuck to produce references to invalid memory; \
                     wrap fields with #[repr(transparent)] and verify size_of::<T>() == size_of::<Inner>()",
                )
            } else if trait_path.ends_with("::CheckedBitPattern") {
                (
                    "CheckedBitPattern",
                    "is_valid_bit_pattern must return true exactly when the bit pattern is a valid T; \
                     a false positive allows bytemuck::checked::from_bytes to return an invalid T; \
                     test edge cases (discriminant boundaries for enums, null for pointers)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "bytemuck_unsafe_impl",
                severity: Severity::Warning,
                span: item.span,
                message: format!(
                    "`unsafe impl bytemuck::{trait_name}` — {note}"
                ),
            });
        }

        findings
    }
}
