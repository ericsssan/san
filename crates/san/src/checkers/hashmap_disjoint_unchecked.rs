/// Detects calls to `HashMap::get_disjoint_unchecked_mut` (stable since Rust 1.86).
///
/// `get_disjoint_unchecked_mut([k1, k2, ...])` returns N independent mutable
/// references into the map at the specified keys. The checked version
/// (`get_disjoint_mut`) returns an error if any key is missing or if any two
/// keys are equal. The unchecked variant skips the equality check.
///
/// The caller must guarantee ALL of the following:
///   • All N keys are pairwise distinct (no duplicates in the key array)
///     — duplicate keys yield two `Option<&mut V>` that point to the same memory,
///     and if both `Some` variants are unwrapped, the resulting `&mut V` references
///     alias the same slot (immediate UB from aliased mutable references)
///   • Missing keys produce `None` — this is not UB, but the invariant violation
///     on duplicates is, independent of whether the returned `Some(&mut V)` is used
///
/// Note: `get_disjoint_mut` (the checked variant) returns `Err(...)` on duplicates
/// and is the safe alternative.
///
/// Common bugs: constructing key arrays from computed values without deduplication,
/// using index-based loops that accidentally repeat a key.
///
/// Stable since Rust 1.86 (previously named `get_many_mut` in nightly).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HashMapDisjointUnchecked;

impl Checker for HashMapDisjointUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("get_disjoint_unchecked_mut")
                || !path.contains("HashMap")
            {
                continue;
            }

            findings.push(Finding {
                rule_id: "hashmap_disjoint_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`HashMap::get_disjoint_unchecked_mut` — all keys in the array \
                          must be pairwise distinct; duplicate keys produce aliased \
                          `&mut V` references (immediate UB even if neither is written); \
                          use `get_disjoint_mut` for the checked version"
                    .to_string(),
            });
        }

        findings
    }
}
