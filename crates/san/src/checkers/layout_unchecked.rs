/// Detects calls to `Layout::from_size_align_unchecked`,
/// `Layout::from_size_alignment_unchecked`, and
/// `Alignment::new_unchecked` (nightly feature `ptr_alignment_type`).
///
/// `Layout::from_size_align_unchecked` creates an allocator `Layout` without
/// validating its invariants. The caller must guarantee:
///   • `align` is a power of two (non-power-of-two alignment is immediate UB)
///   • `size` is a multiple of `align` when rounded up — or more precisely,
///     `size` must not overflow `isize::MAX` when computing `size.next_multiple_of(align)`
///   • Violating either condition causes UB in any subsequent allocator call
///     that uses the layout
///
/// `Alignment::new_unchecked(align: usize) -> Alignment`:
///   • `align` must be a power of two; any other value produces an `Alignment`
///     with an invalid bit representation (UB)
///   • Use `Alignment::new(align)` which returns `Option<Alignment>` instead
///
/// The safe alternative is `Layout::from_size_align` which returns a `Result`.
///
/// Common bugs: computing alignment from an integer that may not be a power-of-two,
/// using a hardcoded size that doesn't account for padding, or trusting FFI-
/// supplied size/align values without validation.
///
/// Flow suppression for `from_size_align_unchecked`:
///   • If the `size` argument has `const_upper ≤ isize::MAX / 2` (conservative),
///     overflow on rounding-up is impossible and the finding is suppressed.
///   • If the `align` argument is a constant power of two, the power-of-two
///     requirement is met (the overflow condition still applies).
use crate::analysis::transfer::const_u64;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct LayoutUnchecked;

/// `isize::MAX / 2` — conservative upper bound for layout size. If the size
/// argument is proven ≤ this value, rounding up to any alignment cannot
/// overflow isize::MAX (since we'd add at most the alignment - 1, and realistic
/// alignments are all far smaller than isize::MAX / 2).
const SAFE_LAYOUT_SIZE: u64 = (i64::MAX / 2) as u64;

impl Checker for LayoutUnchecked {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, note) =
                if path.ends_with("Layout::from_size_align_unchecked")
                    || path.ends_with("Layout::from_size_alignment_unchecked")
                {
                    // Flow suppression: if size (arg[0]) has proven const_upper ≤
                    // SAFE_LAYOUT_SIZE, overflow on rounding is impossible — suppress.
                    let size_arg = args.first();
                let align_arg = args.get(1);
                let size_local = size_arg.and_then(|a| match &a.node {
                    Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                    _ => None,
                });
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    // Check if align is a constant power-of-two (alignment concern met).
                    let align_is_pow2 = align_arg.map_or(false, |a| {
                        const_u64(&a.node).map_or(false, |v| v.is_power_of_two())
                    });
                    if let Some(size_local) = size_local {
                        // If size is provably small enough, both concerns are met.
                        if let Some(&upper) = state.const_upper.get(&size_local) {
                            if upper <= SAFE_LAYOUT_SIZE {
                                continue;
                            }
                        }
                        // If align is a proven power-of-two and the overflow concern
                        // is handled by alloc_size_overflow (mul_overflow[size]),
                        // suppress layout_unchecked to avoid duplicate findings.
                        if align_is_pow2 && state.mul_overflow.contains(&size_local) {
                            continue;
                        }
                    } else if align_is_pow2 {
                        // Constant size (no local) + power-of-two align: no overflow risk.
                        continue;
                    }
                }
                    let note = if path.ends_with("Layout::from_size_alignment_unchecked") {
                        "size must not overflow isize::MAX when rounded to the given Alignment; \
                         the `Alignment` type guarantees power-of-two but size overflow is still \
                         unchecked (nightly feature `ptr_alignment_type`)"
                    } else {
                        "align must be a power of two and size must not overflow \
                         isize::MAX when rounded to align; use `Layout::from_size_align` \
                         (returns Result) instead"
                    };
                    (path.rsplit("::").next().unwrap_or("from_size_align_unchecked"), note)
                } else if path.ends_with("Alignment::new_unchecked") {
                    (
                        "Alignment::new_unchecked",
                        "align must be a power of two; any other value produces an \
                         Alignment with an invalid internal representation (UB); \
                         use `Alignment::new` which returns Option \
                         (nightly feature `ptr_alignment_type`)",
                    )
                } else {
                    continue;
                };

            findings.push(Finding {
                rule_id: "layout_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
