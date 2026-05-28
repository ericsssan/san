/// Detects calls to unsafe operations on `heapless` fixed-capacity collections.
///
/// **`heapless::Vec`**:
///   • `push_unchecked(element)` — writes past end of inline array if len == N (OOB, UB)
///   • `pop_unchecked()` — pops without checking len > 0; returns uninit memory if empty (UB)
///   • `swap_remove_unchecked(index)` — removes element without bounds check (OOB, UB)
///   • `set_len(new_len)` — caller must ensure new_len ≤ N and elements initialized
///
/// **`heapless::Deque`** (double-ended queue):
///   • `push_front_unchecked(v)` / `push_back_unchecked(v)` — write past end if full (UB)
///   • `pop_front_unchecked()` / `pop_back_unchecked()` — pop without checking non-empty (UB)
///
/// **`heapless::spsc` (single-producer / single-consumer queue)**:
///   • `Producer::enqueue_unchecked(val)` — enqueues without checking queue not full (OOB, UB)
///   • `Consumer::dequeue_unchecked()` — dequeues without checking queue not empty (UB)
///
/// Common in embedded firmware that uses fixed-capacity containers without heap.
/// RUSTSEC-2021-0051 (heapless 0.6 double-free) arose from violating a related capacity
/// invariant in unsafe collection code.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HeaplessUnchecked;

impl Checker for HeaplessUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("heapless") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::push_unchecked") {
                (
                    "heapless::Vec::push_unchecked",
                    "no bounds check — if len == N (compile-time capacity), this writes one \
                     element past the end of the inline array (OOB write, immediate UB); \
                     use push() which returns Err on overflow",
                )
            } else if path.ends_with("::pop_unchecked") {
                (
                    "heapless::Vec::pop_unchecked",
                    "no empty check — if len == 0, this reads one slot before the start of \
                     the inline array (OOB read, immediate UB); use pop() → Option<T>",
                )
            } else if path.ends_with("::swap_remove_unchecked") {
                (
                    "heapless::Vec::swap_remove_unchecked",
                    "no bounds check on index — if index >= len, this reads/writes past the \
                     end of the inline array (OOB, immediate UB); use swap_remove() which \
                     panics on out-of-bounds",
                )
            } else if path.ends_with("::set_len") {
                (
                    "heapless::Vec::set_len",
                    "new_len must be ≤ N (compile-time capacity) and all elements in \
                     old_len..new_len must be initialized; uninitialized elements are dropped \
                     when the Vec is dropped (reads from uninit bytes, UB)",
                )
            } else if path.ends_with("::push_front_unchecked") {
                (
                    "heapless::Deque::push_front_unchecked",
                    "no capacity check — if len == N, pushes past the end of the ring buffer \
                     (OOB write, immediate UB); use push_front() → Result",
                )
            } else if path.ends_with("::push_back_unchecked") {
                (
                    "heapless::Deque::push_back_unchecked",
                    "no capacity check — if len == N, pushes past the end of the ring buffer \
                     (OOB write, immediate UB); use push_back() → Result",
                )
            } else if path.ends_with("::pop_front_unchecked") {
                (
                    "heapless::Deque::pop_front_unchecked",
                    "no empty check — if the deque is empty this reads uninitialized memory \
                     (immediate UB); use pop_front() → Option<T>",
                )
            } else if path.ends_with("::pop_back_unchecked") {
                (
                    "heapless::Deque::pop_back_unchecked",
                    "no empty check — if the deque is empty this reads uninitialized memory \
                     (immediate UB); use pop_back() → Option<T>",
                )
            } else if path.ends_with("::enqueue_unchecked") && path.contains("spsc") {
                (
                    "heapless::spsc::Producer::enqueue_unchecked",
                    "no capacity check — if the SPSC queue is full this writes past the end \
                     of the ring buffer (OOB write, immediate UB); \
                     use enqueue() → Result",
                )
            } else if path.ends_with("::dequeue_unchecked") && path.contains("spsc") {
                (
                    "heapless::spsc::Consumer::dequeue_unchecked",
                    "no empty check — if the SPSC queue is empty this reads uninitialized \
                     or recycled memory (immediate UB); use dequeue() → Option<T>",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "heapless_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
