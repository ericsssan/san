/// Detects calls to `Box::into_raw`, `Arc::into_raw`, `Rc::into_raw`,
/// `Arc::Weak::into_raw`, `Rc::Weak::into_raw`,
/// `Box::into_raw_with_allocator`, `Arc::into_raw_with_allocator`,
/// `Rc::into_raw_with_allocator`, `Pin::into_inner_unchecked`,
/// `Thread::into_raw`, `Box::into_non_null`, `Vec::into_raw_parts`,
/// `Vec::into_raw_parts_with_alloc`, and `String::into_raw_parts`.
///
/// `into_raw` leaks the smart pointer and transfers ownership of the underlying
/// allocation to the caller as a raw pointer. The caller becomes responsible for
/// calling the corresponding `from_raw` exactly once to avoid memory leaks or
/// double-frees. Common misuse patterns:
///
/// • Forgetting to call `from_raw` → permanent memory leak
/// • Calling `from_raw` more than once → double-free / use-after-free
/// • Passing the pointer to a different allocator's free function
/// • Calling `Box::from_raw` with a different T than was used for `Box::into_raw`
///   → type confusion, invalid drop
/// • For `Arc::into_raw` / `Rc::into_raw`: the reference count is NOT decremented;
///   the caller has exactly one "logical Arc/Rc" to reconstitute via `from_raw`
///
/// `Pin::into_inner_unchecked` bypasses pin-safety: the caller must guarantee
/// either the type implements `Unpin`, or the value will not be moved after
/// unpinning (e.g., it will be immediately dropped or pinned again).
///
/// RustSec: RUSTSEC-2022-0062 (lz4-sys), RUSTSEC-2020-0160 (os_str_bytes),
/// and many FFI binding crates that transfer Box/Arc ownership to C.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct IntoRaw;

impl Checker for IntoRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::into_raw") && path.contains("sync::Weak") {
                (
                    "Arc::Weak::into_raw",
                    "leaks the Weak reference without decrementing the weak count; the pointer \
                     must be passed to exactly one `Weak::from_raw` call — forgetting to call \
                     `from_raw` leaks the control block; the strong count is unaffected but \
                     the allocation will not be freed until all weak references are dropped",
                )
            } else if path.ends_with("::into_raw") && path.contains("rc::Weak") {
                (
                    "Rc::Weak::into_raw",
                    "leaks the Weak reference without decrementing the weak count; the pointer \
                     must be passed to exactly one `Weak::from_raw` call — forgetting to call \
                     `from_raw` leaks the control block; Rc::Weak is not thread-safe",
                )
            } else if path.ends_with("::into_raw") && path.contains("Box") {
                (
                    "Box::into_raw",
                    "leaks the Box; the pointer must be passed to exactly one \
                     `Box::from_raw` call with the same T; forgetting to call \
                     `from_raw` leaks memory; calling it twice causes double-free",
                )
            } else if path.ends_with("::into_raw") && path.contains("Arc") {
                (
                    "Arc::into_raw",
                    "leaks the Arc without decrementing the refcount; the pointer \
                     represents one logical Arc that MUST be reconstituted via \
                     `Arc::from_raw` exactly once",
                )
            } else if path.ends_with("::into_raw") && path.contains("Rc") {
                (
                    "Rc::into_raw",
                    "leaks the Rc without decrementing the refcount; the pointer \
                     represents one logical Rc that MUST be reconstituted via \
                     `Rc::from_raw` exactly once; Rc is not thread-safe",
                )
            } else if path.ends_with("::into_raw_with_allocator") && path.contains("Box") {
                (
                    "Box::into_raw_with_allocator",
                    "leaks the Box and returns the allocator; the pointer must be passed to \
                     exactly one `Box::from_raw_in` call with the same T and the returned \
                     allocator; forgetting to call `from_raw_in` leaks memory",
                )
            } else if path.ends_with("::into_raw_with_allocator") && path.contains("Arc") {
                (
                    "Arc::into_raw_with_allocator",
                    "leaks the Arc without decrementing the refcount; the pointer represents \
                     one logical Arc that MUST be reconstituted via `Arc::from_raw_in` with \
                     the returned allocator exactly once",
                )
            } else if path.ends_with("::into_raw_with_allocator") && path.contains("Rc") {
                (
                    "Rc::into_raw_with_allocator",
                    "leaks the Rc without decrementing the refcount; must be reconstituted via \
                     `Rc::from_raw_in` with the returned allocator exactly once; Rc is not thread-safe",
                )
            } else if path.ends_with("::into_inner_unchecked") && path.contains("Pin") {
                (
                    "Pin::into_inner_unchecked",
                    "bypasses pin-safety — only valid if T: Unpin or the value is \
                     guaranteed not to move after unpinning; moving a self-referential \
                     struct after unpinning corrupts internal pointers",
                )
            } else if path.ends_with("Thread::into_raw") {
                (
                    "Thread::into_raw",
                    "leaks the Thread handle; the pointer must be passed to exactly one \
                     Thread::from_raw call to reconstruct it; forgetting to call from_raw \
                     leaks the thread object; calling from_raw twice causes double-free \
                     (nightly: #![feature(thread_raw)])",
                )
            } else if path.ends_with("::into_non_null") && path.contains("Box") {
                (
                    "Box::into_non_null",
                    "leaks the Box as NonNull<T>; must be passed to exactly one \
                     Box::from_non_null call with the same T; forgetting leaks memory; \
                     calling from_non_null twice causes double-free \
                     (nightly: #![feature(box_vec_non_null)])",
                )
            } else if path.ends_with("::into_raw_parts_with_alloc") && path.contains("Vec") {
                (
                    "Vec::into_raw_parts_with_alloc",
                    "leaks the Vec and returns (ptr, len, cap, allocator); must be \
                     reconstituted via Vec::from_raw_parts_in with the same T, exact len/cap, \
                     and the returned allocator; forgetting leaks memory, wrong allocator \
                     causes heap corruption (nightly `allocator_api`)",
                )
            } else if path.ends_with("::into_raw_parts") && path.contains("Vec") {
                (
                    "Vec::into_raw_parts",
                    "leaks the Vec and returns (ptr, len, cap); must be reconstituted via \
                     Vec::from_raw_parts with the same T, exact len/cap, and the global \
                     allocator; forgetting leaks memory; wrong cap causes heap corruption \
                     on drop; stable since Rust 1.93",
                )
            } else if path.ends_with("String::into_raw_parts") {
                (
                    "String::into_raw_parts",
                    "leaks the String and returns (ptr, len, cap); must be reconstituted via \
                     String::from_raw_parts with the exact same len/cap and a UTF-8-valid buffer; \
                     forgetting leaks memory; wrong cap causes heap corruption on drop; \
                     bytes written into the raw buffer must be valid UTF-8 before \
                     reconstituting; stable since Rust 1.93",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "into_raw",
                severity: Severity::Info,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
