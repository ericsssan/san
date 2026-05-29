//! Shared constructor for `use_after_free` findings.
//!
//! Several checkers (`ptr_read`, `ptr_write`, `raw_ptr_deref`) reach the same
//! conclusion from flow state — a pointer is dereferenced after its allocation
//! was handed off (`Reconstituted`) — and should report it identically. The
//! "freed" transition can originate in another function: an inter-procedural
//! summary marks a consumed pointer parameter as reconstituted at the call site,
//! so this fires on cross-function use-after-free, not just same-body cases.
use crate::{Finding, Severity};
use rustc_span::Span;

/// Build a `use_after_free` finding. `op` describes the access ("read",
/// "write", "dereference"); `potential` selects the lower-confidence wording
/// used when the pointer is freed on only some control-flow paths.
pub fn uaf_finding(span: Span, op: &str, potential: bool) -> Finding {
    let message = if potential {
        format!(
            "potential use-after-free: {op} through a pointer whose allocation may \
             already have been reclaimed (reconstituted via `from_raw` or a consuming \
             call) on some control-flow path reaching here"
        )
    } else {
        format!(
            "use-after-free: {op} through a pointer whose allocation was already \
             reclaimed (reconstituted via `from_raw` or a consuming call) — the raw \
             pointer no longer owns valid memory"
        )
    };
    Finding {
        rule_id: "use_after_free",
        severity: Severity::Warning,
        span,
        message,
    }
}
