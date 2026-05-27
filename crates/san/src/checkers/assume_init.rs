/// Detects calls to `MaybeUninit::assume_init*` and similar "assume initialized"
/// patterns, plus direct access to uninitialized buffer memory via
/// `tokio::io::ReadBuf` unsafe methods.
///
/// `MaybeUninit::assume_init*` — asserts memory is initialized when it may not be;
/// reads from uninitialized bytes is immediate UB.
///
/// `ReadBuf::assume_init(n)` — marks n bytes as initialized without writing them;
/// unwritten bytes become readable by the buffer consumer (UB).
///
/// `ReadBuf::inner_mut()` / `ReadBuf::unfilled_mut()` — return `&mut [MaybeUninit<u8>]`
/// bypassing the ReadBuf initialization tracking; reading from returned uninitialized
/// bytes before writing is UB; `inner_mut` additionally allows shrinking the
/// initialized portion by writing fewer bytes than tracked.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AssumeInit;

impl Checker for AssumeInit {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };

            let Some((def_id, _)) = func.const_fn_def() else { continue };
            let path = tcx.def_path_str(def_id);

            let (fn_name, msg) = if path.contains("MaybeUninit") && path.contains("assume_init") {
                (
                    path.rsplit("::").next().unwrap_or("assume_init"),
                    "verify all bytes are initialized before calling `assume_init`",
                )
            } else if path.contains("ReadBuf") && path.ends_with("::assume_init") {
                (
                    "ReadBuf::assume_init",
                    "marks the first n bytes of the unfilled region as initialized without \
                     writing to them; caller must have actually written n bytes before this call; \
                     unwritten bytes become readable by the buffer consumer (UB)",
                )
            } else if path.contains("ReadBuf") && path.ends_with("::inner_mut") {
                (
                    "ReadBuf::inner_mut",
                    "returns the entire backing buffer as &mut [MaybeUninit<u8>], bypassing \
                     ReadBuf's initialization tracking; reading from uninitialized bytes is UB; \
                     writing fewer bytes than previously tracked shrinks the initialized region \
                     invisibly, causing future readers to observe stale uninitialized data",
                )
            } else if path.contains("ReadBuf") && path.ends_with("::unfilled_mut") {
                (
                    "ReadBuf::unfilled_mut",
                    "returns the unfilled portion of the buffer as &mut [MaybeUninit<u8>]; \
                     reading from returned bytes before writing to them is UB; \
                     caller must use assume_init() to register any bytes actually written",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "assume_init",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {msg}"),
            });
        }

        findings
    }
}
