/// Detects calls to `time::util::refresh_tz_unchecked`.
///
/// `time::util::refresh_tz_unchecked()`:
///   • Re-reads the system timezone from the OS (e.g., `/etc/localtime`) without
///     any synchronization against other threads that may be concurrently calling
///     `OffsetDateTime::now_local()` or reading local-time offsets
///   • The safe wrapper `refresh_tz()` checks whether the operation is known to
///     be sound on the current platform before proceeding, returning `None` if it
///     is not. `refresh_tz_unchecked` skips this check.
///   • On multi-threaded programs, updating the cached timezone while another
///     thread reads it is a data race — undefined behaviour even if the underlying
///     OS call is itself atomic
///   • On platforms where the soundness check would return `None` (e.g., when
///     local-offset reads are not safe from a multi-threaded context), this
///     function may read stale or partially-written timezone data
///
/// Safe alternative: `time::util::refresh_tz()` — returns `None` when the
/// operation cannot be performed safely; always prefer it over the unchecked form.
///
/// References: RUSTSEC-2020-0071 (time 0.1 / 0.2 unsound offset reading in
/// multi-threaded programs), which motivated the `local-offset` feature gate.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct TimeTzUnchecked;

impl Checker for TimeTzUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if path != "time::util::refresh_tz_unchecked"
                && !(path.ends_with("::refresh_tz_unchecked") && path.contains("time"))
            {
                continue;
            }

            findings.push(Finding {
                rule_id: "time_tz_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`time::util::refresh_tz_unchecked` — re-reads the system timezone \
                     without platform soundness checks or thread synchronization; concurrent \
                     local-time reads from other threads are a data race (UB); \
                     use refresh_tz() → Option<()> which checks platform safety first"
                    .to_string(),
            });
        }

        findings
    }
}
