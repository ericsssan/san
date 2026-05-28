/// Detects calls to `log::set_logger_racy` and `log::set_max_level_racy`.
///
/// Both functions are unsafe because they perform non-atomic global mutations that
/// can race with concurrent initializations or logging:
///
/// `log::set_logger_racy(logger)`:
///   • Installs a global logger without using a compare-and-swap; if called
///     concurrently with another `set_logger` or `set_logger_racy` call, the result
///     is immediate UB (the function's own comments say "plain UB" on race)
///   • Safe alternative: `log::set_logger(logger)` — uses atomic CAS, returns
///     `Err(SetLoggerError)` if a logger is already installed
///
/// `log::set_max_level_racy(level)`:
///   • On targets without atomic pointer support (e.g., `target_has_atomic = "ptr"`
///     absent) the underlying storage uses a `Cell`, which is not Send; updating
///     the level from multiple threads is a data race (UB)
///   • On targets with atomics the race is benign, but code should prefer the
///     safe `log::set_max_level(level)` which always uses atomics
///
/// Both functions are intended only for use in `#[global_allocator]`
/// implementations where calling the safe variants would cause re-entrant
/// allocation. Any other use is almost certainly a mistake.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct LogRacy;

impl Checker for LogRacy {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path == "log::set_logger_racy" {
                (
                    "log::set_logger_racy",
                    "installs a global logger without atomic CAS; concurrent calls with any \
                     other logger-installation function are immediate UB; use log::set_logger() \
                     which uses CAS and returns Err if already set",
                )
            } else if path == "log::set_max_level_racy" {
                (
                    "log::set_max_level_racy",
                    "on targets without atomic pointer support the underlying Cell is not \
                     thread-safe — concurrent writes from multiple threads are a data race (UB); \
                     use log::set_max_level() which always uses atomic storage",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "log_racy",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
