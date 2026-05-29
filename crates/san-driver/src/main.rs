#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface::Compiler;
use rustc_middle::ty::TyCtxt;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

struct SanCallbacks;

impl Callbacks for SanCallbacks {
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> Compilation {
        if env::var("SAN_DEBUG_PATHS").is_ok() {
            san::debug_print_all_paths(tcx);
        }
        let findings = san::run_checks(tcx);
        // Emit via span_warn for IDE / normal builds (workspace members).
        // Also emit directly to stderr so findings are visible when cargo
        // applies --cap-lints allow to dependency crates (RUSTC_WRAPPER mode).
        let cap_lints = env::var_os("RUSTC_WORKSPACE_WRAPPER").is_none()
            && env::var_os("RUSTC_WRAPPER").is_some();
        let dcx = tcx.dcx();
        let sm = tcx.sess.source_map();
        for f in &findings {
            if cap_lints {
                // span_warn is silenced for deps; print directly instead.
                let loc = sm.span_to_diagnostic_string(f.span);
                eprintln!("warning[san::{}]: {}", f.rule_id, f.message);
                eprintln!("  --> {loc}");
            } else {
                dcx.span_warn(f.span, format!("[san::{}] {}", f.rule_id, f.message));
            }
        }
        Compilation::Continue
    }
}

fn detect_sysroot() -> Option<String> {
    if let Ok(s) = env::var("SYSROOT") {
        return Some(s);
    }
    let out = std::process::Command::new("rustc")
        .arg("--print=sysroot")
        .output()
        .ok()?;
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn main() -> ExitCode {
    let orig_args: Vec<String> = env::args().collect();

    let wrapper_mode = orig_args
        .get(1)
        .map(PathBuf::from)
        .and_then(|p| p.file_stem().map(|s| s.to_os_string()))
        .is_some_and(|stem| stem == "rustc");

    let mut args: Vec<String> = if wrapper_mode {
        orig_args.into_iter().skip(1).collect()
    } else {
        orig_args
    };

    // Cargo probes the wrapper with `san rustc -vV` to get version info.
    // Passthrough directly to the real rustc for any non-compilation invocation.
    let is_version_probe = args.iter().any(|a| a == "-vV" || a == "--version" || a == "-V");
    let is_print_only = args.iter().any(|a| a.starts_with("--print=") || a == "--print");
    if is_version_probe || is_print_only {
        let status = std::process::Command::new(&args[0])
            .args(&args[1..])
            .status()
            .unwrap_or_else(|e| panic!("failed to run rustc: {e}"));
        return if status.success() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }

    let has_sysroot = args
        .iter()
        .any(|a| a == "--sysroot" || a.starts_with("--sysroot="));
    if !has_sysroot {
        if let Some(sr) = detect_sysroot() {
            args.push(format!("--sysroot={sr}"));
        }
    }

    let mut callbacks = SanCallbacks;
    rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(&args, &mut callbacks);
    })
}
