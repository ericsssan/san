#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;

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
        let dcx = tcx.dcx();
        for f in findings {
            dcx.span_warn(f.span, format!("[san::{}] {}", f.rule_id, f.message));
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
