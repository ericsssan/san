use std::env;
use std::path::PathBuf;
use std::process::{self, Command};

fn find_san_driver() -> Option<PathBuf> {
    // When installed, san-driver lives next to cargo-san.
    // During development both land in target/{debug,release}/.
    if let Ok(exe) = env::current_exe() {
        let sibling = exe.with_file_name("san-driver");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    // Fallback: search PATH.
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("san-driver");
            candidate.exists().then_some(candidate)
        })
    })
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    // When invoked via `cargo san`, cargo prepends the subcommand name as
    // argv[1]. Strip it so the rest are plain cargo-check args.
    if args.get(1).is_some_and(|a| a == "san") {
        args.remove(1);
    }
    let extra_args = &args[1..]; // everything the user typed after `cargo san`

    let driver = find_san_driver().unwrap_or_else(|| {
        eprintln!("error: san-driver not found next to cargo-san or on PATH");
        process::exit(1);
    });

    let status = Command::new("cargo")
        .arg("check")
        .args(extra_args)
        .env("RUSTC_WORKSPACE_WRAPPER", &driver)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to run cargo: {e}");
            process::exit(1);
        });

    process::exit(status.code().unwrap_or(1));
}
