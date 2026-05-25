use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: san <file>");
        return ExitCode::from(2);
    };

    let source = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("san: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let findings = san::analyze(&source);
    for f in &findings {
        println!("{path}:{}: {}", f.line, f.message);
    }

    if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
