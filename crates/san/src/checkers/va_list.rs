/// Detects calls to `VaList::next_arg` (C variadic argument extraction).
/// (Requires `#![feature(c_variadic)]`.)
///
/// `VaList::next_arg::<T>()` reads the next argument from a C-style variadic
/// argument list (`...`). The caller must guarantee:
///
///   • The next argument in the call was **actually passed as type `T`** (or as
///     a type that C's default argument promotion converts to `T`); reading the
///     wrong type reinterprets the underlying bytes as `T` — this is immediate
///     undefined behaviour, not just a logic error
///   • The variadic list has **not been exhausted**: calling `next_arg` after all
///     arguments have been consumed reads past the end of the call-frame or ABI
///     structure, producing garbage values or a crash
///   • `T` must implement `VaArgSafe` — but this alone does not guarantee that
///     the caller actually passed a `T`; the type-safety check must be done
///     by convention (C does not propagate type information to va_arg)
///
/// Mismatches between the passed type and the extracted type `T` are a classic
/// source of security vulnerabilities (e.g., reading a pointer where an int was
/// passed gives a partial/garbage pointer value; the converse may expose memory).
///
/// C promotion rules: `i8`/`i16` → `i32`, `f32` → `f64`, etc. — read the
/// promoted type if unsure.
///
/// Common bugs: calling `next_arg::<i32>()` when a `u64` was passed, missing a
/// format-string controlled argument count, off-by-one exhaustion.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct VaListNextArg;

impl Checker for VaListNextArg {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("VaList") || !path.contains("next_arg") {
                continue;
            }

            findings.push(Finding {
                rule_id: "va_list",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`VaList::next_arg` — the type parameter T must exactly match \
                          the type of the next argument as passed by the caller (modulo \
                          C default promotion: i8/i16 → i32, f32 → f64); a type mismatch \
                          reinterprets raw bytes as T (UB); calling past the last argument \
                          reads indeterminate memory (nightly feature `c_variadic`)"
                    .to_string(),
            });
        }

        findings
    }
}
