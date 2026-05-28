/// Detects calls to `regex_automata::dfa::dense::DFA::from_bytes_unchecked`
/// and `regex_automata::dfa::sparse::DFA::from_bytes_unchecked`.
///
/// `DFA::from_bytes_unchecked(bytes)` deserializes a precompiled DFA from raw
/// bytes without validating the serialized format. The safe alternative,
/// `DFA::from_bytes`, validates that the bytes represent a correctly-formed DFA
/// before returning.
///
/// Loading from untrusted bytes without validation can cause:
///   • **Out-of-bounds state transitions**: a crafted DFA may encode state
///     transitions that index outside the transition table, causing the
///     automaton execution to read arbitrary memory
///   • **Type confusion**: the DFA uses internal tables with specific endianness
///     and stride assumptions; a byte array with wrong metadata will produce
///     incorrect state machine behavior or memory reads at wrong offsets
///   • **Use of freed or invalid memory**: if the bytes contain a self-referential
///     structure with an invalid offset, the deserialized DFA may reference
///     memory it does not own
///
/// The caller must guarantee:
///   • The bytes were produced by the same version of `regex-automata` with the
///     same endianness and architecture word size
///   • The bytes are fully trusted (not received from network, files, or other
///     untrusted sources without prior integrity verification)
///
/// Common bugs: caching a serialized DFA to disk and loading it with
/// `from_bytes_unchecked` across binary updates that change the DFA format,
/// or loading a DFA received from an untrusted peer without a signature check.
///
/// Safe alternative: `DFA::from_bytes(bytes)` which returns `Result` and
/// validates the format before returning the DFA.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RegexAutomataUnchecked;

impl Checker for RegexAutomataUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("regex_automata") || !path.ends_with("::from_bytes_unchecked") {
                continue;
            }

            let dfa_kind = if path.contains("sparse") { "sparse" } else { "dense" };

            findings.push(Finding {
                rule_id: "regex_automata_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{dfa_kind}::DFA::from_bytes_unchecked` — deserializes a DFA without \
                     format validation; crafted bytes can produce out-of-bounds state \
                     transitions or type confusion UB; only safe for bytes produced by the \
                     same binary with an integrity guarantee; use from_bytes() for untrusted input"
                ),
            });
        }

        findings
    }
}
