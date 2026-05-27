use regex_automata::dfa::dense;

fn main() {
    // Build a DFA and serialize it to bytes.
    let dfa = dense::DFA::new("foo|bar").unwrap();
    let (bytes, pad) = dfa.to_bytes_native_endian();

    // Bug: from_bytes_unchecked — loading DFA bytes without format validation;
    // crafted bytes can encode out-of-bounds state transitions (UB during search).
    // Only safe if the bytes were produced by the same binary version.
    let _dfa2 = unsafe { dense::DFA::from_bytes_unchecked(&bytes[pad..]).unwrap() };
}
