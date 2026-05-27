fn main() {
    // Bug: refresh_tz_unchecked — skips platform soundness check; data race with
    // concurrent local-time reads is UB. Use refresh_tz() → Option<()> instead.
    unsafe { time::util::refresh_tz_unchecked(); }
}
