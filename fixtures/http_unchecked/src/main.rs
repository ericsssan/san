use http::HeaderValue;
use bytes::Bytes;

fn main() {
    // Bug: from_maybe_shared_unchecked — no validation; CRLF bytes enable header injection.
    // In release builds the debug-mode panic is absent.
    let bytes = Bytes::from("application/json");
    let _hv: HeaderValue = unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) };
}
