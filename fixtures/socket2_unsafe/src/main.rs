// Bug: SockAddr::try_init — closure must fully initialize the sockaddr_storage
// and set *len to the correct family struct size.
// Bug: SockAddr::set_length — overwrites length without validating against the
// actual family struct size.
use socket2::SockAddr;

fn main() {
    let (_, mut addr) = unsafe {
        SockAddr::try_init(|storage, len| {
            // Partial initialization: only setting length, not ss_family
            *len = std::mem::size_of::<libc::sockaddr_in>() as _;
            Ok::<(), std::io::Error>(())
        })
    }.unwrap();

    // Bug: set_length without verifying it matches the actual struct
    unsafe { addr.set_length(2); }

    println!("family: {}", addr.family());
}
