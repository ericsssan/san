use rkyv::{Archive, Serialize};
use rkyv::ser::{serializers::AllocSerializer, Serializer};

#[derive(Archive, Serialize)]
struct Config {
    timeout: u32,
    retries: u32,
}

fn main() {
    let config = Config { timeout: 30, retries: 3 };

    let mut serializer = AllocSerializer::<256>::default();
    serializer.serialize_value(&config).unwrap();
    let bytes = serializer.into_serializer().into_inner();

    // Bug: archived_root skips alignment and type validation entirely.
    let archived = unsafe { rkyv::archived_root::<Config>(&bytes) };
    println!("timeout={} retries={}", archived.timeout, archived.retries);

    // Bug: archived_root_mut gives mutable access without any validation.
    let mut bytes_mut = bytes;
    let archived_mut = unsafe { rkyv::archived_root_mut::<Config>(std::pin::Pin::new(&mut bytes_mut)) };
    let _ = archived_mut;
}
