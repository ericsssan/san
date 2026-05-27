// Bug: unsafe impl Pod — implementer must verify no padding, all bit patterns valid.
// Bug: unsafe impl Zeroable — all-zeros must be a valid representation.
#[derive(Copy, Clone)]
#[repr(C)]
struct MyVertex {
    x: f32,
    y: f32,
    z: f32,
}

// Manually implementing what #[derive(Pod, Zeroable)] would do.
// San flags these because manual impls require careful review.
unsafe impl bytemuck::Pod for MyVertex {}
unsafe impl bytemuck::Zeroable for MyVertex {}

fn main() {
    let v = MyVertex { x: 1.0, y: 2.0, z: 3.0 };
    let bytes: &[u8] = bytemuck::bytes_of(&v);
    println!("{} bytes", bytes.len());
}
