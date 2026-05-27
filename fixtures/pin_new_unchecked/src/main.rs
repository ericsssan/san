use std::pin::Pin;

fn main() {
    let mut x: i32 = 5;
    // Bug: Pin::new_unchecked — pointee must not be moved or invalidated while pinned.
    let _pin: Pin<&mut i32> = unsafe { Pin::new_unchecked(&mut x) };

    // Bug: Pin::map_unchecked — must only project to structurally-pinned fields.
    let mut y: (i32, i32) = (1, 2);
    let pin2: Pin<&mut (i32, i32)> = unsafe { Pin::new_unchecked(&mut y) };
    let _projected: Pin<&mut i32> = unsafe { pin2.map_unchecked_mut(|t| &mut t.0) };

    // Bug: Pin::get_unchecked_mut — must not move out of the &mut T for non-Unpin types.
    let mut z: i32 = 10;
    let pin3: Pin<&mut i32> = unsafe { Pin::new_unchecked(&mut z) };
    let _inner: &mut i32 = unsafe { pin3.get_unchecked_mut() };

    // Bug: Pin::into_inner_unchecked — extracted value must remain pinned if !Unpin.
    let mut w: i32 = 99;
    let pin4: Pin<&mut i32> = unsafe { Pin::new_unchecked(&mut w) };
    let _w_ref: &mut i32 = unsafe { Pin::into_inner_unchecked(pin4) };
}
