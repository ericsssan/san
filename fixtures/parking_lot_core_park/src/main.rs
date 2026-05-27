use parking_lot_core::{park, ParkToken};
use std::sync::atomic::{AtomicBool, Ordering};

static FLAG: AtomicBool = AtomicBool::new(false);

fn main() {
    let key = &FLAG as *const _ as usize;

    // Bug: park with unsafe callbacks — closures run with queue lock held and
    // must not panic, allocate, or call back into parking_lot.
    let result = unsafe {
        park(
            key,
            || false, // validate: return false → don't actually sleep
            || {},
            |_, _| {},
            ParkToken(0),
            None,
        )
    };
    println!("park result: {:?}", result);
}
