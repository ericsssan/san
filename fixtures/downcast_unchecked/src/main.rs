#![feature(downcast_unchecked)]
use std::any::Any;

fn main() {
    // Bug: downcast_unchecked on Box<dyn Any> — if the actual type is not u32,
    // the result is type-confusion UB.
    let b: Box<dyn Any> = Box::new(42u32);
    let _n: Box<u32> = unsafe { b.downcast_unchecked::<u32>() };

    // Bug: downcast_unchecked on Rc<dyn Any>.
    let r = std::rc::Rc::new(99u64) as std::rc::Rc<dyn Any>;
    let _m: std::rc::Rc<u64> = unsafe { r.downcast_unchecked::<u64>() };
}
