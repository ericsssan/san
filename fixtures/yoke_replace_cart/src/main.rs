use yoke::{Yoke, Yokeable};

#[derive(Yokeable, Clone)]
struct MyStr<'a>(&'a str);

fn main() {
    let cart = String::from("hello world");
    let yoke: Yoke<MyStr<'static>, String> = Yoke::attach_to_cart(cart, |s| MyStr(s));

    // Bug: replace_cart — closure must transfer ownership of referenced data into
    // the new cart. Failing to do so leaves the yokeable with dangling references.
    let _yoke2: Yoke<MyStr<'static>, String> = unsafe {
        yoke.replace_cart(|old_cart| old_cart + " extra")
    };
}
