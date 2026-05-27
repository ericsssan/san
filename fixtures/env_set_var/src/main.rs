fn main() {
    // Bug: set_var is not thread-safe on POSIX — any concurrent thread reading
    // the environment (via env::var, Command, or C getenv) is a data race.
    unsafe { std::env::set_var("MY_VAR", "hello") };

    // Bug: remove_var has the same hazard.
    unsafe { std::env::remove_var("MY_VAR") };

    println!("env ops done");
}
