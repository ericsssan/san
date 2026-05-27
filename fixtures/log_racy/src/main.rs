struct MyLogger;
impl log::Log for MyLogger {
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, _: &log::Record) {}
    fn flush(&self) {}
}
static MY_LOGGER: MyLogger = MyLogger;

fn main() {
    // Bug: set_logger_racy — concurrent initialization is immediate UB.
    unsafe { log::set_logger_racy(&MY_LOGGER).unwrap(); }

    // Bug: set_max_level_racy — non-atomic on some targets; data race is UB.
    unsafe { log::set_max_level_racy(log::LevelFilter::Info); }
}
