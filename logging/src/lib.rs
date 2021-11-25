pub use log;

pub fn is_only_terminal_output_logging() -> bool {
    return true;
}

pub fn is_file_output_supported() -> bool {
    return false;
}

pub fn init_logging<P: AsRef<std::path::Path>>(_log_file_path: Option<P>) {
    env_logger::init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
