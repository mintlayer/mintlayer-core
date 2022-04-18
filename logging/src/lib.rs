pub use log;

pub fn is_only_terminal_output_logging() -> bool {
    true
}

pub fn is_file_output_supported() -> bool {
    false
}

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

pub fn init_logging<P: AsRef<std::path::Path>>(_log_file_path: Option<P>) {
    INITIALIZE_LOGGER_ONCE_FLAG.call_once(|| env_logger::init());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn initialize_twice() {
        init_logging::<&std::path::Path>(None);
        init_logging::<&std::path::Path>(None);
    }
}
