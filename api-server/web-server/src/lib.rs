pub mod error;

pub use error::APIServerDaemonError;

#[derive(Debug, Clone)]
pub struct APIServerState {
    pub example_shared_value: String,
}
