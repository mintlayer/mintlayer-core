//! Top-level node runner as a library

mod options;
mod runner;

pub use options::Options;
pub use runner::{initialize, run};
