//! Top-level node runner as a library

mod options;
mod runner;

pub type Error = anyhow::Error;

pub use options::Options;
pub use runner::{initialize, run};

pub fn init_logging(opts: &Options) {
    logging::init_logging(opts.log_path.as_ref())
}
