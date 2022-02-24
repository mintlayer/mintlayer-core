#![deny(clippy::clone_on_ref_ptr)]

pub mod pool;

pub use pool::Error as MempoolError;
