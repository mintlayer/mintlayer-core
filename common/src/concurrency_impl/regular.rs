//! Regular concurrency primitives

// TODO we may want some of the following to come from tokio instead
pub use std::sync;
pub use std::thread;

pub mod concurrency {
    /// Regular concurrency model.
    ///
    /// Like `loom::model` but runs the body under normal concurrency primitives. Useful for
    /// writing tests that support both loom-based and normal execution.
    pub fn model<F: Fn() + Sync + Send + 'static>(body: F) {
        body()
    }
}
