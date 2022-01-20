//! Loom-based concurrency primitives

pub use loom::sync;
pub use loom::thread;

pub mod concurrency {
    pub use loom::model;
}
