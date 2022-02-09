//! An abstraction over concurrency primitives
//!
//! This exists mainly to support permutation testing with loom. If loom is enabled, concurrency
//! primitives from loom are exported. Otherwise, standard concurrency primitives are used.

#[cfg(loom)]
#[path = "loom.rs"]
mod this;

#[cfg(not(loom))]
#[path = "regular.rs"]
mod this;

pub use this::*;
