use super::*;
use static_assertions::*;

assert_impl_all!(ChainstateInterfaceImpl: Send);

// TODO: write tests for consensus crate
