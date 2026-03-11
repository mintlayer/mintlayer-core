// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Mutex;

pub use rand::prelude::SliceRandom;
pub use rand::{seq, CryptoRng, Rng, RngCore, SeedableRng};

pub mod distributions {
    pub use rand::distributions::{
        Alphanumeric, DistString, Distribution, Standard, WeightedIndex,
    };
    pub mod uniform {
        pub use rand::distributions::uniform::SampleRange;
    }
}

pub mod rngs {
    pub use rand::rngs::mock::StepRng;
    pub use rand::rngs::OsRng;
}

#[must_use]
pub fn make_true_rng() -> impl Rng + CryptoRng {
    rand::rngs::StdRng::from_entropy()
}

#[must_use]
pub fn make_pseudo_rng() -> impl Rng {
    rand::rngs::ThreadRng::default()
}

/// A wrapper over `Mutex<Box<R>>` that implements `RngCore` and `CryptoRng` if `R` does the same.
///
/// This can be passed to a function that accept `impl Rng`, to avoid the need to lock the mutex
/// for the entire duration of the function call.
/// In particular, this is useful in async code, because passing a `MutexGuard` across an `await`
/// point produces a non-Send future.
pub struct BoxedRngMutexWrapper<'a, R: ?Sized>(&'a Mutex<Box<R>>);

impl<'a, R: ?Sized> BoxedRngMutexWrapper<'a, R> {
    pub fn new(rng: &'a Mutex<Box<R>>) -> Self {
        Self(rng)
    }
}

impl<'a, R: RngCore + ?Sized> RngCore for BoxedRngMutexWrapper<'a, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.lock().expect("poisoned mutex").next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.lock().expect("poisoned mutex").next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.lock().expect("poisoned mutex").fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.lock().expect("poisoned mutex").try_fill_bytes(dest)
    }
}

impl<'a, R: CryptoRng> CryptoRng for BoxedRngMutexWrapper<'a, R> {}

#[cfg(test)]
mod tests {
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    use super::*;

    // `DumbRng` implements `RngCore` but not `CryptoRng`.
    #[allow(dead_code)]
    struct DumbRng;

    impl RngCore for DumbRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            dest.fill(0);
            Ok(())
        }
    }

    assert_impl_all!(BoxedRngMutexWrapper<'static, DumbRng>: RngCore);
    assert_not_impl_any!(BoxedRngMutexWrapper<'static, DumbRng>: CryptoRng);

    // Note: `ThreadRng` actually implements `CryptoRng`, even though we use it in `make_pseudo_rng`.
    assert_impl_all!(BoxedRngMutexWrapper<'static, rand::rngs::ThreadRng>: RngCore, CryptoRng);
}
