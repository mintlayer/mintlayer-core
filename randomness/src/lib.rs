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

pub mod adapters;

use std::sync::Mutex;

pub use rand::prelude::{IndexedMutRandom, IndexedRandom, SliceRandom};
pub use rand::{CryptoRng, Rng, RngExt, SeedableRng, TryCryptoRng, TryRng, seq};

pub mod distributions {
    pub use rand::distr::{
        weighted::WeightedIndex, Alphanumeric, Distribution, Open01, SampleString, StandardUniform,
    };
    pub mod uniform {
        pub use rand::distr::uniform::SampleRange;
    }
}

pub mod rngs {
    pub use rand::rngs::SysRng;
}

pub mod rand_core_utils {
    pub use rand_core::utils::*;
}

#[must_use]
pub fn make_true_rng() -> impl CryptoRng {
    // Note: the old call `StdRng::from_entropy()` from rand v0.8.x that we used to have here would
    // also panic on RNG creation failure. In either case, the possible failure comes from `getrandom`,
    // which states in its docs (https://docs.rs/getrandom/latest/getrandom/#error-handling)
    // that the failure is highly unlikely and that after the first successful call one can be
    // reasonably confident that no failure will occur. So panicking on failure is reasonable
    // behavior here.
    // TODO: it's still better to propagate the error, to fail gracefully in such a situation.
    rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).expect("RNG creation failed")
}

#[must_use]
pub fn make_pseudo_rng() -> impl Rng {
    rand::rngs::ThreadRng::default()
}

/// A wrapper over `Mutex<Box<R>>` that implements `Rng` and `CryptoRng` if `R` does the same.
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

impl<'a, R: Rng + ?Sized> TryRng for BoxedRngMutexWrapper<'a, R> {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.lock().expect("poisoned mutex").next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.lock().expect("poisoned mutex").next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.lock().expect("poisoned mutex").fill_bytes(dest);
        Ok(())
    }
}

// Note: `CryptoRng` is implemented automatically for all `R: TryCryptoRng<Error = Infallible>`.
impl<'a, R: TryCryptoRng<Error = std::convert::Infallible>> TryCryptoRng
    for BoxedRngMutexWrapper<'a, R>
{
}

#[cfg(test)]
mod tests {
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    use crate::adapters::*;

    use super::*;

    // `NonCryptoRngType` implements `Rng` but not `CryptoRng`.
    #[allow(dead_code)]
    struct NonCryptoRngType;

    impl TryRng for NonCryptoRngType {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(0);
            Ok(())
        }
    }

    #[allow(dead_code)]
    type CryptoRngType = rand::rngs::StdRng;

    // Sanity checks
    assert_impl_all!(CryptoRngType: Rng, CryptoRng);
    assert_impl_all!(NonCryptoRngType: Rng);
    assert_not_impl_any!(NonCryptoRngType: CryptoRng);

    assert_impl_all!(BoxedRngMutexWrapper<'static, NonCryptoRngType>: Rng);
    assert_not_impl_any!(BoxedRngMutexWrapper<'static, NonCryptoRngType>: CryptoRng);
    assert_impl_all!(BoxedRngMutexWrapper<'static, CryptoRngType>: Rng, CryptoRng);

    assert_impl_all!(Rng08Adapter<NonCryptoRngType>: rand_0_8::RngCore);
    assert_not_impl_any!(Rng08Adapter<NonCryptoRngType>: rand_0_8::CryptoRng);
    assert_impl_all!(Rng08Adapter<CryptoRngType>: rand_0_8::Rng, rand_0_8::CryptoRng);
}
