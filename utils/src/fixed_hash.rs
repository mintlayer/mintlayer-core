// Copyright (c) 2026 RBB S.r.l
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

pub use fixed_hash::construct_fixed_hash as construct_fixed_hash_orig;

/// A macro that wraps the namesake one from `fixed_hash` (which is compiled with its `rand` feature
/// disabled) and adds custom RNG-related methods to the generated type.
///
/// It's a temporary workaround to avoid creating an RNG adapter every time `random_using` is
/// called. Once `fixed_hash` is updated to use `rand` v0.10, this wrapper can be removed.
#[macro_export]
macro_rules! construct_fixed_hash {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ( $n_bytes:expr ); ) => {
        $crate::fixed_hash::construct_fixed_hash_orig! {
            $(#[$attr])*
            $visibility struct $name($n_bytes);
        }

        $crate::impl_rand_for_fixed_hash!($name);
    }
}

// This is basically a copy of the similar macro in the fixed_hash src, except that here we use
// RNG primitives from `randomness` and omit the `randomize` and `random` methods that would create
// a new RNG on the fly (mainly because the RNG that they were creating originally is no longer
// infallible).
#[macro_export]
#[doc(hidden)]
macro_rules! impl_rand_for_fixed_hash {
    ( $name:ident ) => {
        impl randomness::distributions::Distribution<$name>
            for randomness::distributions::StandardUniform
        {
            fn sample<R: randomness::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                use randomness::RngExt as _;

                let mut ret = $name::zero();
                for byte in ret.as_bytes_mut().iter_mut() {
                    *byte = rng.random();
                }
                ret
            }
        }

        impl $name {
            pub fn randomize_using<R>(&mut self, rng: &mut R)
            where
                R: randomness::Rng + ?Sized,
            {
                use randomness::distributions::Distribution;
                *self = randomness::distributions::StandardUniform.sample(rng);
            }

            pub fn random_using<R>(rng: &mut R) -> Self
            where
                R: randomness::Rng + ?Sized,
            {
                let mut ret = Self::zero();
                ret.randomize_using(rng);
                ret
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;

    use randomness::RngExt as _;
    use serialization::{Decode, Encode};
    use test_utils::random::{make_seedable_rng, Seed};

    construct_fixed_hash! {
        #[derive(Encode, Decode)]
        pub struct TestHash(32);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        // Check some basic stuff coming from the original macro.
        let hash = TestHash::repeat_byte(0xAB);
        assert_eq!(hash.as_bytes(), &[0xAB; 32]);
        // Note: we actually want to call `clone` here, to make sure it's callable.
        #[allow(clippy::clone_on_copy)]
        let hash_clone = hash.clone();
        let hash_copy = hash;
        assert_eq!(hash_clone, hash);
        assert_eq!(hash_copy, hash);

        // Check rng calls
        let random_hash1 = rng.random::<TestHash>();
        let random_hash2 = TestHash::random_using(&mut rng);
        let random_hash3 = {
            let mut random_hash = hash;
            random_hash.randomize_using(&mut rng);
            assert_ne!(random_hash, hash);
            random_hash
        };

        let random_hashes = BTreeSet::from([random_hash1, random_hash2, random_hash3]);
        assert_eq!(random_hashes.len(), 3);
    }
}
