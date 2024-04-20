// Copyright (c) 2021-2024 RBB S.r.l
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

pub mod no_rng;
pub mod traits;
pub mod with_rng;

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::{no_rng::VRFTranscript, traits::SignableTranscript};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn ensure_both_with_and_without_rng_are_equivalent(#[case] seed: Seed) {
        use randomness::Rng;

        use crate::vrf::transcript::with_rng::VRFTranscriptWithRng;

        let no_rng_value = {
            let mut rng = make_seedable_rng(seed);

            let assembled_transcript = VRFTranscript::new(b"initial")
                .attach_raw_data(b"abc", b"xyz")
                .attach_u64(b"rx42", 424242);

            let mut generator = assembled_transcript.take().build_rng().finalize(&mut rng);

            (0..100).map(|_| generator.gen::<u64>()).collect::<Vec<_>>()
        };

        let with_rng_value = {
            let rng1 = make_seedable_rng(seed);
            let mut rng2 = make_seedable_rng(seed);

            let assembled_transcript = VRFTranscriptWithRng::new(b"initial", rng1)
                .attach_raw_data(b"abc", b"xyz")
                .attach_u64(b"rx42", 424242);

            let mut generator = assembled_transcript.take().build_rng().finalize(&mut rng2);

            (0..100).map(|_| generator.gen::<u64>()).collect::<Vec<_>>()
        };

        assert_eq!(with_rng_value, no_rng_value);
    }
}
