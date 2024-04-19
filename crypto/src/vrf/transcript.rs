// Copyright (c) 2021-2022 RBB S.r.l
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

use schnorrkel::context::SigningTranscript;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptComponent {
    RawData(Vec<u8>),
    U64(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptAssembler {
    label: &'static [u8],
    components: Vec<(&'static [u8], TranscriptComponent)>,
}

// A wrapper that makes it unnecessary to directly use the merlin dependency
#[must_use]
#[derive(Clone)]
pub struct VRFTranscript(merlin::Transcript);

impl VRFTranscript {
    #[cfg(test)]
    pub(crate) fn append_u64(&mut self, label: &'static [u8], x: u64) {
        self.0.append_u64(label, x)
    }
}

impl SigningTranscript for VRFTranscript {
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.0.append_message(label, bytes)
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.0.challenge_bytes(label, dest)
    }

    fn witness_bytes_rng<R>(
        &self,
        label: &'static [u8],
        dest: &mut [u8],
        nonce_seeds: &[&[u8]],
        rng: R,
    ) where
        R: rand::prelude::RngCore + rand::prelude::CryptoRng,
    {
        self.0.witness_bytes_rng(label, dest, nonce_seeds, rng)
    }

    fn witness_bytes(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]]) {
        self.witness_bytes_rng(label, dest, nonce_seeds, crate::random::make_true_rng())
    }
}

impl TranscriptAssembler {
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            label,
            components: Vec::new(),
        }
    }

    pub fn attach(self, label: &'static [u8], value: TranscriptComponent) -> Self {
        let mut result = self;
        result.components.push((label, value));
        result
    }

    pub fn finalize(self) -> VRFTranscript {
        let mut transcript = merlin::Transcript::new(self.label);
        for component in &self.components {
            match &component.1 {
                TranscriptComponent::RawData(d) => transcript.append_message(component.0, d),
                TranscriptComponent::U64(d) => transcript.append_u64(component.0, *d),
            }
        }

        VRFTranscript(transcript)
    }
}

#[cfg(test)]
mod tests {

    use rand_chacha::ChaChaRng;

    use crate::random::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn manual_vs_assembled() {
        // build first transcript by manually filling values
        let mut manual_transcript = merlin::Transcript::new(b"initial");
        manual_transcript.append_message(b"abc", b"xyz");
        manual_transcript.append_u64(b"rx42", 424242);

        // build the second transcript using the assembler
        let assembled_transcript = TranscriptAssembler::new(b"initial")
            .attach(b"abc", TranscriptComponent::RawData(b"xyz".to_vec()))
            .attach(b"rx42", TranscriptComponent::U64(424242))
            .finalize();

        // build a random number generator using each transcript and ensure they both arrive to the same values
        let mut g1 = manual_transcript.build_rng().finalize(&mut ChaChaRng::from_seed([0u8; 32]));
        let mut g2 = assembled_transcript
            .0
            .build_rng()
            .finalize(&mut ChaChaRng::from_seed([0u8; 32]));

        for _ in 0..100 {
            assert_eq!(g1.gen::<u64>(), g2.gen::<u64>());
        }
    }
}
