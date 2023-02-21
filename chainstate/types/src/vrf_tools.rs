// Copyright (c) 2023 RBB S.r.l
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

use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockHeader},
        config::EpochIndex,
    },
    primitives::H256,
};
use crypto::vrf::{
    transcript::{TranscriptAssembler, TranscriptComponent, WrappedTranscript},
    VRFError, VRFPublicKey, VRFReturn,
};
use thiserror::Error;

const TRANSCRIPT_MAIN_LABEL: &[u8] = b"MintlayerStakeVRF";
const RANDOMNESS_COMPONENT_LABEL: &[u8] = b"Randomness";
const SLOT_COMPONENT_LABEL: &[u8] = b"Slot";
const EPOCH_INDEX_COMPONENT_LABEL: &[u8] = b"EpochIndex";

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ProofOfStakeVRFError {
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(#[from] VRFError),
}

pub fn construct_transcript(
    epoch_index: EpochIndex,
    random_seed: &H256,
    block_timestamp: BlockTimestamp,
) -> WrappedTranscript {
    TranscriptAssembler::new(TRANSCRIPT_MAIN_LABEL)
        .attach(
            RANDOMNESS_COMPONENT_LABEL,
            TranscriptComponent::RawData(random_seed.as_bytes().to_vec()),
        )
        .attach(
            SLOT_COMPONENT_LABEL,
            TranscriptComponent::U64(block_timestamp.as_int_seconds()),
        )
        .attach(
            EPOCH_INDEX_COMPONENT_LABEL,
            TranscriptComponent::U64(epoch_index),
        )
        .finalize()
}

fn extract_vrf_output(
    vrf_data: &VRFReturn,
    vrf_public_key: VRFPublicKey,
    transcript: WrappedTranscript,
) -> Result<[u8; 32], VRFError> {
    match &vrf_data {
        VRFReturn::Schnorrkel(d) => d
            .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32>(
                vrf_public_key,
                transcript.into(),
            )
            .map(|a| a.into()),
    }
}

pub fn verify_vrf_and_get_vrf_output(
    epoch_index: EpochIndex,
    random_seed: &H256,
    vrf_data: &VRFReturn,
    vrf_public_key: &VRFPublicKey,
    spender_block_header: &BlockHeader,
) -> Result<H256, ProofOfStakeVRFError> {
    let transcript =
        construct_transcript(epoch_index, random_seed, spender_block_header.timestamp());

    vrf_public_key.verify_vrf_data(transcript.clone().into(), vrf_data)?;

    let vrf_raw_output = extract_vrf_output(vrf_data, vrf_public_key.clone(), transcript)?;

    Ok(vrf_raw_output.into())
}
