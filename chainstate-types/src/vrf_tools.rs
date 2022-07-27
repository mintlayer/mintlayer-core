use common::{
    chain::block::{consensus_data::PoSData, BlockHeader},
    primitives::H256,
};
use crypto::vrf::{
    transcript::{TranscriptAssembler, TranscriptComponent, WrappedTranscript},
    VRFError, VRFPublicKey, VRFReturn,
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ProofOfStakeVRFError {
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(VRFError),
}

fn construct_transcript(
    epoch_index: u64,
    random_seed: &H256,
    spender_block_header: &BlockHeader,
) -> WrappedTranscript {
    TranscriptAssembler::new(b"MintlayerStakeVRF")
        .attach(
            b"Randomness",
            TranscriptComponent::RawData(random_seed.as_bytes().to_vec()),
        )
        .attach(
            b"Slot",
            TranscriptComponent::U64(spender_block_header.timestamp().as_int_seconds() as u64),
        )
        .attach(b"EpochIndex", TranscriptComponent::U64(epoch_index))
        .finalize()
}

fn extract_vrf_output(
    vrf_data: &VRFReturn,
    vrf_public_key: VRFPublicKey,
    transcript: WrappedTranscript,
) -> [u8; 32] {
    match &vrf_data {
        VRFReturn::Schnorrkel(d) => d
            .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32>(
                vrf_public_key,
                transcript.into(),
            )
            .unwrap()
            .into(),
    }
}

pub fn verify_vrf_and_get_vrf_output(
    epoch_index: u64,
    random_seed: &H256,
    pos_data: &PoSData,
    vrf_public_key: &VRFPublicKey,
    spender_block_header: &BlockHeader,
) -> Result<H256, ProofOfStakeVRFError> {
    let transcript = construct_transcript(epoch_index, random_seed, spender_block_header);

    let vrf_data = pos_data.vrf_data();

    vrf_public_key
        .verify_vrf_data(transcript.clone().into(), vrf_data)
        .map_err(ProofOfStakeVRFError::VRFDataVerificationFailed)?;

    let vrf_raw_output = extract_vrf_output(vrf_data, vrf_public_key.clone(), transcript);

    Ok(vrf_raw_output.into())
}
