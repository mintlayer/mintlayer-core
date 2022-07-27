use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, Block, BlockHeader},
        signature::Transactable,
        stakelock::StakePoolData,
        ChainConfig, GenBlock, OutputSpentState, TxOutput,
    },
    primitives::{Compact, Id, Idable, H256},
    Uint256,
};
use crypto::vrf::{
    transcript::{TranscriptAssembler, TranscriptComponent, WrappedTranscript},
    VRFError, VRFPublicKey, VRFReturn,
};
use thiserror::Error;
use utils::ensure;

use super::{
    consensus_validator::{BlockIndexHandle, TransactionIndexHandle},
    gen_block_index::GenBlockIndex,
    PropertyQueryError,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoSError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Stake kernel hash failed to meet the target requirement")]
    StakeKernelHashTooHigh,
    #[error(
        "Stake block timestamp cannot be smaller than the kernel's (kernel: {0} < stake: {1})"
    )]
    TimestampViolation(BlockTimestamp, BlockTimestamp),
    #[error("Kernel inputs are empty")]
    NoKernel,
    #[error("Only one kernel allowed")]
    MultipleKernels,
    #[error("Could not load the transaction pointed to by an outpoint")]
    OutpointTransactionRetrievalError,
    #[error("Could not find the transaction pointed to by an outpoint")]
    OutpointTransactionNotFound,
    #[error("Outpoint access error. Possibly invalid")]
    InIndexOutpointAccessError,
    #[error("Output already spent")]
    KernelOutputAlreadySpent,
    #[error("Kernel block index load error with block id: {0}")]
    KernelBlockIndexLoadError(Id<GenBlock>),
    #[error("Kernel block index not found with block id: {0}")]
    KernelBlockIndexNotFound(Id<GenBlock>),
    #[error("Kernel input transaction retrieval error: {0}")]
    KernelTransactionRetrievalFailed(PropertyQueryError),
    #[error("Kernel output index out of range: {0}")]
    KernelOutputIndexOutOfRange(u32),
    #[error("Kernel input transaction not found")]
    KernelTransactionNotFound,
    #[error("Kernel header output load error")]
    KernelHeaderOutputDoesNotExist(Id<GenBlock>),
    #[error("Kernel header index out of range. Block id: {0} and index {1}")]
    KernelHeaderOutputIndexOutOfRange(Id<GenBlock>, u32),
    #[error("Bits to target conversion failed {0:?}")]
    BitsToTargetConversionFailed(Compact),
    #[error("Could not find previous block's stake modifer")]
    PrevStakeModiferNotFound,
    #[error("Could not find the previous block index of block: {0}")]
    PrevBlockIndexNotFound(Id<Block>),
    #[error("The kernel is not an ancestor of the current header of id {0}. This is a double-spend attempt at best")]
    KernelAncesteryCheckFailed(Id<Block>),
    #[error("Attempted to use a non-locked stake as stake kernel in block {0}")]
    InvalidOutputPurposeInStakeKernel(Id<Block>),
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(VRFError),
    #[error("Error while attempting to retrieve epoch data of index {0} with error: {1}")]
    EpochDataRetrievalQueryError(u64, PropertyQueryError),
    #[error("Epoch data not found for index: {0}")]
    EpochDataNotFound(u64),
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

fn verify_vrf_and_get_output(
    epoch_index: u64,
    random_seed: &H256,
    pos_data: &PoSData,
    pool_data: &StakePoolData,
    spender_block_header: &BlockHeader,
) -> Result<H256, ConsensusPoSError> {
    let transcript = construct_transcript(epoch_index, random_seed, spender_block_header);

    let vrf_data = pos_data.vrf_data();

    pool_data
        .vrf_public_key()
        .verify_vrf_data(transcript.clone().into(), vrf_data)
        .map_err(ConsensusPoSError::VRFDataVerificationFailed)?;

    let vrf_raw_output =
        extract_vrf_output(vrf_data, pool_data.vrf_public_key().clone(), transcript);

    Ok(vrf_raw_output.into())
}

fn check_stake_kernel_hash(
    epoch_index: u64,
    random_seed: &H256,
    pos_data: &PoSData,
    kernel_output: &TxOutput,
    spender_block_header: &BlockHeader,
) -> Result<H256, ConsensusPoSError> {
    let target: Uint256 = (*pos_data.bits())
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(*pos_data.bits()))?;

    let pool_data = match kernel_output.purpose() {
        common::chain::OutputPurpose::Transfer(_)
        | common::chain::OutputPurpose::LockThenTransfer(_, _) => {
            // only pool outputs can be staked
            return Err(ConsensusPoSError::InvalidOutputPurposeInStakeKernel(
                spender_block_header.get_id(),
            ));
        }

        common::chain::OutputPurpose::StakePool(d) => &**d,
    };

    let hash_pos: H256 = verify_vrf_and_get_output(
        epoch_index,
        random_seed,
        pos_data,
        pool_data,
        spender_block_header,
    )?;
    let hash_pos_arith: Uint256 = hash_pos.into();

    // TODO: calculate the total pool balance, not just from the delegation as done here, but also add all delegated stakes
    let pool_balance = kernel_output.value().into();

    // TODO: the target multiplication can overflow, use Uint512
    ensure!(
        hash_pos_arith <= target * pool_balance,
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(hash_pos)
}

/// Ensures that the kernel_block_index is an ancestor of header
fn ensure_correct_ancestry(
    header: &BlockHeader,
    prev_block_index: &GenBlockIndex,
    kernel_block_index: &GenBlockIndex,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<(), ConsensusPoSError> {
    let prev_block_index = match prev_block_index {
        GenBlockIndex::Block(bi) => bi,
        GenBlockIndex::Genesis(_) => return Ok(()),
    };
    let kernel_block_header_as_ancestor = block_index_handle
        .get_ancestor(prev_block_index, kernel_block_index.block_height())
        .map_err(|_| ConsensusPoSError::KernelAncesteryCheckFailed(header.get_id()))?;

    ensure!(
        kernel_block_header_as_ancestor.block_id() == kernel_block_index.block_id(),
        ConsensusPoSError::KernelAncesteryCheckFailed(header.block_id()),
    );
    Ok(())
}

pub fn check_proof_of_stake(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pos_data: &PoSData,
    block_index_handle: &dyn BlockIndexHandle,
    tx_index_retriever: &dyn TransactionIndexHandle,
) -> Result<(), ConsensusPoSError> {
    ensure!(
        !pos_data.kernel_inputs().is_empty(),
        ConsensusPoSError::NoKernel,
    );
    // in general this should not be an issue, but we have to first study this security model with one kernel
    ensure!(
        pos_data.kernel_inputs().len() == 1,
        ConsensusPoSError::MultipleKernels,
    );
    let kernel_outpoint =
        pos_data.kernel_inputs().get(0).ok_or(ConsensusPoSError::NoKernel)?.outpoint();
    let kernel_tx_index = tx_index_retriever
        .get_mainchain_tx_index(&kernel_outpoint.tx_id())
        .map_err(|_| ConsensusPoSError::OutpointTransactionRetrievalError)?
        .ok_or(ConsensusPoSError::OutpointTransactionNotFound)?;

    let kernel_block_id = kernel_tx_index.position().block_id_anyway();

    let kernel_block_index = block_index_handle
        .get_gen_block_index(&kernel_block_id)
        .map_err(|_| ConsensusPoSError::KernelBlockIndexLoadError(kernel_block_id))?
        .ok_or(ConsensusPoSError::KernelBlockIndexNotFound(kernel_block_id))?;

    let prev_block_index = block_index_handle
        .get_gen_block_index(header.prev_block_id())
        .expect("Database error while retrieving prev block index")
        .ok_or_else(|| ConsensusPoSError::PrevBlockIndexNotFound(header.get_id()))?;

    let epoch_index =
        chain_config.epoch_index_from_height(&prev_block_index.block_height().next_height());

    let random_seed = if epoch_index >= chain_config.epoch_index_seed_stride() {
        let index_to_retrieve = epoch_index - chain_config.epoch_index_seed_stride();
        *block_index_handle
            .get_epoch_data(index_to_retrieve)
            .map_err(|e| ConsensusPoSError::EpochDataRetrievalQueryError(index_to_retrieve, e))?
            .ok_or(ConsensusPoSError::EpochDataNotFound(index_to_retrieve))?
            .randomness()
    } else {
        *chain_config.initial_randomness()
    };

    ensure_correct_ancestry(
        header,
        &prev_block_index,
        &kernel_block_index,
        block_index_handle,
    )?;

    let kernel_output = match kernel_tx_index.position() {
        common::chain::SpendablePosition::Transaction(tx_pos) => tx_index_retriever
            .get_mainchain_tx_by_position(tx_pos)
            .map_err(ConsensusPoSError::KernelTransactionRetrievalFailed)?
            .ok_or(ConsensusPoSError::KernelTransactionNotFound)?
            .outputs()
            .get(kernel_outpoint.output_index() as usize)
            .ok_or_else(|| {
                ConsensusPoSError::KernelOutputIndexOutOfRange(kernel_outpoint.output_index())
            })?
            .clone(),
        common::chain::SpendablePosition::BlockReward(block_id) => kernel_block_index
            .block_reward_transactable()
            .outputs()
            .ok_or(ConsensusPoSError::KernelHeaderOutputDoesNotExist(*block_id))?
            .get(kernel_outpoint.output_index() as usize)
            .ok_or_else(|| {
                ConsensusPoSError::KernelHeaderOutputIndexOutOfRange(
                    *block_id,
                    kernel_outpoint.output_index(),
                )
            })?
            .clone(),
    };

    let is_input_already_spent = kernel_tx_index
        .get_spent_state(kernel_outpoint.output_index())
        .map_err(|_| ConsensusPoSError::InIndexOutpointAccessError)?;

    ensure!(
        is_input_already_spent == OutputSpentState::Unspent,
        ConsensusPoSError::KernelOutputAlreadySpent,
    );

    ensure!(
        header.timestamp() < kernel_block_index.block_timestamp(),
        ConsensusPoSError::TimestampViolation(
            kernel_block_index.block_timestamp(),
            header.timestamp()
        ),
    );

    let _hash_pos =
        check_stake_kernel_hash(epoch_index, &random_seed, pos_data, &kernel_output, header)?;
    Ok(())
}
