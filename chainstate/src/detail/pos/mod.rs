use chainstate_types::{block_index::BlockIndex, stake_modifer::PoSStakeModifier};
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, Block, BlockHeader},
        signature::Transactable,
        ChainConfig, OutputSpentState, TxOutput,
    },
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Compact, Id, Idable, H256,
    },
    Uint256,
};
use thiserror::Error;
use utils::ensure;

use super::{
    consensus_validator::{BlockIndexHandle, TransactionIndexHandle},
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
    KernelBlockIndexLoadError(Id<Block>),
    #[error("Kernel block index not found with block id: {0}")]
    KernelBlockIndexNotFound(Id<Block>),
    #[error("Kernel input transaction retrieval error: {0}")]
    KernelTransactionRetrievalFailed(PropertyQueryError),
    #[error("Kernel output index out of range: {0}")]
    KernelOutputIndexOutOfRange(u32),
    #[error("Kernel input transaction not found")]
    KernelTransactionNotFound,
    #[error("Kernel header output load error")]
    KernelHeaderOutputDoesNotExist(Id<Block>),
    #[error("Kernel header index out of range. Block id: {0} and index {1}")]
    KernelHeaderOutputIndexOutOfRange(Id<Block>, u32),
    #[error("Bits to target conversion failed {0:?}")]
    BitsToTargetConversionFailed(Compact),
    #[error("Could not find previous block's stake modifer")]
    PrevStakeModiferNotFound,
    #[error("Could not find the previous block index of block: {0}")]
    PrevBlockIndexNotFound(Id<Block>),
    #[error("The kernel is not an ancestor of the current header of id {0}. This is a double-spend attempt at best")]
    KernelAncesteryCheckFailed(Id<Block>),
}

fn check_stake_kernel_hash(
    target: Uint256,
    kernel_block_time: BlockTimestamp,
    kernel_output: TxOutput,
    spender_block_time: BlockTimestamp,
    prev_stake_modifier: &PoSStakeModifier,
) -> Result<H256, ConsensusPoSError> {
    use crypto::hash::StreamHasher;

    ensure!(
        spender_block_time < kernel_block_time,
        ConsensusPoSError::TimestampViolation(kernel_block_time, spender_block_time),
    );

    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(&prev_stake_modifier.value(), &mut hasher);
    hash_encoded_to(&kernel_output, &mut hasher);
    hash_encoded_to(&spender_block_time, &mut hasher);
    let hash_pos: H256 = hasher.finalize().into();
    let hash_pos_arith: Uint256 = hash_pos.into();

    // TODO: the target multiplication can overflow, use Uint512
    ensure!(
        hash_pos_arith <= target * kernel_output.value().into(),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(hash_pos)
}

/// Ensures that the kernel_block_index is an ancestor of header
fn ensure_correct_ancestry(
    header: &BlockHeader,
    prev_block_index: &BlockIndex,
    kernel_block_index: &BlockIndex,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<(), ConsensusPoSError> {
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
    _chain_config: &ChainConfig,
    header: &BlockHeader,
    pos_data: &PoSData,
    block_index_handle: &dyn BlockIndexHandle,
    tx_index_retriever: &dyn TransactionIndexHandle,
) -> Result<(), ConsensusPoSError> {
    ensure!(
        !pos_data.kernel_inputs().is_empty(),
        ConsensusPoSError::NoKernel
    );
    // in general this should not be an issue, but we have to first study this security model with one kernel
    ensure!(
        pos_data.kernel_inputs().len() == 1,
        ConsensusPoSError::MultipleKernels
    );
    let kernel_outpoint =
        pos_data.kernel_inputs().get(0).ok_or(ConsensusPoSError::NoKernel)?.outpoint();
    let kernel_tx_index = tx_index_retriever
        .get_mainchain_tx_index(&kernel_outpoint.tx_id())
        .map_err(|_| ConsensusPoSError::OutpointTransactionRetrievalError)?
        .ok_or(ConsensusPoSError::OutpointTransactionNotFound)?;

    let kernel_block_id = kernel_tx_index.position().block_id_anyway();

    let kernel_block_index = block_index_handle
        .get_block_index(kernel_block_id)
        .map_err(|_| ConsensusPoSError::KernelBlockIndexLoadError(kernel_block_id.clone()))?
        .ok_or_else(|| ConsensusPoSError::KernelBlockIndexNotFound(kernel_block_id.clone()))?;

    let prev_block_index = block_index_handle
        .get_block_index(header.prev_block_id().as_ref().expect("There has to be a prev block"))
        .expect("Database error while retrieving prev block index")
        .ok_or_else(|| ConsensusPoSError::PrevBlockIndexNotFound(header.get_id()))?;

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
            .block_header()
            .block_reward_transactable()
            .outputs()
            .ok_or_else(|| ConsensusPoSError::KernelHeaderOutputDoesNotExist(block_id.clone()))?
            .get(kernel_outpoint.output_index() as usize)
            .ok_or_else(|| {
                ConsensusPoSError::KernelHeaderOutputIndexOutOfRange(
                    block_id.clone(),
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

    let target: Uint256 = (*pos_data.bits())
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(*pos_data.bits()))?;

    let prev_stake_modifier = prev_block_index
        .preconnect_data()
        .stake_modifier()
        .ok_or(ConsensusPoSError::PrevStakeModiferNotFound)?;

    let _hash_pos = check_stake_kernel_hash(
        target,
        kernel_block_index.block_timestamp(),
        kernel_output,
        header.timestamp(),
        prev_stake_modifier,
    )?;
    Ok(())
}
