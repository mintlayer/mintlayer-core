use chainstate_types::stake_modifer::PoSStakeModifier;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, Block, BlockHeader},
        signature::Transactable,
        ChainConfig, OutputSpentState, TxOutput,
    },
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Compact, Id, H256,
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
pub enum PoSError {
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
    OutputAlreadySpent,
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
    #[error("Kernel header retrieval error {0}")]
    KernelHeaderRetrievalFailed(PropertyQueryError),
    #[error("Bits to target conversion failed {0:?}")]
    BitsToTargetConversionFailed(Compact),
    #[error("Could not find previous block's stake modifer")]
    PrevStakeModiferNotFound,
}

fn check_stake_kernel_hash(
    target: Uint256,
    kernel_block_time: BlockTimestamp,
    kernel_output: TxOutput,
    spender_block_time: BlockTimestamp,
    prev_stake_modifier: PoSStakeModifier,
) -> Result<H256, PoSError> {
    use crypto::hash::StreamHasher;

    ensure!(
        spender_block_time < kernel_block_time,
        PoSError::TimestampViolation(kernel_block_time, spender_block_time),
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
        PoSError::StakeKernelHashTooHigh
    );

    Ok(hash_pos)
}

fn get_stake_modifier(
    _chain_config: &ChainConfig,
    _block_id: &Id<Block>,
    _block_index_handle: &dyn BlockIndexHandle,
) -> Result<Option<PoSStakeModifier>, PoSError> {
    todo!()
}

pub fn check_proof_of_stake(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pos_data: PoSData,
    block_index_handle: &dyn BlockIndexHandle,
    tx_index_retriever: &dyn TransactionIndexHandle,
) -> Result<(), PoSError> {
    ensure!(!pos_data.kernel_inputs().is_empty(), PoSError::NoKernel);
    // in general this should not be an issue, but we have to first study this security model with one kernel
    ensure!(
        pos_data.kernel_inputs().len() == 1,
        PoSError::MultipleKernels
    );
    let kernel_outpoint = pos_data.kernel_inputs().get(0).ok_or(PoSError::NoKernel)?.outpoint();
    let kernel_tx_index = tx_index_retriever
        .get_mainchain_tx_index(&kernel_outpoint.tx_id())
        .map_err(|_| PoSError::OutpointTransactionRetrievalError)?
        .ok_or(PoSError::OutpointTransactionNotFound)?;

    let kernel_block_id = kernel_tx_index.position().block_id_anyway();

    let kernel_block_header = block_index_handle
        .get_block_index(kernel_block_id)
        .map_err(|_| PoSError::KernelBlockIndexLoadError(kernel_block_id.clone()))?
        .ok_or(PoSError::KernelBlockIndexNotFound(kernel_block_id.clone()))?;

    // TODO: ensure that kernel_block_header is an ancestor of header

    let kernel_output = match kernel_tx_index.position() {
        common::chain::SpendablePosition::Transaction(tx_pos) => tx_index_retriever
            .get_mainchain_tx_by_position(tx_pos)
            .map_err(PoSError::KernelTransactionRetrievalFailed)?
            .ok_or(PoSError::KernelTransactionNotFound)?
            .outputs()
            .get(kernel_outpoint.output_index() as usize)
            .ok_or(PoSError::KernelOutputIndexOutOfRange(
                kernel_outpoint.output_index(),
            ))?
            .clone(),
        common::chain::SpendablePosition::BlockReward(block_id) => kernel_block_header
            .block_header()
            .block_reward_transactable()
            .outputs()
            .ok_or(PoSError::KernelHeaderOutputDoesNotExist(block_id.clone()))?
            .get(kernel_outpoint.output_index() as usize)
            .ok_or(PoSError::KernelHeaderOutputIndexOutOfRange(
                block_id.clone(),
                kernel_outpoint.output_index(),
            ))?
            .clone(),
    };

    let is_input_already_spent = kernel_tx_index
        .get_spent_state(kernel_outpoint.output_index())
        .map_err(|_| PoSError::InIndexOutpointAccessError)?;

    ensure!(
        is_input_already_spent == OutputSpentState::Unspent,
        PoSError::OutputAlreadySpent,
    );

    let target: Uint256 = (*pos_data.bits())
        .try_into()
        .map_err(|_| PoSError::BitsToTargetConversionFailed(pos_data.bits().clone()))?;

    let prev_stake_modifier = get_stake_modifier(
        chain_config,
        header.prev_block_id().as_ref().expect("Prev block id must exist"),
        block_index_handle,
    )?
    .ok_or(PoSError::PrevStakeModiferNotFound)?;

    let _hash_pos = check_stake_kernel_hash(
        target,
        kernel_block_header.block_timestamp(),
        kernel_output,
        header.timestamp(),
        prev_stake_modifier,
    )?;
    Ok(())
}
