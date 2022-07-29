use chainstate_types::vrf_tools::verify_vrf_and_get_vrf_output;
use common::{
    chain::{
        block::{consensus_data::PoSData, BlockHeader},
        ChainConfig, OutputSpentState, TxOutput,
    },
    primitives::{Idable, H256},
    Uint256,
};

use utils::ensure;

use crate::detail::pos::kernel::{get_kernel_block_index, get_kernel_output};

use self::error::ConsensusPoSError;

use super::{
    consensus_validator::{BlockIndexHandle, TransactionIndexHandle},
    gen_block_index::GenBlockIndex,
};

pub mod error;
pub mod kernel;

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

    let hash_pos: H256 = verify_vrf_and_get_vrf_output(
        epoch_index,
        random_seed,
        pos_data.vrf_data(),
        pool_data.vrf_public_key(),
        spender_block_header,
    )
    .map_err(ConsensusPoSError::VRFDataVerificationFailed)?;

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
        .map_err(|_| ConsensusPoSError::KernelAncestryCheckFailed(header.get_id()))?;

    ensure!(
        kernel_block_header_as_ancestor.block_id() == kernel_block_index.block_id(),
        ConsensusPoSError::KernelAncestryCheckFailed(header.block_id()),
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
    let kernel_block_index =
        get_kernel_block_index(pos_data, block_index_handle, tx_index_retriever)?;

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

    let kernel_output = get_kernel_output(pos_data, block_index_handle, tx_index_retriever)?;

    ensure_correct_ancestry(
        header,
        &prev_block_index,
        &kernel_block_index,
        block_index_handle,
    )?;

    let kernel_outpoint =
        pos_data.kernel_inputs().get(0).ok_or(ConsensusPoSError::NoKernel)?.outpoint();
    let kernel_tx_index = tx_index_retriever
        .get_mainchain_tx_index(&kernel_outpoint.tx_id())
        .map_err(|_| ConsensusPoSError::OutpointTransactionRetrievalError)?
        .ok_or(ConsensusPoSError::OutpointTransactionNotFound)?;
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
