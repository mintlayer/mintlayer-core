use common::chain::{block::consensus_data::PoSData, signature::Transactable, TxOutput};
use utils::ensure;

use crate::detail::{
    consensus_validator::{BlockIndexHandle, TransactionIndexHandle},
    gen_block_index::GenBlockIndex,
};

use super::error::ConsensusPoSError;

pub fn get_kernel_block_index(
    pos_data: &PoSData,
    block_index_handle: &dyn BlockIndexHandle,
    tx_index_retriever: &dyn TransactionIndexHandle,
) -> Result<GenBlockIndex, ConsensusPoSError> {
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

    Ok(kernel_block_index)
}

pub fn get_kernel_output(
    pos_data: &PoSData,
    block_index_handle: &dyn BlockIndexHandle,
    tx_index_retriever: &dyn TransactionIndexHandle,
) -> Result<TxOutput, ConsensusPoSError> {
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

    Ok(kernel_output)
}
