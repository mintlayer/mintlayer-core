// Copyright (c) 2022 RBB S.r.l
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

use super::{
    storage::{TransactionVerifierStorageError, TransactionVerifierStorageMut},
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp, ConsumedTokenIssuanceCache},
    CachedInputsOperation, TransactionVerifierDelta,
};
use common::chain::OutPointSourceId;

fn flush_tx_indexes(
    storage: &mut impl TransactionVerifierStorageMut,
    tx_id: OutPointSourceId,
    tx_index_op: CachedInputsOperation,
) -> Result<(), TransactionVerifierStorageError> {
    match tx_index_op {
        CachedInputsOperation::Write(ref tx_index) => {
            storage.set_mainchain_tx_index(&tx_id, tx_index)?
        }
        CachedInputsOperation::Read(_) => (),
        CachedInputsOperation::Erase => storage.del_mainchain_tx_index(&tx_id)?,
    }
    Ok(())
}

fn flush_tokens(
    storage: &mut impl TransactionVerifierStorageMut,
    token_cache: &ConsumedTokenIssuanceCache,
) -> Result<(), TransactionVerifierStorageError> {
    debug_assert_eq!(token_cache.data.len(), token_cache.txid_vs_tokenid.len());

    token_cache.data.iter().try_for_each(
        |(token_id, aux_data_op)| -> Result<(), TransactionVerifierStorageError> {
            match aux_data_op {
                CachedAuxDataOp::Write(aux_data) => {
                    storage.set_token_aux_data(token_id, aux_data)?;
                }
                CachedAuxDataOp::Read(_) => (),
                CachedAuxDataOp::Erase => {
                    storage.del_token_aux_data(token_id)?;
                }
            };
            Ok(())
        },
    )?;

    token_cache.txid_vs_tokenid.iter().try_for_each(
        |(tx_id, token_index_op)| -> Result<(), TransactionVerifierStorageError> {
            match token_index_op {
                CachedTokenIndexOp::Write(token_id) => {
                    storage.set_token_id(tx_id, token_id)?;
                }
                CachedTokenIndexOp::Read(_) => (),
                CachedTokenIndexOp::Erase => {
                    storage.del_token_id(tx_id)?;
                }
            };
            Ok(())
        },
    )?;
    Ok(())
}

pub fn flush_to_storage(
    storage: &mut impl TransactionVerifierStorageMut,
    consumed: TransactionVerifierDelta,
) -> Result<(), TransactionVerifierStorageError> {
    for (tx_id, tx_index_op) in consumed.tx_index_cache {
        flush_tx_indexes(storage, tx_id, tx_index_op)?;
    }

    flush_tokens(storage, &consumed.token_issuance_cache)?;

    // flush utxo set
    storage.batch_write(consumed.utxo_cache)?;

    // flush block undo
    for (tx_source, entry) in consumed.utxo_block_undo {
        if entry.is_fresh {
            storage.set_undo_data(tx_source, &entry.undo)?;
        } else if entry.undo.is_empty() {
            storage.del_undo_data(tx_source)?;
        } else {
            unreachable!("BlockUndo was not used up completely")
        }
    }

    Ok(())
}
