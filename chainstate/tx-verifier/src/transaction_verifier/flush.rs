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

use crate::TransactionSource;

use super::{
    storage::{TransactionVerifierStorageMut, TransactionVerifierStorageRef},
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp, ConsumedTokenIssuanceCache},
    CachedInputsOperation, CachedOperation, TransactionVerifierDelta,
};
use common::chain::OutPointSourceId;
use tokens_accounting::FlushableTokensAccountingView;
use utxo::FlushableUtxoView;

fn flush_tx_indexes<S: TransactionVerifierStorageMut>(
    storage: &mut S,
    tx_id: OutPointSourceId,
    tx_index_op: CachedInputsOperation,
) -> Result<(), <S as TransactionVerifierStorageRef>::Error> {
    match tx_index_op {
        CachedInputsOperation::Write(ref tx_index) => {
            storage.set_mainchain_tx_index(&tx_id, tx_index)?
        }
        CachedInputsOperation::Read(_) => (),
        CachedInputsOperation::Erase => storage.del_mainchain_tx_index(&tx_id)?,
    }
    Ok(())
}

fn flush_tokens<S: TransactionVerifierStorageMut>(
    storage: &mut S,
    token_cache: &ConsumedTokenIssuanceCache,
) -> Result<(), <S as TransactionVerifierStorageRef>::Error> {
    debug_assert_eq!(token_cache.data.len(), token_cache.txid_vs_tokenid.len());

    token_cache.data.iter().try_for_each(
        |(token_id, aux_data_op)| -> Result<(), <S as TransactionVerifierStorageRef>::Error> {
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
        |(tx_id, token_index_op)| -> Result<(), <S as TransactionVerifierStorageRef>::Error> {
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

pub fn flush_to_storage<S: TransactionVerifierStorageMut>(
    storage: &mut S,
    consumed: TransactionVerifierDelta,
) -> Result<(), <S as TransactionVerifierStorageRef>::Error>
where
    <S as TransactionVerifierStorageRef>::Error: From<<S as FlushableUtxoView>::Error>,
    <S as TransactionVerifierStorageRef>::Error: From<<S as FlushableTokensAccountingView>::Error>,
    <S as TransactionVerifierStorageRef>::Error: From<pos_accounting::Error>,
{
    for (tx_id, tx_index_op) in consumed.tx_index_cache {
        flush_tx_indexes(storage, tx_id, tx_index_op)?;
    }

    flush_tokens(storage, &consumed.token_issuance_cache)?;

    // flush utxo set
    storage.batch_write(consumed.utxo_cache)?;

    // flush utxo block undo
    for (tx_source, entry) in consumed.utxo_block_undo {
        if entry.is_fresh {
            storage.set_utxo_undo_data(tx_source, &entry.undo)?;
        } else if entry.undo.is_empty() {
            storage.del_utxo_undo_data(tx_source)?;
        } else {
            match tx_source {
                TransactionSource::Chain(block_id) => {
                    panic!("BlockUndo utxo entries were not used up completely while disconnecting a block {}", block_id)
                }
                TransactionSource::Mempool => {
                    /* it's ok for the mempool to use tx undos partially */
                }
            }
        }
    }

    // flush pos accounting
    storage.batch_write_delta(consumed.accounting_delta)?;

    storage.batch_write_tokens_data(consumed.tokens_accounting_delta)?;

    for (tx_source, delta) in consumed.accounting_block_deltas {
        storage.apply_accounting_delta(tx_source, &delta)?;
    }

    // flush accounting block undo
    for (tx_source, entry) in consumed.accounting_delta_undo {
        if entry.is_fresh {
            storage.set_accounting_undo_data(tx_source, &entry.undo)?;
        } else if entry.undo.is_empty() {
            storage.del_accounting_undo_data(tx_source)?;
        } else {
            match tx_source {
                TransactionSource::Chain(block_id) => {
                    panic!("BlockUndo accounting entries were not used up completely while disconnecting a block {}", block_id)
                }
                TransactionSource::Mempool => {
                    /* it's ok for the mempool to use tx undos partially */
                }
            }
        }
    }

    // flush nonce values
    for (account, op) in consumed.account_nonce {
        match op {
            CachedOperation::Write(nonce) => storage.set_account_nonce_count(account, nonce)?,
            CachedOperation::Read(_) => (),
            CachedOperation::Erase => storage.del_account_nonce_count(account)?,
        };
    }

    Ok(())
}
