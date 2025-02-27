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
    storage::{TransactionVerifierStorageMut, TransactionVerifierStorageRef},
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp, ConsumedTokenIssuanceCache},
    CachedOperation, TransactionVerifierDelta,
};
use orders_accounting::FlushableOrdersAccountingView;
use pos_accounting::FlushablePoSAccountingView;
use tokens_accounting::FlushableTokensAccountingView;
use utxo::FlushableUtxoView;

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
    <S as TransactionVerifierStorageRef>::Error: From<<S as FlushableOrdersAccountingView>::Error>,
    <S as TransactionVerifierStorageRef>::Error: From<<S as FlushablePoSAccountingView>::Error>,
{
    flush_tokens(storage, &consumed.token_issuance_cache)?;

    // flush utxo set
    storage.batch_write(consumed.utxo_cache)?;

    // flush utxo block undo
    for (tx_source, op) in consumed.utxo_block_undo {
        match op {
            CachedOperation::Write(undo) => storage.set_utxo_undo_data(tx_source, &undo)?,
            CachedOperation::Read(_) => (),
            CachedOperation::Erase => storage.del_utxo_undo_data(tx_source)?,
        }
    }

    // flush pos accounting
    storage.batch_write_delta(consumed.accounting_delta)?;

    // Note: the deltas here are sorted by block id, which is a wrong order to use when applying them.
    // This currently works because the map can only contain at most one element at a time.
    // See the comment for `PoSAccountingDeltaAdapter::accounting_block_deltas`.
    debug_assert!(consumed.pos_accounting_block_deltas.len() <= 1);
    for (tx_source, delta) in consumed.pos_accounting_block_deltas {
        storage.apply_accounting_delta(tx_source, &delta)?;
    }

    // flush pos accounting block undo
    for (tx_source, op) in consumed.pos_accounting_delta_undo {
        match op {
            CachedOperation::Write(undo) => {
                storage.set_pos_accounting_undo_data(tx_source, &undo)?
            }
            CachedOperation::Read(_) => (),
            CachedOperation::Erase => storage.del_pos_accounting_undo_data(tx_source)?,
        }
    }

    storage.batch_write_tokens_data(consumed.tokens_accounting_delta)?;

    // flush tokens accounting block undo
    for (tx_source, op) in consumed.tokens_accounting_delta_undo {
        match op {
            CachedOperation::Write(undo) => {
                storage.set_tokens_accounting_undo_data(tx_source, &undo)?
            }
            CachedOperation::Read(_) => (),
            CachedOperation::Erase => storage.del_tokens_accounting_undo_data(tx_source)?,
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

    storage.batch_write_orders_data(consumed.orders_accounting_delta)?;

    // flush orders accounting block undo
    for (tx_source, op) in consumed.orders_accounting_delta_undo {
        match op {
            CachedOperation::Write(undo) => {
                storage.set_orders_accounting_undo_data(tx_source, &undo)?
            }
            CachedOperation::Read(_) => (),
            CachedOperation::Erase => storage.del_orders_accounting_undo_data(tx_source)?,
        }
    }

    Ok(())
}
