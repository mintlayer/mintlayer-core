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
    error::ConnectTransactionError, storage::TransactionVerifierStorageMut,
    token_issuance_cache::CachedTokensOperation, CachedInputsOperation, TransactionVerifierDelta,
};
use common::{
    chain::{tokens::TokenId, OutPointSourceId},
    primitives::Idable,
};
use utxo::{FlushableUtxoView, UtxosDBMut};

fn flush_tx_indexes(
    storage: &mut impl TransactionVerifierStorageMut,
    tx_id: OutPointSourceId,
    tx_index_op: CachedInputsOperation,
) -> Result<(), ConnectTransactionError> {
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
    token_id: TokenId,
    token_op: CachedTokensOperation,
) -> Result<(), ConnectTransactionError> {
    match token_op {
        CachedTokensOperation::Write(ref issuance_tx) => {
            storage.set_token_aux_data(&token_id, issuance_tx)?;
            storage.set_token_id(&issuance_tx.issuance_tx().get_id(), &token_id)?;
        }
        CachedTokensOperation::Read(_) => (),
        CachedTokensOperation::Erase(issuance_tx) => {
            storage.del_token_aux_data(&token_id)?;
            storage.del_token_id(&issuance_tx)?;
        }
    }
    Ok(())
}

pub fn flush_to_storage(
    storage: &mut impl TransactionVerifierStorageMut,
    consumed: TransactionVerifierDelta,
) -> Result<(), ConnectTransactionError> {
    for (tx_id, tx_index_op) in consumed.tx_index_cache {
        flush_tx_indexes(storage, tx_id, tx_index_op)?;
    }
    for (token_id, token_op) in consumed.token_issuance_cache {
        flush_tokens(storage, token_id, token_op)?;
    }

    // flush utxo set
    let mut utxo_db = UtxosDBMut::new(storage);
    utxo_db.batch_write(consumed.utxo_cache)?;

    //flush block undo
    for (block_id, entry) in consumed.utxo_block_undo {
        if entry.is_fresh {
            storage.set_undo_data(block_id, &entry.undo)?;
        } else {
            storage.del_undo_data(block_id)?;
        }
    }

    Ok(())
}
