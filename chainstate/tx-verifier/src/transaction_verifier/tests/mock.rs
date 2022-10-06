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

use super::storage::{
    TransactionVerifierStorageError, TransactionVerifierStorageMut, TransactionVerifierStorageRef,
};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPoint, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::Id,
};
use utxo::{BlockUndo, ConsumedUtxoCache, FlushableUtxoView, Utxo, UtxosStorageRead};

mockall::mock! {
    pub Store {}

    impl TransactionVerifierStorageRef for Store {
        fn get_token_id_from_issuance_tx(
            &self,
            tx_id: Id<Transaction>,
        ) -> Result<Option<TokenId>, TransactionVerifierStorageError>;

        fn get_gen_block_index(
            &self,
            block_id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, storage_result::Error>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError>;

        fn get_token_aux_data(
            &self,
            token_id: &TokenId,
        ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError>;
    }

    impl TransactionVerifierStorageMut for Store {
        fn set_mainchain_tx_index(
            &mut self,
            tx_id: &OutPointSourceId,
            tx_index: &TxMainChainIndex,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_mainchain_tx_index(
            &mut self,
            tx_id: &OutPointSourceId,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_token_aux_data(
            &mut self,
            token_id: &TokenId,
            data: &TokenAuxiliaryData,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_token_aux_data(
            &mut self,
            token_id: &TokenId,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_token_id(
            &mut self,
            issuance_tx_id: &Id<Transaction>,
            token_id: &TokenId,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_token_id(
            &mut self,
            issuance_tx_id: &Id<Transaction>,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), TransactionVerifierStorageError>;
        fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), TransactionVerifierStorageError>;
    }

    impl UtxosStorageRead for Store {
        fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, storage_result::Error>;
        fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>,storage_result::Error>;
        fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, storage_result::Error>;
    }

    impl FlushableUtxoView for Store {
        fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error>;
    }
}
