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

//! Chainstate database schema

use chainstate_types::BlockIndex;
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPoint, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::{DelegationData, DelegationId, PoolData, PoolId};
use utxo::Utxo;

storage::decl_schema! {
    /// Database schema for blockchain storage
    pub Schema {
        /// Storage for individual values.
        pub DBValue: Map<Vec<u8>, Vec<u8>>,
        /// Storage for blocks.
        pub DBBlock: Map<Id<Block>, Block>,
        /// Store tag for blocks indexes.
        pub DBBlockIndex: Map<Id<Block>, BlockIndex>,
        /// Storage for transaction indices.
        pub DBTxIndex: Map<OutPointSourceId, TxMainChainIndex>,
        /// Storage for block IDs indexed by block height.
        pub DBBlockByHeight: Map<BlockHeight, Id<GenBlock>>,
        /// Store for Utxo Entries
        pub DBUtxo: Map<OutPoint, Utxo>,
        /// Store for utxo BlockUndo
        pub DBBlockUndo: Map<Id<Block>, utxo::BlockUndo>,
        /// Store for token's info; created on issuance
        pub DBTokensAuxData: Map<TokenId, TokenAuxiliaryData>,
        /// Store of issuance tx id vs token id
        pub DBIssuanceTxVsTokenId: Map<Id<Transaction>, TokenId>,

        /// Store for accounts BlockUndo
        pub DBAccountsBlockUndo: Map<Id<Block>, pos_accounting::BlockUndo>,

        pub DBAccountsPoolData: Map<PoolId, PoolData>,
        pub DBAccountsPoolBalances: Map<PoolId, Amount>,
        pub DBAccountsDelegationData: Map<DelegationId, DelegationData>,
        pub DBAccountsDelegationBalances: Map<DelegationId, Amount>,
        pub DBAccountsPoolDelegationShares: Map<(PoolId, DelegationId), Amount>,
    }
}
