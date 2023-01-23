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
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DelegationId, DeltaMergeUndo, PoSAccountingDeltaData,
    PoolData, PoolId,
};
use utxo::{Utxo, UtxosBlockUndo};

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
        // TODO: no need to store info for sealed blocks
        /// Store for utxo BlockUndo
        pub DBUtxosBlockUndo: Map<Id<Block>, UtxosBlockUndo>,
        /// Store for token's info; created on issuance
        pub DBTokensAuxData: Map<TokenId, TokenAuxiliaryData>,
        /// Store of issuance tx id vs token id
        pub DBIssuanceTxVsTokenId: Map<Id<Transaction>, TokenId>,

        // TODO: no need to store info for sealed blocks
        /// Store for accounting BlockUndo
        pub DBAccountingBlockUndo: Map<Id<Block>, AccountingBlockUndo>,

        // FIXME write better description for tip/seal/pre-seal

        /// Store for accumulated accounting deltas per epochs that are about
        /// to go to the sealed storage
        pub DBAccountingPreSealData: Map<u64, PoSAccountingDeltaData>,
        /// Store of undos for pre-seal delta. They are stored per epoch and block
        /// so that it is easy to disconnect and undo a block but also to discard
        /// undos when an epoch is sealed.
        pub DBAccountingPreSealDataUndo: Map<(u64, Id<Block>), DeltaMergeUndo>,

        /// Store for accounting pool data
        pub DBAccountingPoolDataTip: Map<PoolId, PoolData>,
        /// Store for accounting pool balances
        pub DBAccountingPoolBalancesTip: Map<PoolId, Amount>,
        /// Store for accounting delegation data
        pub DBAccountingDelegationDataTip: Map<DelegationId, DelegationData>,
        /// Store for accounting delegation data
        pub DBAccountingDelegationBalancesTip: Map<DelegationId, Amount>,
        /// Store for accounting pool delegations balances
        pub DBAccountingPoolDelegationSharesTip: Map<(PoolId, DelegationId), Amount>,

        /// Store for accounting pool data
        pub DBAccountingPoolDataSealed: Map<PoolId, PoolData>,
        /// Store for accounting pool balances
        pub DBAccountingPoolBalancesSealed: Map<PoolId, Amount>,
        /// Store for accounting delegation data
        pub DBAccountingDelegationDataSealed: Map<DelegationId, DelegationData>,
        /// Store for accounting delegation data
        pub DBAccountingDelegationBalancesSealed: Map<DelegationId, Amount>,
        /// Store for accounting pool delegations balances
        pub DBAccountingPoolDelegationSharesSealed: Map<(PoolId, DelegationId), Amount>,
    }
}
