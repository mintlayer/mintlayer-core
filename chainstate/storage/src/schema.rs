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
        config::EpochIndex,
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
        /// Store for utxo BlockUndo
        pub DBUtxosBlockUndo: Map<Id<Block>, UtxosBlockUndo>,
        /// Store for token's info; created on issuance
        pub DBTokensAuxData: Map<TokenId, TokenAuxiliaryData>,
        /// Store of issuance tx id vs token id
        pub DBIssuanceTxVsTokenId: Map<Id<Transaction>, TokenId>,

        /// Store for accounting BlockUndo
        pub DBAccountingBlockUndo: Map<Id<Block>, AccountingBlockUndo>,
        /// Store for accounting deltas per block
        pub DBAccountingBlockDelta: Map<Id<Block>, PoSAccountingDeltaData>,
        /// Store for accounting undo deltas per epoch
        pub DBAccountingEpochDeltaUndo: Map<EpochIndex, DeltaMergeUndo>,

        /// Accounting data is stored as 2 different sets: tip, sealed
        /// `Tip` is the current state of the accounting data. It is updated on every block.
        /// `Pre-seal` is the intermediary state of the accounting data that is about to be sealed.

        /// Store for tip accounting pool data
        pub DBAccountingPoolDataTip: Map<PoolId, PoolData>,
        /// Store for tip accounting pool balances
        pub DBAccountingPoolBalancesTip: Map<PoolId, Amount>,
        /// Store for tip accounting delegation data
        pub DBAccountingDelegationDataTip: Map<DelegationId, DelegationData>,
        /// Store for tip accounting delegation data
        pub DBAccountingDelegationBalancesTip: Map<DelegationId, Amount>,
        /// Store for tip accounting pool delegations balances
        pub DBAccountingPoolDelegationSharesTip: Map<(PoolId, DelegationId), Amount>,

        /// Store for sealed accounting pool data
        pub DBAccountingPoolDataSealed: Map<PoolId, PoolData>,
        /// Store for sealed accounting pool balances
        pub DBAccountingPoolBalancesSealed: Map<PoolId, Amount>,
        /// Store for sealed accounting delegation data
        pub DBAccountingDelegationDataSealed: Map<DelegationId, DelegationData>,
        /// Store for sealed accounting delegation data
        pub DBAccountingDelegationBalancesSealed: Map<DelegationId, Amount>,
        /// Store for sealed accounting pool delegations balances
        pub DBAccountingPoolDelegationSharesSealed: Map<(PoolId, DelegationId), Amount>,
    }
}
