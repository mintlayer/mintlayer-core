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

use chainstate_types::{BlockIndex, EpochData};
use common::{
    chain::{
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{height::BlockHeightIntType, Amount, BlockHeight, Id, H256},
};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, PoSAccountingDeltaData, PoSAccountingUndo, PoolData,
};
use serialization::{Decode, Encode};
use storage::OrderPreservingValue;
use tokens_accounting::TokenAccountingUndo;
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
        /// Storage for block IDs indexed by block height.
        pub DBBlockByHeight: Map<BlockHeight, Id<GenBlock>>,
        /// The set of ids of blocks (both valid and invalid) that don't have children.
        /// If the set is empty, then genesis is the only leaf block.
        /// Note that the set may or may not contain the current main chain tip - the tip
        /// may have invalid children, in which case it won't be marked as a leaf.
        pub DBLeafBlockIds: Map<crate::schema::DBLeafBlockIdsMapKey, ()>,
        /// Store for Utxo Entries
        pub DBUtxo: Map<UtxoOutPoint, Utxo>,
        /// Store for utxo BlockUndo
        pub DBUtxosBlockUndo: Map<Id<Block>, UtxosBlockUndo>,
        /// Store for EpochData
        pub DBEpochData: Map<EpochIndex, EpochData>,
        /// Store for token's info; created on issuance
        pub DBTokensAuxData: Map<TokenId, TokenAuxiliaryData>,
        /// Store of issuance tx id vs token id
        pub DBIssuanceTxVsTokenId: Map<Id<Transaction>, TokenId>,
        /// Store the number of transactions per account
        pub DBAccountNonceCount: Map<AccountType, AccountNonce>,

        pub DBTokensData: Map<TokenId, tokens_accounting::TokenData>,
        pub DBTokensCirculatingSupply: Map<TokenId, Amount>,
        pub DBTokensAccountingBlockUndo: Map<Id<Block>, accounting::BlockUndo<TokenAccountingUndo>>,

        /// Store for accounting BlockUndo
        pub DBAccountingBlockUndo: Map<Id<Block>, accounting::BlockUndo<PoSAccountingUndo>>,
        /// Store for accounting deltas per epoch
        pub DBAccountingEpochDelta: Map<EpochIndex, PoSAccountingDeltaData>,
        /// Store for accounting undo deltas per epoch
        pub DBAccountingEpochDeltaUndo: Map<EpochIndex, DeltaMergeUndo>,

        /// Accounting data is stored as 2 different sets: tip, sealed
        /// `Tip` is the current state of the PoS accounting data. It is updated on every block.
        /// `Sealed` is the state of the PoS accounting data that is N epochs behind the tip.

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

/// The key type for the `DBLeafBlockIds` map.
///
/// Here `block_height` doesn't add any additional information to the data, because block height
/// is unambiguously determined by the block id. But by putting it before the id we get the ability
/// to search for ids with height bigger or equal to the specified one, using `greater_equal_iter`.
#[derive(Encode, Decode)]
pub struct DBLeafBlockIdsMapKey {
    block_height: OrderPreservingValue<BlockHeightIntType>,
    block_id: Id<Block>,
}

impl DBLeafBlockIdsMapKey {
    pub fn new(block_height: BlockHeight, block_id: Id<Block>) -> Self {
        Self {
            block_height: OrderPreservingValue::new(block_height.into_int()),
            block_id,
        }
    }

    pub fn with_zero_id(block_height: BlockHeight) -> Self {
        Self::new(block_height, Id::new(H256::zero()))
    }

    pub fn from_block_index(block_index: &BlockIndex) -> Self {
        Self::new(block_index.block_height(), *block_index.block_id())
    }

    pub fn block_height(&self) -> BlockHeight {
        BlockHeight::new(self.block_height.inner())
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use common::primitives::H256;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    use super::*;

    // DBLeafBlockIdsMapKey in the encoded form must have the same ordering as the tuple (BlockHeight, Id<Block>).
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_block_ids_map_key(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for _ in 0..100 {
            let val1 = DBLeafBlockIdsMapKey::new(
                BlockHeight::new(rng.gen::<BlockHeightIntType>()),
                Id::new(H256::random_using(&mut rng)),
            );

            let val2 = DBLeafBlockIdsMapKey::new(
                BlockHeight::new(rng.gen::<BlockHeightIntType>()),
                Id::new(H256::random_using(&mut rng)),
            );

            let val1_encoded = val1.encode();
            let val2_encoded = val2.encode();

            let cmp1 =
                (val1.block_height(), val1.block_id()).cmp(&(val2.block_height(), val2.block_id()));
            let cmp2 = val1_encoded.cmp(&val2_encoded);
            assert_eq!(cmp1, cmp2);

            // Also check that the key with the zeroed block id is always less than or equal to the original one.
            let val1_0 = DBLeafBlockIdsMapKey::with_zero_id(val1.block_height());
            let val1_0_encoded = val1_0.encode();
            assert!(
                (val1_0.block_height(), val1_0.block_id())
                    <= (val1.block_height(), val1.block_id())
            );
            assert!(val1_0_encoded <= val1_encoded);
        }
    }
}
