// Copyright (c) 2023 RBB S.r.l
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

use crate::chain::{transaction::Transaction, Block, GenBlock, Genesis};
use crate::primitives::Id;
use serialization::{Decode, Encode};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Ord,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumDiscriminants,
)]
#[strum_discriminants(name(OutPointSourceIdTag), derive(strum::EnumIter))]
pub enum OutPointSourceId {
    #[codec(index = 0)]
    Transaction(Id<Transaction>),
    #[codec(index = 1)]
    BlockReward(Id<GenBlock>),
}

impl From<Id<Transaction>> for OutPointSourceId {
    fn from(id: Id<Transaction>) -> OutPointSourceId {
        OutPointSourceId::Transaction(id)
    }
}

impl From<Id<GenBlock>> for OutPointSourceId {
    fn from(id: Id<GenBlock>) -> OutPointSourceId {
        OutPointSourceId::BlockReward(id)
    }
}

impl From<Id<Block>> for OutPointSourceId {
    fn from(id: Id<Block>) -> OutPointSourceId {
        OutPointSourceId::BlockReward(id.into())
    }
}

impl From<Id<Genesis>> for OutPointSourceId {
    fn from(id: Id<Genesis>) -> OutPointSourceId {
        OutPointSourceId::BlockReward(id.into())
    }
}

impl OutPointSourceId {
    pub fn get_tx_id(&self) -> Option<&Id<Transaction>> {
        match self {
            OutPointSourceId::Transaction(id) => Some(id),
            _ => None,
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Ord,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct UtxoOutPoint {
    id: OutPointSourceId,
    index: u32,
}

impl UtxoOutPoint {
    pub fn new(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        UtxoOutPoint {
            id: outpoint_source_id,
            index: output_index,
        }
    }

    pub fn source_id(&self) -> OutPointSourceId {
        self.id.clone()
    }

    pub fn output_index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod test {
    use crate::primitives::H256;

    use rstest::rstest;
    use test_utils::random::Seed;

    use super::*;

    // The hash value doesn't matter because we first compare the enum arm
    fn compare_test(block_reward_hash: &H256, tx_hash: &H256) {
        let br = OutPointSourceId::BlockReward(Id::new(*block_reward_hash));
        let bro0 = UtxoOutPoint::new(br.clone(), 0);
        let bro1 = UtxoOutPoint::new(br.clone(), 1);
        let bro2 = UtxoOutPoint::new(br, 2);

        let tx = OutPointSourceId::Transaction(Id::new(*tx_hash));
        let txo0 = UtxoOutPoint::new(tx.clone(), 0);
        let txo1 = UtxoOutPoint::new(tx.clone(), 1);
        let txo2 = UtxoOutPoint::new(tx, 2);

        assert_eq!(bro0.cmp(&bro1), std::cmp::Ordering::Less);
        assert_eq!(bro0.cmp(&bro2), std::cmp::Ordering::Less);
        assert_eq!(bro1.cmp(&bro2), std::cmp::Ordering::Less);
        assert_eq!(bro0.cmp(&bro0), std::cmp::Ordering::Equal);
        assert_eq!(bro1.cmp(&bro1), std::cmp::Ordering::Equal);
        assert_eq!(bro2.cmp(&bro2), std::cmp::Ordering::Equal);
        assert_eq!(bro1.cmp(&bro0), std::cmp::Ordering::Greater);
        assert_eq!(bro2.cmp(&bro1), std::cmp::Ordering::Greater);
        assert_eq!(bro2.cmp(&bro0), std::cmp::Ordering::Greater);

        assert_eq!(txo0.cmp(&txo1), std::cmp::Ordering::Less);
        assert_eq!(txo0.cmp(&txo2), std::cmp::Ordering::Less);
        assert_eq!(txo1.cmp(&txo2), std::cmp::Ordering::Less);
        assert_eq!(txo0.cmp(&txo0), std::cmp::Ordering::Equal);
        assert_eq!(txo1.cmp(&txo1), std::cmp::Ordering::Equal);
        assert_eq!(txo2.cmp(&txo2), std::cmp::Ordering::Equal);
        assert_eq!(txo1.cmp(&txo0), std::cmp::Ordering::Greater);
        assert_eq!(txo2.cmp(&txo1), std::cmp::Ordering::Greater);
        assert_eq!(txo2.cmp(&txo0), std::cmp::Ordering::Greater);

        assert_eq!(bro0.cmp(&txo0), std::cmp::Ordering::Greater);
        assert_eq!(bro0.cmp(&txo1), std::cmp::Ordering::Greater);
        assert_eq!(bro0.cmp(&txo2), std::cmp::Ordering::Greater);

        assert_eq!(txo0.cmp(&bro0), std::cmp::Ordering::Less);
        assert_eq!(txo1.cmp(&bro0), std::cmp::Ordering::Less);
        assert_eq!(txo2.cmp(&bro0), std::cmp::Ordering::Less);

        assert_eq!(txo0.cmp(&bro1), std::cmp::Ordering::Less);
        assert_eq!(txo1.cmp(&bro1), std::cmp::Ordering::Less);
        assert_eq!(txo2.cmp(&bro1), std::cmp::Ordering::Less);

        assert_eq!(txo0.cmp(&bro2), std::cmp::Ordering::Less);
        assert_eq!(txo1.cmp(&bro2), std::cmp::Ordering::Less);
        assert_eq!(txo2.cmp(&bro2), std::cmp::Ordering::Less);

        assert_eq!(bro1.cmp(&txo1), std::cmp::Ordering::Greater);
        assert_eq!(txo1.cmp(&bro1), std::cmp::Ordering::Less);

        assert_eq!(bro2.cmp(&txo2), std::cmp::Ordering::Greater);
        assert_eq!(txo2.cmp(&bro2), std::cmp::Ordering::Less);
    }

    #[test]
    fn ord_and_equality_less() {
        let hash_br = H256::from_low_u64_le(10);
        let hash_tx = H256::from_low_u64_le(20);

        compare_test(&hash_br, &hash_tx);
    }

    #[test]
    fn ord_and_equality_greater() {
        let hash_br = H256::from_low_u64_le(20);
        let hash_tx = H256::from_low_u64_le(10);

        compare_test(&hash_br, &hash_tx);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn ord_and_equality_random(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let hash_br = H256::random_using(&mut rng);
        let hash_tx = H256::random_using(&mut rng);

        compare_test(&hash_br, &hash_tx);
    }
}
