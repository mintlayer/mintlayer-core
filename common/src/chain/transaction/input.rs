// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::chain::{
    transaction::signature::inputsig::InputWitness, transaction::Transaction, Block, GenBlock,
    Genesis,
};
use crate::primitives::{Id, H256};
use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
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

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OutPoint {
    id: OutPointSourceId,
    index: u32,
}

impl OutPointSourceId {
    fn outpoint_source_id_as_monolithic_tuple(&self) -> (u8, H256) {
        const TX_OUT_INDEX: u8 = 0;
        const BLK_REWARD_INDEX: u8 = 1;
        match self {
            OutPointSourceId::Transaction(h) => (TX_OUT_INDEX, h.get()),
            OutPointSourceId::BlockReward(h) => (BLK_REWARD_INDEX, h.get()),
        }
    }
}

impl PartialOrd for OutPointSourceId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OutPointSourceId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let id = self.outpoint_source_id_as_monolithic_tuple();
        let other_id = other.outpoint_source_id_as_monolithic_tuple();
        id.cmp(&other_id)
    }
}

impl PartialOrd for OutPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OutPoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let id = self.id.outpoint_source_id_as_monolithic_tuple();
        let other_id = other.id.outpoint_source_id_as_monolithic_tuple();

        (id, self.index).cmp(&(other_id, other.index))
    }
}

impl OutPoint {
    pub fn new(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        OutPoint {
            id: outpoint_source_id,
            index: output_index,
        }
    }

    pub fn tx_id(&self) -> OutPointSourceId {
        self.id.clone()
    }

    pub fn output_index(&self) -> u32 {
        self.index
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct TxInput {
    outpoint: OutPoint,
    witness: InputWitness,
}

impl TxInput {
    pub fn new(
        outpoint_source_id: OutPointSourceId,
        output_index: u32,
        witness: InputWitness,
    ) -> Self {
        TxInput {
            outpoint: OutPoint::new(outpoint_source_id, output_index),
            witness,
        }
    }

    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    pub fn witness(&self) -> &InputWitness {
        &self.witness
    }

    pub fn update_witness(&mut self, witness: InputWitness) {
        self.witness = witness
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // The hash value doesn't matter because we first compare the enum arm
    fn compare_test(block_reward_hash: &H256, tx_hash: &H256) {
        let br = OutPointSourceId::BlockReward(Id::new(*block_reward_hash));
        let bro0 = OutPoint::new(br.clone(), 0);
        let bro1 = OutPoint::new(br.clone(), 1);
        let bro2 = OutPoint::new(br, 2);

        let tx = OutPointSourceId::Transaction(Id::new(*tx_hash));
        let txo0 = OutPoint::new(tx.clone(), 0);
        let txo1 = OutPoint::new(tx.clone(), 1);
        let txo2 = OutPoint::new(tx, 2);

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

    #[test]
    fn ord_and_equality_random() {
        let hash_br = H256::random();
        let hash_tx = H256::random();

        compare_test(&hash_br, &hash_tx);
    }
}
