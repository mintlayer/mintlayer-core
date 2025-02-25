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

mod block_merkle;
mod merkle_tools;

pub mod merkle_proxy;

use merkletree_mintlayer::{MerkleTreeFormError, MerkleTreeProofExtractionError};
use serialization::{Decode, Encode};

use crate::chain::SignedTransaction;

use self::merkle_proxy::BlockBodyMerkleProxy;

use super::BlockReward;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockMerkleTreeError {
    #[error("Error while creating merkle tree: {0}")]
    MerkleTreeConstruction(#[from] MerkleTreeFormError),
    #[error("Error while extracting merkle tree proof: {0}")]
    MerkleTreeProofExtraction(#[from] MerkleTreeProofExtractionError),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockBody {
    pub(super) reward: BlockReward,
    pub(super) transactions: Vec<SignedTransaction>,
}

impl BlockBody {
    pub fn new(reward: BlockReward, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            reward,
            transactions,
        }
    }

    pub fn transactions(&self) -> &[SignedTransaction] {
        &self.transactions
    }

    pub fn reward(&self) -> &BlockReward {
        &self.reward
    }

    pub fn merkle_tree_proxy(&self) -> Result<BlockBodyMerkleProxy, BlockMerkleTreeError> {
        BlockBodyMerkleProxy::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::primitives::id::Idable;
    use crate::{
        chain::{
            block::BlockReward,
            output_value::OutputValue,
            signature::{
                inputsig::{standard_signature::StandardInputSignature, InputWitness},
                sighash::sighashtype::SigHashType,
            },
            Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::key::{KeyKind, PrivateKey};
    use proptest::prelude::Rng;
    use randomness::CryptoRng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn generate_random_h256(rng: &mut impl Rng) -> H256 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        H256::from(bytes)
    }

    fn generate_random_bytes(rng: &mut impl Rng, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn generate_random_invalid_witness(count: usize, rng: &mut impl Rng) -> Vec<InputWitness> {
        (0..count)
            .map(|_| {
                let witness_size = rng.next_u32();
                let witness_size = 1 + witness_size % 1000;
                let witness = generate_random_bytes(rng, witness_size as usize);
                InputWitness::Standard(StandardInputSignature::new(SigHashType::all(), witness))
            })
            .collect::<Vec<_>>()
    }

    fn generate_random_invalid_input(rng: &mut impl Rng) -> TxInput {
        let outpoint = if rng.next_u32() % 2 == 0 {
            OutPointSourceId::Transaction(Id::new(generate_random_h256(rng)))
        } else {
            OutPointSourceId::BlockReward(Id::new(generate_random_h256(rng)))
        };

        TxInput::from_utxo(outpoint, rng.next_u32())
    }

    fn generate_random_invalid_output(rng: &mut (impl Rng + CryptoRng)) -> TxOutput {
        let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.next_u64() as u128)),
            Destination::PublicKey(pub_key),
        )
    }

    fn generate_random_invalid_transaction(rng: &mut (impl Rng + CryptoRng)) -> SignedTransaction {
        let inputs = {
            let input_count = 1 + (rng.next_u32() as usize) % 10;
            (0..input_count).map(|_| generate_random_invalid_input(rng)).collect::<Vec<_>>()
        };

        let outputs = {
            let output_count = 1 + (rng.next_u32() as usize) % 10;
            (0..output_count)
                .map(|_| generate_random_invalid_output(rng))
                .collect::<Vec<_>>()
        };

        let flags = rng.gen::<u128>();

        let tx = Transaction::new(flags, inputs.clone(), outputs).expect("Creating tx caused fail");

        SignedTransaction::new(tx, generate_random_invalid_witness(inputs.len(), rng)).unwrap()
    }

    fn generate_random_invalid_block_reward(rng: &mut (impl Rng + CryptoRng)) -> BlockReward {
        let output_count = (rng.next_u32() as usize) % 10;
        let outputs = (0..output_count)
            .map(|_| generate_random_invalid_output(rng))
            .collect::<Vec<_>>();
        BlockReward::new(outputs)
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let reward = generate_random_invalid_block_reward(&mut rng);
        let transactions = (0..=10)
            .map(|_| generate_random_invalid_transaction(&mut rng))
            .collect::<Vec<_>>();

        let block_body = BlockBody::new(reward.clone(), transactions.clone());

        let block_reward_witness_hash = reward.serialized_hash();

        let transaction_witness_hashes =
            transactions.iter().map(|tx| tx.serialized_hash()).collect::<Vec<_>>();

        let transaction_ids = transactions
            .iter()
            .map(|tx| tx.transaction().get_id().to_hash())
            .collect::<Vec<_>>();

        let expected_merkle_leaves = std::iter::once(block_reward_witness_hash)
            .chain(transaction_ids)
            .collect::<Vec<_>>();
        let expected_witness_merkle_leaves = std::iter::once(block_reward_witness_hash)
            .chain(transaction_witness_hashes)
            .collect::<Vec<_>>();

        let merkle_proxy = block_body.merkle_tree_proxy().unwrap();

        let merkle_tree = merkle_proxy.merkle_tree();
        let witness_merkle_tree = merkle_proxy.witness_merkle_tree();

        // Check leaf count
        let leaf_count = (transactions.len() + 1).next_power_of_two();
        assert_eq!(merkle_tree.raw_tree().leaf_count().get(), leaf_count as u32);
        assert_eq!(
            witness_merkle_tree.raw_tree().leaf_count().get(),
            leaf_count as u32
        );

        // Check leaves hashes
        let merkle_tree_leaves =
            (0..transactions.len() + 1) // +1 for block reward
                .map(|i| merkle_tree.raw_tree().node_from_bottom(0, i as u32).unwrap())
                .collect::<Vec<_>>();
        assert_eq!(
            merkle_tree_leaves.iter().map(|v| *v.hash()).collect::<Vec<_>>(),
            expected_merkle_leaves[..transactions.len() + 1]
        );

        // Check witness leaves hashes
        let witness_merkle_tree_leaves =
            (0..transactions.len() + 1) // +1 for block reward
                .map(|i| witness_merkle_tree.raw_tree().node_from_bottom(0, i as u32).unwrap())
                .collect::<Vec<_>>();
        assert_eq!(
            witness_merkle_tree_leaves.iter().map(|v| *v.hash()).collect::<Vec<_>>(),
            expected_witness_merkle_leaves
        );

        // Verify inclusion proofs for block reward (both witness and non-witness are the same for block reward)
        let block_reward_inclusion_proof = merkle_tree.block_reward_inclusion_proof().unwrap();
        let block_reward_witness_inclusion_proof =
            witness_merkle_tree.block_reward_inclusion_proof().unwrap();

        if transactions.is_empty() {
            // If there are no transactions, the block reward is the root
            assert!(block_reward_inclusion_proof
                .verify(block_reward_witness_hash, merkle_tree.root())
                .passed_trivially());
            assert!(block_reward_witness_inclusion_proof
                .verify(block_reward_witness_hash, witness_merkle_tree.root())
                .passed_trivially());
            assert_eq!(merkle_tree.root(), witness_merkle_tree.root());
        } else {
            assert!(block_reward_inclusion_proof
                .verify(block_reward_witness_hash, merkle_tree.root())
                .passed_decisively());
            assert!(block_reward_witness_inclusion_proof
                .verify(block_reward_witness_hash, witness_merkle_tree.root())
                .passed_decisively());
        }

        // Verify inclusion proofs for transactions
        for (i, tx) in transactions.iter().enumerate() {
            let inclusion_proof = merkle_tree.transaction_inclusion_proof(i as u32).unwrap();
            let witness_inclusion_proof =
                witness_merkle_tree.transaction_witness_inclusion_proof(i as u32).unwrap();

            assert!(inclusion_proof
                .verify(tx.transaction().get_id().to_hash(), merkle_tree.root())
                .passed_decisively());
            assert!(witness_inclusion_proof
                .verify(tx.serialized_hash(), witness_merkle_tree.root())
                .passed_decisively());
        }
    }
}
