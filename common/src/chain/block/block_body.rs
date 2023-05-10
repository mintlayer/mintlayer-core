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

use merkletree::{
    proof::single::{SingleProofHashes, SingleProofNodes},
    tree::MerkleTree,
    MerkleTreeFormError, MerkleTreeProofExtractionError,
};
use serialization::{Decode, Encode};

use crate::{
    chain::SignedTransaction,
    primitives::{merkle_tools::MerkleHasher, H256},
};

use super::{
    block_merkle::{calculate_tx_merkle_tree, calculate_witness_merkle_tree},
    BlockReward,
};

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

    pub fn transactions(&self) -> &Vec<SignedTransaction> {
        &self.transactions
    }

    pub fn reward(&self) -> &BlockReward {
        &self.reward
    }

    pub fn tx_merkle_tree(&self) -> Result<MerkleTree<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_tx_merkle_tree(self)?;
        Ok(tree)
    }

    pub fn tx_witness_merkle_tree(
        &self,
    ) -> Result<MerkleTree<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_witness_merkle_tree(self)?;
        Ok(tree)
    }

    pub fn tx_merkle_root(&self) -> Result<H256, BlockMerkleTreeError> {
        let tree = calculate_tx_merkle_tree(self)?;
        Ok(tree.root())
    }

    pub fn witness_merkle_root(&self) -> Result<H256, BlockMerkleTreeError> {
        let tree = calculate_witness_merkle_tree(self)?;
        Ok(tree.root())
    }

    /// Create a proof that the block reward is included in the block (witness) merkle tree.
    pub fn create_witness_block_reward_inclusion_proof(
        &self,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_witness_merkle_tree(self)?;

        // Block reward has index 0 in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&tree, 0)?;

        Ok(proof.into_values())
    }

    pub fn create_tx_block_reward_inclusion_proof(
        &self,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_tx_merkle_tree(self)?;

        // Block reward has index 0 in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&tree, 0)?;

        Ok(proof.into_values())
    }

    pub fn create_witness_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_witness_merkle_tree(self)?;

        // We add 1 to the index_in_block because the block reward is the first element in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&tree, index_in_block + 1)?;

        Ok(proof.into_values())
    }

    pub fn create_tx_inclusion_proof(
        &self,
        index_in_block: u32,
    ) -> Result<SingleProofHashes<H256, MerkleHasher>, BlockMerkleTreeError> {
        let tree = calculate_tx_merkle_tree(self)?;

        // We add 1 to the index_in_block because the block reward is the first element in the block merkle tree
        let proof = SingleProofNodes::from_tree_leaf(&tree, index_in_block + 1)?;

        Ok(proof.into_values())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::primitives::id::Idable;
    use crate::{
        chain::{
            block::BlockReward,
            signature::{
                inputsig::{standard_signature::StandardInputSignature, InputWitness},
                sighash::sighashtype::SigHashType,
            },
            tokens::OutputValue,
            Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::{
        key::{KeyKind, PrivateKey},
        random::CryptoRng,
    };
    use proptest::prelude::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn generate_random_h256(rng: &mut impl Rng) -> H256 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        H256::from(bytes)
    }

    fn generate_random_bytes(rng: &mut impl Rng, length: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.resize(length, 0);
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn generate_random_invalid_witness(count: usize, rng: &mut impl Rng) -> Vec<InputWitness> {
        (0..count)
            .map(|_| {
                let witness_size = rng.next_u32();
                let witness_size = 1 + witness_size % 1000;
                let witness = generate_random_bytes(rng, witness_size as usize);
                InputWitness::Standard(StandardInputSignature::new(
                    SigHashType::try_from(SigHashType::ALL).unwrap(),
                    witness,
                ))
            })
            .collect::<Vec<_>>()
    }

    fn generate_random_invalid_input(rng: &mut impl Rng) -> TxInput {
        let outpoint = if rng.next_u32() % 2 == 0 {
            OutPointSourceId::Transaction(Id::new(generate_random_h256(rng)))
        } else {
            OutPointSourceId::BlockReward(Id::new(generate_random_h256(rng)))
        };

        TxInput::new(outpoint, rng.next_u32())
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

        let flags = rng.next_u32();
        let lock_time = rng.next_u32();

        let tx = Transaction::new(flags, inputs.clone(), outputs, lock_time)
            .expect("Creating tx caused fail");

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
            .map(|tx| tx.transaction().get_id().get())
            .collect::<Vec<_>>();

        let expected_merkle_leaves = std::iter::once(block_reward_witness_hash)
            .chain(transaction_ids.clone())
            .collect::<Vec<_>>();
        let expected_witness_merkle_leaves = std::iter::once(block_reward_witness_hash)
            .chain(transaction_witness_hashes.clone())
            .collect::<Vec<_>>();

        let merkle_tree = block_body.tx_merkle_tree().unwrap();
        let witness_merkle_tree = block_body.tx_witness_merkle_tree().unwrap();

        // Check leaf count
        let leaf_count = (transactions.len() + 1).next_power_of_two();
        assert_eq!(merkle_tree.leaf_count().get(), leaf_count as u32);
        assert_eq!(witness_merkle_tree.leaf_count().get(), leaf_count as u32);

        // Check leaves hashes
        let merkle_tree_leaves =
            (0..transactions.len() + 1) // +1 for block reward
                .map(|i| merkle_tree.node_from_bottom(0, i as u32).unwrap())
                .collect::<Vec<_>>();
        assert_eq!(
            merkle_tree_leaves.iter().map(|v| *v.hash()).collect::<Vec<_>>(),
            expected_merkle_leaves[..transactions.len() + 1]
        );

        // Check witness leaves hashes
        let witness_merkle_tree_leaves =
            (0..transactions.len() + 1) // +1 for block reward
                .map(|i| witness_merkle_tree.node_from_bottom(0, i as u32).unwrap())
                .collect::<Vec<_>>();
        assert_eq!(
            witness_merkle_tree_leaves.iter().map(|v| *v.hash()).collect::<Vec<_>>(),
            expected_witness_merkle_leaves
        );

        // Verify inclusion proofs for block reward (both witness and non-witness are the same for block reward)
        let block_reward_inclusion_proof =
            block_body.create_tx_block_reward_inclusion_proof().unwrap();
        let block_reward_witness_inclusion_proof =
            block_body.create_tx_block_reward_inclusion_proof().unwrap();

        block_reward_inclusion_proof.verify(
            block_reward_witness_hash,
            block_body.witness_merkle_root().unwrap(),
        );
        block_reward_witness_inclusion_proof.verify(
            block_reward_witness_hash,
            block_body.witness_merkle_root().unwrap(),
        );

        // Verify inclusion proofs for transactions
        for (i, tx) in transactions.iter().enumerate() {
            let inclusion_proof = block_body.create_tx_inclusion_proof(i as u32).unwrap();
            let witness_inclusion_proof =
                block_body.create_witness_inclusion_proof(i as u32).unwrap();

            inclusion_proof.verify(
                tx.transaction().get_id().get(),
                block_body.tx_merkle_root().unwrap(),
            );
            witness_inclusion_proof.verify(
                tx.serialized_hash(),
                block_body.witness_merkle_root().unwrap(),
            );
        }
    }
}
