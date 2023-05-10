// Copyright (c) 2021-2023 RBB S.r.l
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

use merkletree::{tree::MerkleTree, MerkleTreeFormError};

use crate::{
    chain::SignedTransaction,
    primitives::{
        id::{self, Idable, H256},
        merkle_tools::MerkleHasher,
    },
};

use super::block_body::BlockBody;

pub fn calculate_tx_merkle_root(body: &BlockBody) -> Result<H256, MerkleTreeFormError> {
    const TX_HASHER: fn(&SignedTransaction) -> H256 =
        |tx: &SignedTransaction| tx.transaction().get_id().get();
    calculate_generic_merkle_root(&TX_HASHER, body)
}

pub fn calculate_witness_merkle_root(body: &BlockBody) -> Result<H256, MerkleTreeFormError> {
    const TX_HASHER: fn(&SignedTransaction) -> H256 =
        |tx: &SignedTransaction| tx.serialized_hash().get();
    calculate_generic_merkle_root(&TX_HASHER, body)
}

fn calculate_generic_merkle_root(
    tx_hasher: &fn(&SignedTransaction) -> H256,
    body: &BlockBody,
) -> Result<H256, MerkleTreeFormError> {
    let rewards_hash = id::hash_encoded(&body.reward);

    if body.transactions.is_empty() {
        // using bitcoin's way, blocks that only have the coinbase (or a single tx in general)
        // use their coinbase as the merkleroot
        return Ok(rewards_hash);
    }

    let hashes: Vec<H256> = std::iter::once(rewards_hash)
        .chain(body.transactions.iter().map(tx_hasher))
        .collect();
    let t = MerkleTree::<H256, MerkleHasher>::from_leaves(hashes)?;
    Ok(t.root())
}
