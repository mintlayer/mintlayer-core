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

use chainstate::{BlockError, BlockIndex, BlockSource, ChainstateError, OrphanCheckError};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        output_value::OutputValue, signed_transaction::SignedTransaction, timelock::OutputTimeLock,
        Block, GenBlock, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use randomness::{CryptoRng, Rng};

// Build a block that spends some outputs of its parent.
pub fn build_block(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut impl Rng,
) -> Block {
    tf.make_block_builder()
        .add_test_transaction_with_parent(*parent_block, rng)
        .with_parent(*parent_block)
        .with_reward(make_block_reward())
        .build()
}

pub fn make_block_reward() -> Vec<TxOutput> {
    vec![TxOutput::LockThenTransfer(
        coins(1_000_000),
        anyonecanspend_address(),
        OutputTimeLock::ForBlockCount(0),
    )]
}

// Process a block that spends some outputs of its parent.
pub fn process_block(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut impl Rng,
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let block = build_block(tf, parent_block, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

// Build a block with an invalid tx that has no inputs and outputs.
pub fn build_block_with_empty_tx(tf: &mut TestFramework, parent_block: &Id<GenBlock>) -> Block {
    let bad_tx = TransactionBuilder::new().build();
    tf.make_block_builder()
        .with_parent(*parent_block)
        .with_transactions(vec![bad_tx])
        .build()
}

// Process a block with an invalid tx that has no inputs and outputs.
pub fn process_block_with_empty_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let bad_block = build_block_with_empty_tx(tf, parent_block);
    let bad_block_id = bad_block.get_id();
    let result = tf.process_block(bad_block, BlockSource::Local);

    (bad_block_id, result)
}

pub fn build_block_burn_or_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    burn: bool,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(*parent_block), 0),
            empty_witness(rng),
        )
        .add_output(if burn {
            TxOutput::Burn(some_coins(rng))
        } else {
            TxOutput::Transfer(some_coins(rng), anyonecanspend_address())
        })
        .build();
    let block = tf
        .make_block_builder()
        .with_transactions(vec![tx.clone()])
        .with_parent(*parent_block)
        .with_reward(make_block_reward())
        .build();

    (block, tx)
}

pub fn build_block_burn_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    build_block_burn_or_spend_parent_reward(tf, parent_block, true, rng)
}

pub fn build_block_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    build_block_burn_or_spend_parent_reward(tf, parent_block, false, rng)
}

pub fn process_block_burn_or_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    burn: bool,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let (block, _) = build_block_burn_or_spend_parent_reward(tf, parent_block, burn, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

pub fn process_block_spend_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    process_block_burn_or_spend_parent_reward(tf, parent_block, false, rng)
}

// Build a block with one transaction that spends the parent's reward and has two outputs:
// output #0 transfers some coins to anyonecanspend address, and #1 burns some coins;
pub fn build_block_split_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (Block, SignedTransaction) {
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(*parent_block), 0),
            empty_witness(rng),
        )
        .add_output(TxOutput::Transfer(
            some_coins(rng),
            anyonecanspend_address(),
        ))
        .add_output(TxOutput::Burn(some_coins(rng)))
        .build();
    let block = tf
        .make_block_builder()
        .with_transactions(vec![tx.clone()])
        .with_parent(*parent_block)
        .with_reward(make_block_reward())
        .build();

    (block, tx)
}

pub fn process_block_split_parent_reward(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    rng: &mut (impl Rng + CryptoRng),
) -> (
    Id<Block>,
    Id<Transaction>,
    Result<Option<BlockIndex>, ChainstateError>,
) {
    let (block, tx) = build_block_split_parent_reward(tf, parent_block, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, tx.transaction().get_id(), result)
}

// Build a block that spends the specified tx.
pub fn build_block_spend_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    parent_tx: &Id<Transaction>,
    tx_output_index: u32,
    rng: &mut (impl Rng + CryptoRng),
) -> Block {
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo((*parent_tx).into(), tx_output_index),
            empty_witness(rng),
        )
        .add_output(TxOutput::Transfer(
            less_coins(rng),
            anyonecanspend_address(),
        ))
        .build();

    tf.make_block_builder()
        .with_transactions(vec![tx])
        .with_parent(*parent_block)
        .with_reward(make_block_reward())
        .build()
}

// Process a block that spends the specified tx.
pub fn process_block_spend_tx(
    tf: &mut TestFramework,
    parent_block: &Id<GenBlock>,
    parent_tx: &Id<Transaction>,
    tx_output_index: u32,
    rng: &mut (impl Rng + CryptoRng),
) -> (Id<Block>, Result<Option<BlockIndex>, ChainstateError>) {
    let block = build_block_spend_tx(tf, parent_block, parent_tx, tx_output_index, rng);
    let block_id = block.get_id();
    let result = tf.process_block(block, BlockSource::Local);
    (block_id, result)
}

pub fn assert_block_data_exists(tf: &TestFramework, block_id: &Id<Block>, should_exist: bool) {
    assert_eq!(tf.block_opt(*block_id).is_some(), should_exist);
}

pub fn assert_orphan_added_result<T: std::fmt::Debug>(result: Result<T, ChainstateError>) {
    assert_eq!(
        result.unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::OrphanCheckFailed(
            OrphanCheckError::LocalOrphan
        ))
    );
}

pub fn coins(amount: u32) -> OutputValue {
    OutputValue::Coin(Amount::from_atoms(amount.into()))
}

pub fn some_coins(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    coins(rng.gen_range(100_000..200_000))
}

pub fn less_coins(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    coins(rng.gen_range(50_000..100_000))
}
