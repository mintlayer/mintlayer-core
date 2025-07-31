// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate_test_framework::{anyonecanspend_address, TestFramework, TransactionBuilder};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, output_value::OutputValue,
        signature::inputsig::InputWitness, timelock::OutputTimeLock, Destination, Transaction,
        TxInput, TxOutput,
    },
    primitives::{Amount, BlockDistance, Id, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::{CryptoRng, Rng};

pub mod block_creation_helpers;
pub mod block_index_handle_impl;
pub mod block_status_helpers;
pub mod in_memory_storage_wrapper;
pub mod pos;

/// Adds a block with the locked output and returns input corresponding to this output.
pub fn add_block_with_locked_output(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    output_time_lock: OutputTimeLock,
    timestamp: BlockTimestamp,
) -> (InputWitness, TxInput, Id<Transaction>) {
    // Find the last block.
    let current_height = tf.best_block_index().block_height();
    let prev_block_outputs = tf.outputs_from_genblock(tf.block_id(current_height.into()));

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(prev_block_outputs.keys().next().unwrap().clone(), 0),
            InputWitness::NoSignature(None),
        )
        .add_anyone_can_spend_output(10000)
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(100000)),
            anyonecanspend_address(),
            output_time_lock,
        ))
        .build();
    let tx_id = tx.transaction().get_id();
    tf.make_block_builder()
        .add_transaction(tx)
        .with_timestamp(timestamp)
        .build_and_process(rng)
        .unwrap();

    let new_height = (current_height + BlockDistance::new(1)).unwrap();
    assert_eq!(tf.best_block_index().block_height(), new_height);

    let block_outputs = tf.outputs_from_genblock(tf.block_id(new_height.into()));
    assert!(block_outputs.contains_key(&tx_id.into()));
    (
        InputWitness::NoSignature(None),
        TxInput::from_utxo(tx_id.into(), 1),
        tx_id,
    )
}

pub fn new_pub_key_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pub_key)
}
