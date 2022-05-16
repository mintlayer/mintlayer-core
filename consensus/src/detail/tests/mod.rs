// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

use crate::detail::*;
use blockchain_storage::Store;
use common::address::Address;
use common::chain::block::{Block, ConsensusData};
use common::chain::config::create_mainnet;
use common::chain::{Destination, Transaction, TxInput, TxOutput};
use common::primitives::H256;
use common::primitives::{Amount, Id};
use rand::prelude::*;
use std::sync::Mutex;

pub(in crate::detail::tests) type EventList = Arc<Mutex<Vec<(Id<Block>, BlockHeight)>>>;

mod test_framework;

#[cfg(test)]
mod double_spend_tests;
#[cfg(test)]
mod events_tests;
#[cfg(test)]
mod indices_tests;
#[cfg(test)]
mod processing_tests;
#[cfg(test)]
mod reorgs_tests;

pub(crate) const ERR_BEST_BLOCK_NOT_FOUND: &str = "Best block not found";
pub(crate) const ERR_STORAGE_FAIL: &str = "Storage failure";
pub(crate) const ERR_CREATE_BLOCK_FAIL: &str = "Creating block caused fail";
pub(crate) const ERR_CREATE_TX_FAIL: &str = "Creating tx caused fail";

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::detail::tests) enum TestBlockParams {
    NoErrors,
    TxCount(usize),
    Fee(Amount),
    Orphan,
    SpendFrom(Id<Block>),
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::detail::tests) enum TestSpentStatus {
    Spent,
    Unspent,
    NotInMainchain,
}

fn setup_consensus() -> Consensus {
    let config = create_mainnet();
    let storage = Store::new_empty().unwrap();
    Consensus::new(config, storage).unwrap()
}

fn random_witness() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut witness: Vec<u8> = (1..100).collect();
    witness.shuffle(&mut rng);
    witness
}

fn random_address(chain_config: &ChainConfig) -> Destination {
    let mut rng = rand::thread_rng();
    let mut address: Vec<u8> = (1..22).collect();
    address.shuffle(&mut rng);
    let receiver = Address::new(chain_config, address).expect("Failed to create address");
    Destination::Address(receiver)
}

fn generate_random_h256(g: &mut impl rand::Rng) -> H256 {
    let mut bytes = [0u8; 32];
    g.fill_bytes(&mut bytes);
    H256::from(bytes)
}

fn generate_random_bytes(g: &mut impl rand::Rng, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.resize(length, 0);
    g.fill_bytes(&mut bytes);
    bytes
}

fn generate_random_invalid_input(g: &mut impl rand::Rng) -> TxInput {
    let witness_size = g.next_u32();
    let witness = generate_random_bytes(g, (1 + witness_size % 1000) as usize);
    let outpoint = if g.next_u32() % 2 == 0 {
        OutPointSourceId::Transaction(Id::new(&generate_random_h256(g)))
    } else {
        OutPointSourceId::BlockReward(Id::new(&generate_random_h256(g)))
    };

    TxInput::new(outpoint, g.next_u32(), witness)
}

fn generate_random_invalid_output(g: &mut impl rand::Rng) -> TxOutput {
    let config = create_mainnet();

    let addr =
        Address::new(&config, generate_random_bytes(g, 20)).expect("Failed to create address");

    TxOutput::new(
        Amount::from_atoms(g.next_u64() as u128),
        Destination::Address(addr),
    )
}

fn generate_random_invalid_transaction(rng: &mut impl rand::Rng) -> Transaction {
    let inputs = {
        let input_count = 1 + (rng.next_u32() as usize) % 10;
        (0..input_count)
            .into_iter()
            .map(|_| generate_random_invalid_input(rng))
            .collect::<Vec<_>>()
    };

    let outputs = {
        let output_count = 1 + (rng.next_u32() as usize) % 10;
        (0..output_count)
            .into_iter()
            .map(|_| generate_random_invalid_output(rng))
            .collect::<Vec<_>>()
    };

    let flags = rng.next_u32();
    let lock_time = rng.next_u32();

    Transaction::new(flags, inputs, outputs, lock_time).expect(ERR_CREATE_TX_FAIL)
}

fn generate_random_invalid_block() -> Block {
    let mut rng = rand::rngs::StdRng::from_entropy();

    let transactions = {
        let transaction_count = rng.next_u32() % 2000;
        (0..transaction_count)
            .into_iter()
            .map(|_| generate_random_invalid_transaction(&mut rng))
            .collect::<Vec<_>>()
    };
    let time = rng.next_u32();
    let prev_id = Some(Id::new(&generate_random_h256(&mut rng)));

    Block::new(transactions, prev_id, time, ConsensusData::None).expect(ERR_CREATE_BLOCK_FAIL)
}

fn create_utxo_data(
    config: &ChainConfig,
    tx_id: &Id<Transaction>,
    index: usize,
    output: &TxOutput,
) -> Option<(TxInput, TxOutput)> {
    if output.get_value() > Amount::from_atoms(1) {
        Some((
            TxInput::new(
                OutPointSourceId::Transaction(tx_id.clone()),
                index as u32,
                random_witness(),
            ),
            TxOutput::new(
                (output.get_value() - Amount::from_atoms(1)).unwrap(),
                random_address(config),
            ),
        ))
    } else {
        None
    }
}

fn produce_test_block(config: &ChainConfig, prev_block: &Block, orphan: bool) -> Block {
    // For each output we create a new input and output that will placed into a new block.
    // If value of original output is less than 1 then output will disappear in a new block.
    // Otherwise, value will be decreasing for 1.
    let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
        .transactions()
        .iter()
        .flat_map(|tx| create_new_outputs(config, tx))
        .unzip();

    Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
        if orphan {
            Some(Id::new(&H256::random()))
        } else {
            Some(Id::new(&prev_block.get_id().get()))
        },
        time::get() as u32,
        ConsensusData::None,
    )
    .expect(ERR_CREATE_BLOCK_FAIL)
}

fn create_new_outputs(config: &ChainConfig, tx: &Transaction) -> Vec<(TxInput, TxOutput)> {
    tx.get_outputs()
        .iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(config, &tx.get_id(), index, output))
        .collect::<Vec<(TxInput, TxOutput)>>()
}

fn wait_for_threadpool_to_finish(consensus: &mut Consensus) {
    // We continue execution when previous threads finished, or cause panic in 3 secs
    let handle = consensus.events_broadcaster.spawn_handle(|| {});
    assert!(handle.wait_timeout(std::time::Duration::from_secs(3)).is_ok());
}
