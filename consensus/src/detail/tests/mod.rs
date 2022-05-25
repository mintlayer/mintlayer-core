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
use common::chain::block::{Block, ConsensusData};
use common::chain::config::create_unit_test_config;
use common::chain::signature::inputsig::InputWitness;
use common::chain::{Destination, Transaction, TxInput, TxOutput};
use common::primitives::{time, H256};
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
mod processing_tests;
#[cfg(test)]
mod reorgs_tests;

#[cfg(test)]
mod signature_tests;

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

fn empty_witness() -> InputWitness {
    let mut rng = rand::thread_rng();
    let mut msg: Vec<u8> = (1..100).collect();
    msg.shuffle(&mut rng);
    InputWitness::NoSignature(Some(msg))
}

fn anyonecanspend_address() -> Destination {
    Destination::AnyoneCanSpend
}

fn create_utxo_data(
    tx_id: &Id<Transaction>,
    index: usize,
    output: &TxOutput,
) -> Option<(TxInput, TxOutput)> {
    let mut rng = thread_rng();
    let spent_value = rng.gen_range(0..output.get_value().into_atoms());
    if output.get_value() > Amount::from_atoms(spent_value) {
        Some((
            TxInput::new(
                OutPointSourceId::Transaction(tx_id.clone()),
                index as u32,
                empty_witness(),
            ),
            TxOutput::new(
                (output.get_value() - Amount::from_atoms(spent_value)).unwrap(),
                anyonecanspend_address(),
            ),
        ))
    } else {
        None
    }
}

struct ConsensusBuilder {
    config: ChainConfig,
    storage: Store,
}

impl ConsensusBuilder {
    fn new() -> Self {
        Self {
            config: create_unit_test_config(),
            storage: Store::new_empty().unwrap(),
        }
    }
    fn build(self) -> Consensus {
        Consensus::new(Arc::new(self.config), self.storage).unwrap()
    }

    #[allow(unused)]
    fn with_config(mut self, chain_config: ChainConfig) -> Self {
        self.config = chain_config;
        self
    }
}

fn setup_consensus() -> Consensus {
    ConsensusBuilder::new().build()
}

fn produce_test_block(prev_block: &Block, orphan: bool) -> Block {
    produce_test_block_with_consensus_data(prev_block, orphan, ConsensusData::None)
}

fn produce_test_block_with_consensus_data(
    prev_block: &Block,
    orphan: bool,
    consensus_data: ConsensusData,
) -> Block {
    // For each output we create a new input and output that will placed into a new block.
    // If value of original output is less than 1 then output will disappear in a new block.
    // Otherwise, value will be decreasing for 1.
    let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) =
        prev_block.transactions().iter().flat_map(create_new_outputs).unzip();

    Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
        if orphan {
            Some(Id::new(&H256::random()))
        } else {
            Some(Id::new(&prev_block.get_id().get()))
        },
        time::get() as u32,
        consensus_data,
    )
    .expect(ERR_CREATE_BLOCK_FAIL)
}

fn create_new_outputs(tx: &Transaction) -> Vec<(TxInput, TxOutput)> {
    tx.get_outputs()
        .iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(&tx.get_id(), index, output))
        .collect::<Vec<(TxInput, TxOutput)>>()
}

fn wait_for_threadpool_to_finish(consensus: &mut Consensus) {
    // We continue execution when previous threads finished, or cause panic in 3 secs
    let handle = consensus.events_broadcaster.spawn_handle(|| {});
    // TODO: This is not the correct way to check threads finishing because of the thread pool has
    // multiple threads (where it's now only one), there's no guarantee that the last spawned event will
    // finish last. The correct solution to this is either keeping track of all handles, or
    // counting the number of running threads with an atomic counter through a wrapper that
    // calls the functions and increase/decrease the counter.
    assert!(handle.wait_timeout(std::time::Duration::from_secs(3)).is_ok());
}
