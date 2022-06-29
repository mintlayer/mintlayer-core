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

use std::{iter, sync::Mutex};

use crate::detail::*;
use chainstate_storage::Store;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        config::create_unit_test_config,
        signature::inputsig::InputWitness,
        Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount, Id, H256},
};
use crypto::random::Rng;

mod double_spend_tests;
mod events_tests;
mod processing_tests;
mod reorgs_tests;
mod signature_tests;
mod syncing_tests;
mod test_framework;

type EventList = Arc<Mutex<Vec<(Id<Block>, BlockHeight)>>>;

const ERR_BEST_BLOCK_NOT_FOUND: &str = "Best block not found";
const ERR_STORAGE_FAIL: &str = "Storage failure";
const ERR_CREATE_BLOCK_FAIL: &str = "Creating block caused fail";
const ERR_CREATE_TX_FAIL: &str = "Creating tx caused fail";

fn empty_witness() -> InputWitness {
    let mut rng = crypto::random::make_pseudo_rng();
    let length = rng.gen_range(50..150);
    let msg = iter::from_fn(|| rng.gen()).take(length).collect();
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
    let mut rng = crypto::random::make_pseudo_rng();
    let spent_value = rng.gen_range(0..output.value().into_atoms());
    if output.value() > Amount::from_atoms(spent_value) {
        Some((
            TxInput::new(
                OutPointSourceId::Transaction(tx_id.clone()),
                index as u32,
                empty_witness(),
            ),
            TxOutput::new(
                (output.value() - Amount::from_atoms(spent_value)).unwrap(),
                anyonecanspend_address(),
            ),
        ))
    } else {
        None
    }
}

struct ChainstateBuilder {
    config: ChainConfig,
    storage: Store,
}

impl ChainstateBuilder {
    fn new() -> Self {
        Self {
            config: create_unit_test_config(),
            storage: Store::new_empty().unwrap(),
        }
    }
    fn build(self) -> Chainstate {
        Chainstate::new(
            Arc::new(self.config),
            self.storage,
            None,
            Default::default(),
        )
        .unwrap()
    }

    fn with_config(mut self, chain_config: ChainConfig) -> Self {
        self.config = chain_config;
        self
    }
}

fn setup_chainstate() -> Chainstate {
    ChainstateBuilder::new().build()
}

fn chainstate_with_config(config: ChainConfig) -> Chainstate {
    ChainstateBuilder::new().with_config(config).build()
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
        BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
        consensus_data,
    )
    .expect(ERR_CREATE_BLOCK_FAIL)
}

fn create_new_outputs(tx: &Transaction) -> Vec<(TxInput, TxOutput)> {
    tx.outputs()
        .iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(&tx.get_id(), index, output))
        .collect::<Vec<(TxInput, TxOutput)>>()
}
