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

use crate::detail::tests::test_framework::BlockTestFramework;
use crate::detail::*;
use blockchain_storage::Store;
use common::chain::block::{Block, ConsensusData};
use common::chain::config::{create_regtest, create_unit_test_config};
use common::chain::signature::inputsig::InputWitness;
use common::chain::{Destination, OutPointSourceId, Transaction, TxInput, TxOutput};
use common::primitives::{time, H256};
use common::primitives::{Amount, Id};
use common::Uint256;
use crypto::random::{Rng, SliceRandom};
use serialization::Encode;
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
#[cfg(test)]
mod syncing_tests;

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
    let mut rng = crypto::random::make_pseudo_rng();
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
    let mut rng = crypto::random::make_pseudo_rng();
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

    #[allow(unused)]
    fn with_config(mut self, chain_config: ChainConfig) -> Self {
        self.config = chain_config;
        self
    }
}

fn setup_chainstate() -> Chainstate {
    ChainstateBuilder::new().build()
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

// generate 5 regtest blocks and print them in hex
// TODO: remove when block production is ready
#[ignore]
#[test]
fn generate_blocks_for_functional_tests() {
    let config = create_regtest();
    let chainstate = ChainstateBuilder::new().with_config(config).build();
    let mut btf = BlockTestFramework::with_chainstate(chainstate);
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]);

    for i in 1..6 {
        let prev_block =
            btf.get_block(btf.block_indexes[i - 1].get_block_id().clone()).unwrap().unwrap();
        let mut mined_block = btf.random_block(&prev_block, None);
        let bits = difficulty.into();
        assert!(
            crate::detail::pow::work::mine(&mut mined_block, u128::MAX, bits, vec![])
                .expect("Unexpected conversion error")
        );
        println!("{}", hex::encode(mined_block.encode()));
        btf.add_special_block(mined_block).unwrap();
    }
}
