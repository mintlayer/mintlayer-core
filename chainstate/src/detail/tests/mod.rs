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
// Author(s): S. Afach, A. Sinitsyn, S. Tkach

use std::sync::Mutex;

use crate::detail::{tests::test_framework::BlockTestFramework, *};
use chainstate_storage::Store;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        config::{create_regtest, create_unit_test_config},
        signature::inputsig::InputWitness,
        Destination, OutPointSourceId, OutputPurpose, Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount, Id, H256},
    Uint256,
};
use crypto::random::{Rng, SliceRandom};
use serialization::Encode;

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
    let spent_value = Amount::from_atoms(rng.gen_range(0..output.value().into_atoms()));
    if output.value() > spent_value {
        Some((
            TxInput::new(
                OutPointSourceId::Transaction(tx_id.clone()),
                index as u32,
                empty_witness(),
            ),
            TxOutput::new(
                (output.value() - spent_value).unwrap(),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ),
        ))
    } else {
        None
    }
}

fn setup_chainstate() -> Chainstate {
    chainstate_with_config(create_unit_test_config(), ChainstateConfig::new())
}

fn chainstate_with_config(
    chain_config: ChainConfig,
    chainstate_config: ChainstateConfig,
) -> Chainstate {
    Chainstate::new(
        Arc::new(chain_config),
        chainstate_config,
        Store::new_empty().unwrap(),
        None,
        Default::default(),
    )
    .unwrap()
}

fn produce_test_block(prev_block: &Block, orphan: bool) -> Block {
    produce_test_block_with_consensus_data(prev_block, orphan, ConsensusData::None)
}

fn produce_test_block_with_consensus_data(
    prev_block: &Block,
    orphan: bool,
    consensus_data: ConsensusData,
) -> Block {
    // The value of each output is decreased by a random amount to produce a new input and output.
    let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) =
        prev_block.transactions().iter().flat_map(create_new_outputs).unzip();

    Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
        if orphan {
            Some(Id::new(H256::random()))
        } else {
            Some(Id::new(prev_block.get_id().get()))
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

// Generate 5 regtest blocks and print their hex encoding, which is useful for functional tests.
// TODO: remove when block production is ready
#[ignore]
#[test]
fn generate_blocks_for_functional_tests() {
    let chain_config = create_regtest();
    let chainstate_config = ChainstateConfig::new();
    let chainstate = chainstate_with_config(chain_config, chainstate_config);
    let mut btf = BlockTestFramework::with_chainstate(chainstate);
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]);

    for i in 1..6 {
        let prev_block =
            btf.get_block(btf.block_indexes[i - 1].block_id().clone()).unwrap().unwrap();
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
