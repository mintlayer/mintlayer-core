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
// Author(s): S. Afach, A. Sinitsyn, A. Altonen
use chainstate::{chainstate_interface::ChainstateInterface, make_chainstate, BlockSource};
use common::{
    chain::{
        block::{Block, ConsensusData},
        config::ChainConfig,
        signature::inputsig::InputWitness,
        transaction::Transaction,
        Destination, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{time, Amount, Id, Idable, H256},
};
use crypto::random::SliceRandom;
use std::sync::Arc;

fn create_utxo_data(
    _config: &ChainConfig,
    tx_id: &Id<Transaction>,
    index: usize,
    output: &TxOutput,
) -> Option<(TxInput, TxOutput)> {
    if output.get_value() > Amount::from_atoms(1) {
        Some((
            TxInput::new(
                OutPointSourceId::Transaction(tx_id.clone()),
                index as u32,
                nosig_random_witness(),
            ),
            TxOutput::new(
                (output.get_value() - Amount::from_atoms(1)).unwrap(),
                anyonecanspend_address(),
            ),
        ))
    } else {
        None
    }
}

fn produce_test_block(config: &ChainConfig, prev_block: &Block, orphan: bool) -> Block {
    produce_test_block_with_consensus_data(config, prev_block, orphan, ConsensusData::None)
}

fn produce_test_block_with_consensus_data(
    config: &ChainConfig,
    prev_block: &Block,
    orphan: bool,
    consensus_data: ConsensusData,
) -> Block {
    // For each output we create a new input and output that will placed into a new block.
    // If value of original output is less than 1 then output will disappear in a new block.
    // Otherwise, value will be decreasing for 1.
    let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
        .transactions()
        .iter()
        .flat_map(|tx| create_new_outputs(config, tx))
        .unzip();

    Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect("not to fail")],
        if orphan {
            Some(Id::new(&H256::random()))
        } else {
            Some(Id::new(&prev_block.get_id().get()))
        },
        time::get().as_secs() as u32,
        consensus_data,
    )
    .expect("not to fail")
}

fn create_new_outputs(config: &ChainConfig, tx: &Transaction) -> Vec<(TxInput, TxOutput)> {
    tx.get_outputs()
        .iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(config, &tx.get_id(), index, output))
        .collect::<Vec<(TxInput, TxOutput)>>()
}

fn nosig_random_witness() -> InputWitness {
    let mut rng = crypto::random::make_pseudo_rng();
    let mut data: Vec<u8> = (1..100).collect();
    data.shuffle(&mut rng);

    InputWitness::NoSignature(Some(data))
}

fn anyonecanspend_address() -> Destination {
    Destination::AnyoneCanSpend
}

pub async fn start_chainstate(
    config: Arc<ChainConfig>,
) -> subsystem::Handle<Box<dyn ChainstateInterface>> {
    let storage = blockchain_storage::Store::new_empty().unwrap();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "chainstate",
        make_chainstate(config, storage, None, Default::default()).unwrap(),
    );
    tokio::spawn(async move { man.main().await });
    handle
}

pub fn create_block(config: Arc<ChainConfig>, parent: &Block) -> Block {
    produce_test_block(&config, parent, false)
}

pub fn create_n_blocks(config: Arc<ChainConfig>, parent: &Block, nblocks: usize) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut prev = parent.clone();

    for _ in 0..nblocks {
        let block = create_block(Arc::clone(&config), &prev);
        prev = block.clone();
        blocks.push(block.clone());
    }

    blocks
}

pub async fn import_blocks(
    handle: &subsystem::Handle<Box<dyn ChainstateInterface>>,
    blocks: Vec<Block>,
) {
    for block in blocks.into_iter() {
        let _res = handle
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await
            .unwrap();
    }
}

pub async fn add_more_blocks(
    config: Arc<ChainConfig>,
    handle: &subsystem::Handle<Box<dyn ChainstateInterface>>,
    nblocks: usize,
) {
    let id = handle.call(move |this| this.get_best_block_id()).await.unwrap().unwrap();
    let best_block = handle.call(move |this| this.get_block(id)).await.unwrap().unwrap();

    let blocks = create_n_blocks(config, &best_block.unwrap(), nblocks);
    import_blocks(handle, blocks).await;
}
