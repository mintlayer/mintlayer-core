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

#![allow(clippy::unwrap_used)]

use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, BlockSource, ChainstateConfig,
};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        config::ChainConfig,
        signature::inputsig::InputWitness,
        tokens::OutputValue,
        transaction::Transaction,
        Destination, GenBlock, GenBlockId, Genesis, OutPointSourceId, OutputPurpose, TxInput,
        TxOutput,
    },
    primitives::{time, Amount, Id, Idable},
};
use crypto::random::SliceRandom;
use libp2p::Multiaddr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

pub fn make_libp2p_addr() -> Multiaddr {
    "/ip6/::1/tcp/0".parse().unwrap()
}

pub fn make_mock_addr() -> SocketAddr {
    "[::1]:0".parse().unwrap()
}

pub async fn get_two_connected_sockets() -> (TcpStream, TcpStream) {
    let addr = make_mock_addr();
    let server = TcpListener::bind(addr).await.unwrap();
    let peer_fut = TcpStream::connect(server.local_addr().unwrap());

    let (res1, res2) = tokio::join!(server.accept(), peer_fut);
    (res1.unwrap().0, res2.unwrap())
}

pub async fn get_tcp_socket() -> TcpStream {
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    let addr: SocketAddr = format!("[::1]:{}", port).parse().unwrap();
    let server = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        loop {
            let _ = server.accept().await.unwrap();
        }
    });

    TcpStream::connect(addr).await.unwrap()
}

pub type ChainstateHandle = subsystem::Handle<Box<dyn ChainstateInterface + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBlockInfo {
    pub(crate) txns: Vec<(OutPointSourceId, Vec<TxOutput>)>,
    pub(crate) id: Id<GenBlock>,
}

impl TestBlockInfo {
    pub fn from_block(blk: &Block) -> Self {
        let txns = blk
            .transactions()
            .iter()
            .map(|tx| {
                (
                    OutPointSourceId::Transaction(tx.get_id()),
                    tx.outputs().clone(),
                )
            })
            .collect();
        let id = blk.get_id().into();
        Self { txns, id }
    }

    pub fn from_genesis(genesis: &Genesis) -> Self {
        let id: Id<GenBlock> = genesis.get_id().into();
        let outsrc = OutPointSourceId::BlockReward(id);
        let txns = vec![(outsrc, genesis.utxos().to_vec())];
        Self { txns, id }
    }

    pub async fn from_id(ci: &ChainstateHandle, config: &ChainConfig, id: Id<GenBlock>) -> Self {
        match id.classify(config) {
            GenBlockId::Genesis(_) => Self::from_genesis(config.genesis_block()),
            GenBlockId::Block(id) => {
                let block = ci.call(move |this| this.get_block(id)).await.unwrap().unwrap();
                Self::from_block(&block.unwrap())
            }
        }
    }

    pub async fn from_tip(handle: &ChainstateHandle, config: &ChainConfig) -> Self {
        let id = handle.call(move |this| this.get_best_block_id()).await.unwrap().unwrap();
        Self::from_id(handle, config, id).await
    }
}

fn create_utxo_data(
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
) -> Option<(TxInput, TxOutput)> {
    let output_value = match output.value() {
        OutputValue::Coin(coin) => *coin,
    };
    let new_value = (output_value - Amount::from_atoms(1)).unwrap();
    if new_value == Amount::from_atoms(0) {
        return None;
    }
    Some((
        TxInput::new(outsrc, index as u32, nosig_random_witness()),
        TxOutput::new(
            OutputValue::Coin(new_value),
            OutputPurpose::Transfer(anyonecanspend_address()),
        ),
    ))
}

fn produce_test_block(config: &ChainConfig, prev_block: TestBlockInfo) -> Block {
    produce_test_block_with_consensus_data(config, prev_block, ConsensusData::None)
}

fn produce_test_block_with_consensus_data(
    _config: &ChainConfig,
    prev_block: TestBlockInfo,
    consensus_data: ConsensusData,
) -> Block {
    // For each output we create a new input and output that will placed into a new block.
    // If value of original output is less than 1 then output will disappear in a new block.
    // Otherwise, value will be decreasing for 1.
    let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
        .txns
        .into_iter()
        .flat_map(|(outsrc, outs)| create_new_outputs(outsrc, &outs))
        .unzip();

    Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect("not to fail")],
        prev_block.id,
        BlockTimestamp::from_duration_since_epoch(time::get()),
        consensus_data,
    )
    .expect("not to fail")
}

fn create_new_outputs(srcid: OutPointSourceId, outs: &[TxOutput]) -> Vec<(TxInput, TxOutput)> {
    outs.iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(srcid.clone(), index, output))
        .collect()
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
    chain_config: Arc<ChainConfig>,
) -> subsystem::Handle<Box<dyn ChainstateInterface>> {
    let storage = chainstate_storage::Store::new_empty().unwrap();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "chainstate",
        make_chainstate(
            chain_config,
            ChainstateConfig::new(),
            storage,
            None,
            Default::default(),
        )
        .unwrap(),
    );
    tokio::spawn(async move { man.main().await });
    handle
}

pub fn create_block(config: Arc<ChainConfig>, parent: TestBlockInfo) -> Block {
    produce_test_block(&config, parent)
}

pub fn create_n_blocks(
    config: Arc<ChainConfig>,
    mut prev: TestBlockInfo,
    nblocks: usize,
) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();

    for _ in 0..nblocks {
        let block = create_block(Arc::clone(&config), prev);
        prev = TestBlockInfo::from_block(&block);
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
    let base_block = match id.classify(&config) {
        GenBlockId::Genesis(_id) => TestBlockInfo::from_genesis(config.genesis_block()),
        GenBlockId::Block(id) => {
            let best_block = handle.call(move |this| this.get_block(id)).await.unwrap().unwrap();
            TestBlockInfo::from_block(&best_block.unwrap())
        }
    };

    let blocks = create_n_blocks(config, base_block, nblocks);
    import_blocks(handle, blocks).await;
}
