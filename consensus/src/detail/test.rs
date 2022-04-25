#[cfg(test)]
use super::*;
use blockchain_storage::Store;
use common::address::Address;
use common::chain::block::{Block, ConsensusData};
use common::chain::config::create_mainnet;

use common::chain::{Destination, OutputSpentState, Transaction, TxInput, TxOutput};
use common::primitives::H256;
use common::primitives::{Amount, Id};
use rand::prelude::*;

#[derive(Debug)]
#[allow(dead_code)]
pub enum TestBlockParams {
    NoErrors,
    TxCount(usize),
    Fee(Amount),
    Orphan,
    SpendFrom(Id<Block>),
}

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum TestSpentStatus {
    Spent,
    Unspent,
    NotInMainchain,
}

pub(crate) const ERR_BEST_BLOCK_NOT_FOUND: &str = "Best block not found";
pub(crate) const ERR_STORAGE_FAIL: &str = "Storage failure";
pub(crate) const ERR_CREATE_BLOCK_FAIL: &str = "Creating block caused fail";
pub(crate) const ERR_CREATE_TX_FAIL: &str = "Creating tx caused fail";

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

fn setup_consensus() -> Consensus {
    let config = create_mainnet();
    let storage = Store::new_empty().unwrap();
    Consensus::new(config, storage).unwrap()
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

#[test]
fn test_indices_calculations() {
    let block = generate_random_invalid_block();
    let serialized_block = block.encode();
    let serialized_header = block.header().encode();
    let serialized_transactions = block.transactions().encode();
    assert_eq!(
        // +1 for the enum arm byte
        1 + serialized_header.len() + serialized_transactions.len(),
        serialized_block.len(),
    );
    // TODO: calculate block reward position
    for (tx_num, tx) in block.transactions().iter().enumerate() {
        let tx_index = calculate_tx_index_from_block(&block, tx_num).unwrap();
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(tx_index.get_output_count(), tx.get_outputs().len() as u32);

        let pos = match tx_index.get_position() {
            common::chain::SpendablePosition::Transaction(pos) => pos,
            common::chain::SpendablePosition::BlockReward(_) => unreachable!(),
        };
        let tx_start_pos = pos.get_byte_offset_in_block() as usize;
        let tx_end_pos =
            pos.get_byte_offset_in_block() as usize + pos.get_serialized_size() as usize;
        let tx_serialized_in_block = &serialized_block[tx_start_pos..tx_end_pos];
        let tx_serialized = tx.encode();
        assert_eq!(tx_serialized_in_block, tx_serialized);

        // to ensure Vec comparison is correct since I'm a paranoid C++ dude, let's mess things up
        let tx_messed = tx_serialized.iter().map(|c| c.wrapping_add(1)).collect::<Vec<u8>>();
        assert!(tx_serialized_in_block != tx_messed);
    }
}

#[test]
#[allow(clippy::eq_op)]
fn test_process_genesis_block_wrong_block_source() {
    common::concurrency::model(|| {
        // Genesis can't be from Peer, test it
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new_no_genesis(config.clone(), storage).unwrap();

        // process the genesis block
        let block_source = BlockSource::Peer(0);
        let result = consensus.process_block(config.genesis_block().clone(), block_source);
        assert_eq!(result, Err(BlockError::InvalidBlockSource));
    });
}

#[test]
#[allow(clippy::eq_op)]
fn test_process_genesis_block() {
    common::concurrency::model(|| {
        // This test process only Genesis block
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new_no_genesis(config, storage).unwrap();

        // process the genesis block
        let block_source = BlockSource::Local;
        let block_index = consensus
            .process_block(consensus.chain_config.genesis_block().clone(), block_source)
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );
        assert_eq!(block_index.get_prev_block_id(), &None);
        assert_eq!(block_index.get_chain_trust(), 1);
        assert_eq!(block_index.get_block_height(), BlockHeight::new(0));
    });
}

#[test]
#[allow(clippy::eq_op)]
fn test_straight_chain() {
    common::concurrency::model(|| {
        // In this test, processing a few correct blocks in a single chain
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new_no_genesis(config, storage).unwrap();

        // process the genesis block
        let block_source = BlockSource::Local;
        let mut block_index = consensus
            .process_block(consensus.chain_config.genesis_block().clone(), block_source)
            .ok()
            .flatten()
            .expect("Unable to process genesis block");
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );
        assert_eq!(
            block_index.get_block_id(),
            &consensus.chain_config.genesis_block().get_id()
        );
        assert_eq!(block_index.get_prev_block_id(), &None);
        // TODO: ensure that block at height is tested after removing the next
        assert_eq!(block_index.get_chain_trust(), 1);
        assert_eq!(block_index.get_block_height(), BlockHeight::new(0));

        let mut prev_block = consensus.chain_config.genesis_block().clone();
        for _ in 0..255 {
            let prev_block_id = block_index.get_block_id();
            let best_block_id = consensus
                .blockchain_storage
                .get_best_block_id()
                .ok()
                .flatten()
                .expect("Unable to get best block ID");
            assert_eq!(&best_block_id, block_index.get_block_id());
            let block_source = BlockSource::Peer(1);
            let new_block = produce_test_block(&consensus.chain_config, &prev_block, false);
            let new_block_index = dbg!(consensus.process_block(new_block.clone(), block_source))
                .ok()
                .flatten()
                .expect("Unable to process block");

            // TODO: ensure that block at height is tested after removing the next
            assert_eq!(
                new_block_index.get_prev_block_id().as_ref(),
                Some(prev_block_id)
            );
            assert!(new_block_index.get_chain_trust() > block_index.get_chain_trust());
            assert_eq!(
                new_block_index.get_block_height(),
                block_index.get_block_height().next_height()
            );

            block_index = new_block_index;
            prev_block = new_block;
        }
    });
}

#[test]
#[allow(clippy::eq_op)]
fn test_reorg_simple() {
    common::concurrency::model(|| {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new_no_genesis(config, storage).unwrap();

        // process the genesis block
        let result = consensus.process_block(
            consensus.chain_config.genesis_block().clone(),
            BlockSource::Local,
        );
        assert!(result.is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );

        // Process the second block
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            false,
        );
        let new_id = Some(block.get_id());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );

        // Process the parallel block and choose the better one
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            false,
        );
        // let new_id = Some(block.get_id());
        assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
        assert_ne!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(consensus.chain_config.genesis_block().get_id())
        );
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );

        // Produce another block that cause reorg
        let new_block = produce_test_block(&consensus.chain_config, &block, false);
        let new_id = Some(new_block.get_id());
        assert!(consensus.process_block(new_block, BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );
    });
}

#[test]
#[allow(clippy::eq_op)]
fn test_orphans_chains() {
    common::concurrency::model(|| {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage).unwrap();

        // Process the orphan block
        let new_block = consensus.chain_config.genesis_block().clone();
        for _ in 0..255 {
            let new_block = produce_test_block(&consensus.chain_config, &new_block, true);
            assert_eq!(
                consensus.process_block(new_block.clone(), BlockSource::Local),
                Err(BlockError::Orphan)
            );
        }
    });
}

#[test]
#[allow(clippy::eq_op)]
fn spend_tx_in_the_same_block() {
    common::concurrency::model(|| {
        // Check is it correctly spend when the second tx pointing on the first tx
        // +--Block----------------+
        // |                       |
        // | +-------tx-1--------+ |
        // | |input = prev_block | |
        // | +-------------------+ |
        // |                       |
        // | +-------tx-2--------+ |
        // | |input = tx1        | |
        // | +-------------------+ |
        // +-----------------------+
        {
            let mut consensus = setup_consensus();
            // Create base tx
            let receiver = random_address(&consensus.chain_config);

            let prev_block_tx_id = consensus
                .chain_config
                .genesis_block()
                .transactions()
                .get(0)
                .expect("Transaction not found")
                .get_id();

            let input = TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                random_witness(),
            );
            let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

            let first_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            let first_tx_id = first_tx.get_id();

            let input = TxInput::new(first_tx_id.into(), 0, vec![]);
            let output = TxOutput::new(Amount::from_atoms(987654321), receiver);
            let second_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            // Create tx that pointing to the previous tx
            let block = Block::new(
                vec![first_tx, second_tx],
                Some(Id::new(
                    &consensus.chain_config.genesis_block().get_id().get(),
                )),
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            let block_id = block.get_id();

            assert!(consensus.process_block(block, BlockSource::Local).is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(block_id)
            );
        }
        // The case is invalid. Transsactions should be in order
        // +--Block----------------+
        // |                       |
        // | +-------tx-1--------+ |
        // | |input = tx2        | |
        // | +-------------------+ |
        // |                       |
        // | +-------tx-2--------+ |
        // | |input = prev_block | |
        // | +-------------------+ |
        // +-----------------------+
        {
            let mut consensus = setup_consensus();
            // Create base tx
            let receiver = random_address(&consensus.chain_config);

            let prev_block_tx_id =
                consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

            let input = TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                random_witness(),
            );
            let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

            let first_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            let first_tx_id = first_tx.get_id();

            let input = TxInput::new(first_tx_id.into(), 0, vec![]);
            let output = TxOutput::new(Amount::from_atoms(987654321), receiver);
            let second_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            // Create tx that pointing to the previous tx
            let block = Block::new(
                vec![second_tx, first_tx],
                Some(Id::new(
                    &consensus.chain_config.genesis_block().get_id().get(),
                )),
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            assert!(consensus.process_block(block, BlockSource::Local).is_err());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND)
                    .expect(ERR_STORAGE_FAIL),
                consensus.chain_config.genesis_block().get_id()
            );
        }
    });
}

#[test]
#[allow(clippy::eq_op)]
fn double_spend_tx_in_the_same_block() {
    common::concurrency::model(|| {
        // Check is it correctly spend when a couple of transactions pointing on one output
        // +--Block----------------+
        // |                       |
        // | +-------tx-1--------+ |
        // | |input = prev_block | |
        // | +-------------------+ |
        // |                       |
        // | +-------tx-2--------+ |
        // | |input = tx1        | |
        // | +-------------------+ |
        // |                       |
        // | +-------tx-3--------+ |
        // | |input = tx1        | |
        // | +-------------------+ |
        // +-----------------------+

        let mut consensus = setup_consensus();
        let receiver = random_address(&consensus.chain_config);

        let prev_block_tx_id =
            consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

        // Create first tx
        let first_tx = Transaction::new(
            0,
            vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                random_witness(),
            )],
            vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone())],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);
        let first_tx_id = first_tx.get_id();

        // Create second tx
        let second_tx = Transaction::new(
            0,
            vec![TxInput::new(first_tx_id.clone().into(), 0, vec![])],
            vec![TxOutput::new(Amount::from_atoms(987654321), receiver.clone())],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);

        // Create third tx
        let third_tx = Transaction::new(
            123456789,
            vec![TxInput::new(first_tx_id.into(), 0, vec![])],
            vec![TxOutput::new(Amount::from_atoms(987654321), receiver)],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);

        // Create tx that pointing to the previous tx
        let block = Block::new(
            vec![first_tx, second_tx, third_tx],
            Some(Id::new(
                &consensus.chain_config.genesis_block().get_id().get(),
            )),
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        assert!(consensus.process_block(block, BlockSource::Local).is_err());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND)
                .expect(ERR_STORAGE_FAIL),
            consensus.chain_config.genesis_block().get_id()
        );
    });
}

#[test]
#[allow(clippy::eq_op)]
fn double_spend_tx_in_another_block() {
    common::concurrency::model(|| {
        // Check is it correctly spend when a couple of transactions in a different blocks pointing on one output
        //
        // Genesis -> b1 -> b2 where
        //
        // +--Block-1--------------+
        // |                       |
        // | +-------tx-1--------+ |
        // | |input = genesis    | |
        // | +-------------------+ |
        // +-----------------------+
        //
        // +--Block-2--------------+
        // |                       |
        // | +-------tx-1--------+ |
        // | |input = genesis    | |
        // | +-------------------+ |
        // +-----------------------+

        let mut consensus = setup_consensus();
        let receiver = random_address(&consensus.chain_config);

        let prev_block_tx_id =
            consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

        // Create first tx
        let first_tx = Transaction::new(
            0,
            vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id.clone()),
                0,
                random_witness(),
            )],
            vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone())],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);

        // Create tx that pointing to the previous tx
        let first_block = Block::new(
            vec![first_tx],
            Some(Id::new(
                &consensus.chain_config.genesis_block().get_id().get(),
            )),
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        let first_block_id = first_block.get_id();
        assert!(consensus.process_block(first_block, BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(first_block_id.clone())
        );
        // Create second tx
        let second_tx = Transaction::new(
            12345,
            vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                random_witness(),
            )],
            vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver)],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);

        // Create tx that pointing to the previous tx
        let second_block = Block::new(
            vec![second_tx],
            Some(first_block_id.clone()),
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        assert!(consensus.process_block(second_block, BlockSource::Local).is_err());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND)
                .expect(ERR_STORAGE_FAIL),
            first_block_id
        );
    });
}

struct BlockTestFrameWork {
    consensus: Consensus,
    blocks: Vec<Block>,
}

impl<'a> BlockTestFrameWork {
    pub fn new() -> Self {
        let consensus = setup_consensus();
        let genesis = consensus.chain_config.genesis_block().clone();
        Self {
            consensus,
            blocks: vec![genesis],
        }
    }

    #[allow(dead_code)]
    pub fn random_block(&self, parent_block: &Block, params: Option<&[TestBlockParams]>) -> Block {
        let (mut inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = parent_block
            .transactions()
            .iter()
            .flat_map(|tx| create_new_outputs(&self.consensus.chain_config, tx))
            .unzip();

        let mut hash_prev_block = Some(parent_block.get_id());
        if let Some(params) = params {
            for param in params {
                match param {
                    TestBlockParams::SpendFrom(block_id) => {
                        let block = self
                            .consensus
                            .blockchain_storage
                            .get_block(block_id.clone())
                            .unwrap()
                            .unwrap();

                        let double_spend_input = TxInput::new(
                            OutPointSourceId::Transaction(block.transactions()[0].get_id()),
                            0,
                            vec![],
                        );
                        inputs.push(double_spend_input)
                    }
                    TestBlockParams::Orphan => hash_prev_block = Some(Id::new(&H256::random())),
                    _ => unimplemented!(),
                }
            }
        }

        Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
            hash_prev_block,
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL)
    }

    pub fn genesis(&self) -> &Block {
        self.consensus.chain_config.genesis_block()
    }

    fn get_children_blocks(current_block_id: &Id<Block>, blocks: &Vec<Block>) -> Vec<Id<Block>> {
        let mut result = Vec::new();
        for block in blocks {
            if let Some(ref prev_block_id) = block.prev_block_id() {
                if prev_block_id == current_block_id {
                    result.push(block.get_id());
                }
            }
        }
        result
    }

    fn get_block_index(&self, block_id: &Id<Block>) -> BlockIndex {
        self.consensus.blockchain_storage.get_block_index(block_id).unwrap().unwrap()
    }

    pub fn debug_print_chains(&self, blocks: Vec<Id<Block>>, depth: usize) {
        if blocks.is_empty() {
            println!("{}X", "--".repeat(depth));
        } else {
            for block_id in blocks {
                let block_index = self.get_block_index(&block_id);
                let mut main_chain = "";
                if self.is_block_in_main_chain(&block_id) {
                    main_chain = ",M";
                }
                println!(
                    "{tabs}+-- {block_id} (H:{height}{mainchain_flag},P:{position})",
                    tabs = "\t".repeat(depth),
                    block_id = &block_id.get(),
                    height = block_index.get_block_height(),
                    mainchain_flag = main_chain,
                    position =
                        self.blocks.iter().position(|block| block.get_id() == block_id).unwrap()
                );
                let block_children = Self::get_children_blocks(&block_id, &self.blocks);
                if !block_children.is_empty() {
                    self.debug_print_chains(block_children, depth + 1);
                }
            }
        }
    }

    pub fn debug_print_tx(&self, block_id: Id<Block>, transactions: &Vec<Transaction>) {
        println!();
        for tx in transactions {
            println!("+ BLOCK: {} => TX: {}", block_id.get(), tx.get_id().get());
            for (input_index, input) in tx.get_inputs().iter().enumerate() {
                println!("\t+Input: {}", input_index);
                println!("\t\t+From: {:?}", input.get_outpoint());
            }
            for (output_index, output) in tx.get_outputs().iter().enumerate() {
                let spent_status = self.get_spent_status(&tx.get_id(), output_index as u32);
                println!("\t+Output: {}", output_index);
                println!("\t\t+Value: {}", output.get_value().into_atoms());
                match spent_status {
                    Some(OutputSpentState::Unspent) => println!("\t\t+Spend: Unspent"),
                    Some(OutputSpentState::SpentBy(spender)) => {
                        println!("\t\t+Spend: {:?}", spender)
                    }
                    None => println!("\t\t+Spend: Not in mainchain"),
                }
            }
        }
    }

    pub fn create_chain(&mut self, parent_block_id: &Id<Block>, count_blocks: usize) {
        let mut block = self
            .consensus
            .blockchain_storage
            .get_block(parent_block_id.clone())
            .ok()
            .flatten()
            .unwrap();

        for _ in 0..count_blocks {
            block = produce_test_block(&self.consensus.chain_config.clone(), &block, false);
            self.consensus
                .process_block(block.clone(), BlockSource::Local)
                .expect("Err block processing");
            self.blocks.push(block.clone());
        }
    }

    pub fn add_special_block(&mut self, block: Block) -> Result<Option<BlockIndex>, BlockError> {
        let result = self.consensus.process_block(block.clone(), BlockSource::Local);
        if result.is_ok() {
            self.blocks.push(block);
        }
        result
    }

    pub fn get_spent_status(
        &self,
        tx_id: &Id<Transaction>,
        output_index: u32,
    ) -> Option<OutputSpentState> {
        let tx_index = self
            .consensus
            .blockchain_storage
            .get_mainchain_tx_index(&OutPointSourceId::from(tx_id.clone()))
            .unwrap()?;
        tx_index.get_spent_state(output_index).ok()
    }

    fn check_spend_status(&self, tx: &Transaction, spend_status: &TestSpentStatus) {
        for (output_index, _) in tx.get_outputs().iter().enumerate() {
            let is_spend_status_correct = if spend_status == &TestSpentStatus::Spent {
                self.get_spent_status(&tx.get_id(), output_index as u32)
                    != Some(OutputSpentState::Unspent)
            } else {
                self.get_spent_status(&tx.get_id(), output_index as u32)
                    == Some(OutputSpentState::Unspent)
            };

            assert!(is_spend_status_correct);
        }
    }

    fn check_block_at_height(
        &self,
        block_height: BlockHeight,
        expected_block_id: &Option<Id<Block>>,
    ) {
        if expected_block_id.is_some() {
            let real_next_block_id =
                self.consensus.blockchain_storage.get_block_id_by_height(&block_height).unwrap();
            assert_eq!(&real_next_block_id, expected_block_id);
        }
    }

    pub fn test_block(
        &self,
        block_id: &Id<Block>,
        prev_block_id: &Option<Id<Block>>,
        next_block_id: &Option<Id<Block>>,
        height: u64,
        spend_status: TestSpentStatus,
    ) {
        if spend_status != TestSpentStatus::NotInMainchain {
            match self.blocks.iter().find(|x| &x.get_id() == block_id) {
                Some(block) => {
                    for tx in block.transactions() {
                        self.check_spend_status(tx, &spend_status);
                    }
                }
                None => {
                    panic!("block not found")
                }
            }
        }

        let block_index = self.get_block_index(block_id);
        assert_eq!(block_index.get_prev_block_id(), prev_block_id);
        assert_eq!(block_index.get_block_height(), BlockHeight::new(height));
        self.check_block_at_height(block_index.get_block_height().next_height(), next_block_id);
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> bool {
        let block_index =
            self.consensus.blockchain_storage.get_block_index(block_id).unwrap().unwrap();
        let height = block_index.get_block_height();
        let id_at_height =
            self.consensus.blockchain_storage.get_block_id_by_height(&height).unwrap();
        match id_at_height {
            Some(id) => id == *block_index.get_block_id(),
            None => false,
        }
    }
}

#[test]
fn test_very_long_reorgs() {
    common::concurrency::model(|| {
        let mut btf = BlockTestFrameWork::new();
        println!("genesis id: {:?}", btf.genesis().get_id());
        // # Fork like this:
        // #
        // # +-- 0x6e45…e8e8 (H:0,P:0) = genesis
        // #        +-- 0xe090…995e (H:1,M,P:1)
        // #                +-- 0x3562…2fb3 (H:2,M,P:2)
        // #                +-- 0xdf27…0fa5 (H:2,P:3)
        // #
        // # Nothing should happen at this point. We saw b2 first so it takes priority.
        println!("\nDon't reorg to a chain of the same length");
        btf.create_chain(&btf.genesis().get_id(), 2);
        btf.create_chain(&btf.blocks[1].get_id(), 1);
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

        // genesis
        btf.test_block(
            &btf.blocks[0].get_id(),
            &None,
            &Some(btf.blocks[1].get_id()),
            0,
            TestSpentStatus::Spent,
        );
        // b1
        btf.test_block(
            &btf.blocks[1].get_id(),
            &Some(btf.genesis().get_id()),
            &Some(btf.blocks[2].get_id()),
            1,
            TestSpentStatus::Spent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[1].get_id()));
        // b2
        btf.test_block(
            &btf.blocks[2].get_id(),
            &Some(btf.blocks[1].get_id()),
            &None,
            2,
            TestSpentStatus::Unspent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[2].get_id()));
        // b3
        btf.test_block(
            &btf.blocks[3].get_id(),
            &Some(btf.blocks[1].get_id()),
            &None,
            2,
            TestSpentStatus::NotInMainchain,
        );
        assert!(!btf.is_block_in_main_chain(&btf.blocks[3].get_id()));
        btf.debug_print_tx(btf.blocks[3].get_id(), btf.blocks[3].transactions());

        // # Now we add another block to make the alternative chain longer.
        // #
        // +-- 0x6e45…e8e8 (H:0,P:0)
        //         +-- 0xe090…995e (H:1,M,P:1)
        //                 +-- 0x3562…2fb3 (H:2,P:2)
        //                 +-- 0xdf27…0fa5 (H:2,M,P:3)
        //                         +-- 0x67fd…6419 (H:3,M,P:4)
        println!("\nReorg to a longer chain");
        let block = match btf.blocks.last() {
            Some(last_block) => btf.random_block(last_block, None),
            None => panic!("Can't find block"),
        };
        assert!(btf.add_special_block(block).is_ok());
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);
        // b3
        btf.test_block(
            &btf.blocks[3].get_id(),
            &Some(btf.blocks[1].get_id()),
            &Some(btf.blocks[4].get_id()),
            2,
            TestSpentStatus::Spent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[3].get_id()));
        // b4
        btf.test_block(
            &btf.blocks[4].get_id(),
            &Some(btf.blocks[3].get_id()),
            &None,
            3,
            TestSpentStatus::Unspent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[4].get_id()));

        // # ... and back to the first chain.
        // +-- 0x6e45…e8e8 (H:0,P:0)
        //         +-- 0xe090…995e (H:1,M,P:1)
        //                 +-- 0x3562…2fb3 (H:2,M,P:2)
        //                         +-- 0xc92d…04c7 (H:3,M,P:5)
        //                                 +-- 0x9dbb…e52f (H:4,M,P:6)
        //                 +-- 0xdf27…0fa5 (H:2,P:3)
        //                         +-- 0x67fd…6419 (H:3,P:4))
        let block_id = btf.blocks[btf.blocks.len() - 3].get_id();
        btf.create_chain(&block_id, 2);
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

        // b3
        btf.test_block(
            &btf.blocks[3].get_id(),
            &Some(btf.blocks[1].get_id()),
            &None,
            2,
            TestSpentStatus::NotInMainchain,
        );
        assert!(!btf.is_block_in_main_chain(&btf.blocks[3].get_id()));
        // b4
        btf.test_block(
            &btf.blocks[4].get_id(),
            &Some(btf.blocks[3].get_id()),
            &None,
            3,
            TestSpentStatus::NotInMainchain,
        );
        assert!(!btf.is_block_in_main_chain(&btf.blocks[4].get_id()));
        // b5
        btf.test_block(
            &btf.blocks[5].get_id(),
            &Some(btf.blocks[2].get_id()),
            &Some(btf.blocks[6].get_id()),
            3,
            TestSpentStatus::Spent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[5].get_id()));
        // b6
        btf.test_block(
            &btf.blocks[6].get_id(),
            &Some(btf.blocks[5].get_id()),
            &None,
            4,
            TestSpentStatus::Unspent,
        );
        assert!(btf.is_block_in_main_chain(&btf.blocks[6].get_id()));

        // # Try to create a fork that double-spends
        // +-- 0x6e45…e8e8 (H:0,P:0)
        //         +-- 0xe090…995e (H:1,M,P:1)
        //                 +-- 0x3562…2fb3 (H:2,M,P:2)
        //                         +-- 0xc92d…04c7 (H:3,M,P:5)
        //                                 +-- 0x9dbb…e52f (H:4,M,P:6)
        //                 +-- 0xdf27…0fa5 (H:2,P:3)
        //                         +-- 0x67fd…6419 (H:3,P:4)
        println!("\nReject a chain with a double spend, even if it is longer");
        let block_id = btf.blocks[6].get_id();
        let double_spend_block = btf.random_block(
            btf.blocks.last().unwrap(),
            Some(&[TestBlockParams::SpendFrom(block_id)]),
        );
        assert!(btf.add_special_block(double_spend_block).is_err());
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

        // # Try to create a block that has too much fee
        // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        // #                                                    \-> b9 (4)
        // #                      \-> b3 (1) -> b4 (2)
        println!("\nReject a block where the miner creates too much reward");
        //TODO: We have not decided yet how's done it correctly. We'll return here later.

        // # Create a fork that ends in a block with too much fee (the one that causes the reorg)
        // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        // #                                          \-> b10 (3) -> b11 (4)
        // #                      \-> b3 (1) -> b4 (2)
        println!("Reject a chain where the miner creates too much coinbase reward, even if the chain is longer");
        //TODO: We have not decided yet how's done it correctly. We'll return here later.

        // # Attempt to spend a transaction created on a different fork
        // +-- 0x6e45…e8e8 (H:0,P:0)
        //         +-- 0xe090…995e (H:1,M,P:1)
        //                 +-- 0x3562…2fb3 (H:2,M,P:2)
        //                         +-- 0xc92d…04c7 (H:3,M,P:5)
        //                                 +-- 0x9dbb…e52f (H:4,P:6)
        //                                 +-- 0x273a…bcae (H:4,M,P:7)
        //                                         +-- 0xb9d1…cf72 (H:5,M,P:8)
        //                                                 +-- 0xa243…517b (H:6,M,P:9)
        //                                                         +-- 0x4273…c93c (H:7,M,P:10)
        //                                                              <= Try to create a new block after this that spend 0x4273…c93c and 0x67fd…6419 in fork
        //                 +-- 0xdf27…0fa5 (H:2,P:3)
        //                         +-- 0x67fd…6419 (H:3,P:4)
        println!("Reject a block with a spend from a re-org'ed out tx");
        btf.create_chain(&btf.blocks[5].get_id(), 4);
        let block_id = btf.blocks[4].get_id();
        let double_spend_block = btf.random_block(
            &btf.blocks[10],
            Some(&[TestBlockParams::SpendFrom(block_id)]),
        );
        assert!(btf.add_special_block(double_spend_block).is_err());
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

        // # Check spending of a transaction in a block which failed to connect
        // #
        // # b6  (3)
        // # b12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        // #                                                                                     \-> b37 (11)
        // #                                                                                     \-> b38 (11/37)
        // #

        btf.create_chain(&btf.blocks[10].get_id(), 1);
        // # save 37's spendable output, but then double-spend out11 to invalidate the block
        let double_spend_block = btf.random_block(
            &btf.blocks[10],
            Some(&[TestBlockParams::SpendFrom(btf.blocks[11].get_id())]),
        );
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);
        btf.debug_print_tx(
            double_spend_block.get_id(),
            double_spend_block.transactions(),
        );
        assert!(btf.add_special_block(double_spend_block).is_ok());
        btf.debug_print_chains(vec![btf.genesis().get_id()], 0);
        btf.debug_print_tx(btf.blocks[12].get_id(), btf.blocks[12].transactions());
    });
}

#[test]
fn test_empty_consensus() {
    common::concurrency::model(|| {
        // No genesis
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let consensus = Consensus::new_no_genesis(config, storage).unwrap();
        assert!(consensus.get_best_block_id().unwrap().is_none());
        assert!(consensus
            .blockchain_storage
            .get_block(consensus.chain_config.genesis_block().get_id())
            .unwrap()
            .is_none());
        // Let's add genesis
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let consensus = Consensus::new(config, storage).unwrap();
        assert!(consensus.get_best_block_id().unwrap().is_some());
        assert!(
            consensus.get_best_block_id().unwrap().unwrap()
                == consensus.chain_config.genesis_block().get_id()
        );
        assert!(consensus
            .blockchain_storage
            .get_block(consensus.chain_config.genesis_block().get_id())
            .unwrap()
            .is_some());
        assert!(
            consensus
                .blockchain_storage
                .get_block(consensus.chain_config.genesis_block().get_id())
                .unwrap()
                .unwrap()
                .get_id()
                == consensus.chain_config.genesis_block().get_id()
        );
    });
}

#[test]
#[allow(clippy::eq_op)]
fn test_spend_inputs_simple() {
    common::concurrency::model(|| {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage).unwrap();

        // Create a new block
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            false,
        );

        // Check that all tx not in the main chain
        for tx in block.transactions() {
            assert!(
                consensus
                    .blockchain_storage
                    .get_mainchain_tx_index(&OutPointSourceId::from(tx.get_id()))
                    .expect(ERR_STORAGE_FAIL)
                    == None
            );
        }

        // Process the second block
        let new_id = Some(block.get_id());
        assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            new_id
        );

        // Check that tx inputs in the main chain and not spend
        for tx in block.transactions() {
            let tx_index = consensus
                .blockchain_storage
                .get_mainchain_tx_index(&OutPointSourceId::from(tx.get_id()))
                .expect("Not found mainchain tx index")
                .expect(ERR_STORAGE_FAIL);

            for input in tx.get_inputs() {
                if tx_index
                    .get_spent_state(input.get_outpoint().get_output_index())
                    .expect("Unable to get spent state")
                    != OutputSpentState::Unspent
                {
                    panic!("Tx input can't be spent");
                }
            }
        }
    });
}
