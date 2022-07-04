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
// Author(s): A. Sinitsyn

use crate::detail::{spend_cache::error::StateUpdateError, tests::*};
use chainstate_storage::BlockchainStorageRead;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        OutPointSourceId, Spender, Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount, Id},
};
use crypto::random::{self, Rng};

// Process a block where the second transaction uses the first one as input.
//
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
#[test]
fn spend_output_in_the_same_block() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let first_tx = tx_from_genesis(&chainstate);
        let second_tx = tx_from_tx(&first_tx);

        let block = Block::new(
            vec![first_tx, second_tx],
            Some(Id::new(chainstate.chain_config.genesis_block_id().get())),
            BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        let block_id = block.get_id();

        chainstate.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(block_id)
        );
    });
}

// The order of transactions is important, so in the following case block processing should result
// in an error.
//
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
#[test]
fn spend_output_in_the_same_block_invalid_order() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let first_tx = tx_from_genesis(&chainstate);
        let second_tx = tx_from_tx(&first_tx);

        let block = Block::new(
            vec![second_tx, first_tx],
            Some(Id::new(chainstate.chain_config.genesis_block_id().get())),
            BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        assert_eq!(
            chainstate.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::StateUpdateFailed(StateUpdateError::MissingOutputOrSpent)
        );
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND)
                .expect(ERR_STORAGE_FAIL),
            chainstate.chain_config.genesis_block_id()
        );
    });
}

// Try to use the transaction output twice in one block.
//
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
#[test]
fn double_spend_tx_in_the_same_block() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let first_tx = tx_from_genesis(&chainstate);
        let second_tx = tx_from_tx(&first_tx);
        let third_tx = tx_from_tx(&first_tx);

        let block = Block::new(
            vec![first_tx, second_tx, third_tx],
            Some(Id::new(chainstate.chain_config.genesis_block_id().get())),
            BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        let block_id = block.get_id();
        assert_eq!(
            chainstate.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::DuplicateInputInBlock(block_id)
            ))
        );
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_STORAGE_FAIL)
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            chainstate.chain_config.genesis_block_id()
        );
    });
}

// Try to use an output twice in different blocks.
//
// Genesis -> b1 -> b2.
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
#[test]
fn double_spend_tx_in_another_block() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let first_tx = tx_from_genesis(&chainstate);
        let first_block = Block::new(
            vec![first_tx.clone()],
            Some(Id::new(chainstate.chain_config.genesis_block_id().get())),
            BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        let first_block_id = first_block.get_id();
        chainstate.process_block(first_block, BlockSource::Local).unwrap();
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(first_block_id.clone())
        );

        let second_tx = tx_from_genesis(&chainstate);
        let second_block = Block::new(
            vec![second_tx],
            Some(first_block_id.clone()),
            BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);
        assert_eq!(
            chainstate.process_block(second_block, BlockSource::Local).unwrap_err(),
            BlockError::StateUpdateFailed(StateUpdateError::DoubleSpendAttempt(
                Spender::RegularInput(first_tx.get_id())
            ))
        );
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_STORAGE_FAIL)
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            first_block_id
        );
    });
}

// Creates a transaction with an input based on the first transaction from the genesis block.
fn tx_from_genesis(chainstate: &Chainstate) -> Transaction {
    let genesis_block_tx_id =
        chainstate.chain_config.genesis_block().transactions().get(0).unwrap().get_id();
    let input = TxInput::new(
        OutPointSourceId::Transaction(genesis_block_tx_id),
        0,
        empty_witness(),
    );
    let output = TxOutput::new(
        Amount::from_atoms(random::make_pseudo_rng().gen_range(100_000..200_000)),
        OutputPurpose::Transfer(anyonecanspend_address()),
    );
    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL)
}

// Creates a transaction with an input based on the specified transaction id.
fn tx_from_tx(tx: &Transaction) -> Transaction {
    let input = TxInput::new(tx.get_id().into(), 0, InputWitness::NoSignature(None));
    let output = TxOutput::new(
        Amount::from_atoms(random::make_pseudo_rng().gen_range(1000..2000)),
        OutputPurpose::Transfer(anyonecanspend_address()),
    );
    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL)
}
