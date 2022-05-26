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

use crate::detail::tests::*;
use common::chain::block::{Block, ConsensusData};
use common::chain::{Transaction, TxInput, TxOutput};
use common::primitives::{time, Amount, Id};

#[test]
fn spend_tx_in_the_same_block() {
    common::concurrency::model(|| {
        // Check is it correctly spend when the second tx pointing on the first tx
        //
        // Genesis -> b1
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
        {
            let mut consensus = setup_consensus();
            // Create base tx
            let receiver = anyonecanspend_address();

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
                empty_witness(),
            );
            let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

            let first_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            let first_tx_id = first_tx.get_id();

            let input = TxInput::new(first_tx_id.into(), 0, InputWitness::NoSignature(None));
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
        // The case is invalid. Transactions must in order.
        //
        // Genesis -> b1
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
        {
            let mut consensus = setup_consensus();
            // Create base tx
            let receiver = anyonecanspend_address();

            let prev_block_tx_id =
                consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

            let input = TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                empty_witness(),
            );
            let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

            let first_tx =
                Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
            let first_tx_id = first_tx.get_id();

            let input = TxInput::new(first_tx_id.into(), 0, InputWitness::NoSignature(None));
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
        //
        // Genesis -> b1
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

        let mut consensus = setup_consensus();
        let receiver = anyonecanspend_address();

        let prev_block_tx_id =
            consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

        // Create first tx
        let first_tx = Transaction::new(
            0,
            vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id),
                0,
                empty_witness(),
            )],
            vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone())],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);
        let first_tx_id = first_tx.get_id();

        // Create second tx
        let second_tx = Transaction::new(
            0,
            vec![TxInput::new(
                first_tx_id.clone().into(),
                0,
                InputWitness::NoSignature(None),
            )],
            vec![TxOutput::new(Amount::from_atoms(987654321), receiver.clone())],
            0,
        )
        .expect(ERR_CREATE_TX_FAIL);

        // Create third tx
        let third_tx = Transaction::new(
            123456789,
            vec![TxInput::new(first_tx_id.into(), 0, InputWitness::NoSignature(None))],
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
fn double_spend_tx_in_another_block() {
    common::concurrency::model(|| {
        // Different blocks in the same chain attempt to spend the same output
        //
        // Genesis -> b1 -> b2
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
        let receiver = anyonecanspend_address();

        let prev_block_tx_id =
            consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

        // Create first tx
        let first_tx = Transaction::new(
            0,
            vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block_tx_id.clone()),
                0,
                empty_witness(),
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
        consensus.process_block(first_block, BlockSource::Local).unwrap();
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
                empty_witness(),
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
