// Copyright (c) 2021 RBB S.r.l
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

use crate::detail::tests::*;
use blockchain_storage::Store;
use common::chain::{config::create_mainnet, OutputSpentState};

#[test]
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
fn test_spend_inputs_simple() {
    common::concurrency::model(|| {
        let mut consensus = setup_consensus();

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

#[test]
fn test_straight_chain() {
    common::concurrency::model(|| {
        const COUNT_BLOCKS: usize = 255;
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
        for _ in 0..COUNT_BLOCKS {
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
