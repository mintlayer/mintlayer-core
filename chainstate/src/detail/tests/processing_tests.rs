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

use std::{sync::atomic::Ordering, time::Duration};

use crate::{
    detail::{
        median_time::calculate_median_time_past,
        pow::error::ConsensusPoWError,
        tests::{test_framework::BlockTestFramework, *},
    },
    make_chainstate, ChainstateConfig,
};
use chainstate_storage::{BlockchainStorageRead, Store};
use common::{
    chain::{
        block::consensus_data::PoWData,
        config::{create_unit_test_config, Builder as ConfigBuilder},
        ConsensusUpgrade, NetUpgrades, OutputPurpose, OutputSpentState, UpgradeVersion,
    },
    primitives::Compact,
    Uint256,
};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{self, Rng};

#[test]
fn process_genesis_block() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let genesis_id: Id<GenBlock> = chain_config.genesis_block_id();
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new_no_genesis(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        );
        chainstate.process_genesis().unwrap();
        let chainstate = chainstate.make_db_tx_ro();

        // Check the genesis block is properly set up
        assert_eq!(chainstate.get_best_block_id(), Ok(genesis_id));
        let genesis_index = chainstate.get_gen_block_index(&genesis_id).unwrap().unwrap();
        assert_eq!(genesis_index.block_height(), BlockHeight::from(0));
        assert_eq!(genesis_index.block_id(), genesis_id.clone());
        let block_at_0 = chainstate.get_block_id_by_height(&BlockHeight::from(0)).unwrap().unwrap();
        assert_eq!(block_at_0, genesis_id);
        assert_eq!(genesis_index.chain_trust(), &Uint256::from_u64(0));
    });
}

#[test]
fn orphans_chains() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        assert_eq!(
            chainstate.get_best_block_id().unwrap(),
            chainstate.chain_config.genesis_block_id()
        );

        // Process the orphan block
        let genesis_block = chainstate.chain_config.genesis_block().clone();
        let missing_block = produce_test_block(TestBlockInfo::from_genesis(&genesis_block));

        // Create and process orphan blocks.
        const MAX_ORPHANS_COUNT_IN_TEST: usize = 100;
        let mut current_block = missing_block.clone();
        for orphan_count in 1..MAX_ORPHANS_COUNT_IN_TEST {
            current_block = produce_test_block(TestBlockInfo::from_block(&current_block));
            assert_eq!(
                chainstate.process_block(current_block.clone(), BlockSource::Local).unwrap_err(),
                BlockError::OrphanCheckFailed(OrphanCheckError::LocalOrphan)
            );
            // The genesis block is still the best one, because we are processing orphan blocks.
            assert_eq!(
                chainstate.get_best_block_id().unwrap(),
                chainstate.chain_config.genesis_block_id()
            );
            assert!(chainstate.orphan_blocks.is_already_an_orphan(&current_block.get_id()));
            assert_eq!(chainstate.orphan_blocks.len(), orphan_count);
        }

        // now we submit the missing block (at height 1), and we expect all blocks to be processed
        let last_block_index =
            chainstate.process_block(missing_block, BlockSource::Local).unwrap().unwrap();
        let current_best = chainstate
            .get_best_block_id()
            .unwrap()
            .classify(&chainstate.chain_config)
            .chain_block_id()
            .unwrap();
        assert_eq!(
            last_block_index.block_height(),
            (MAX_ORPHANS_COUNT_IN_TEST as u64).into()
        );
        assert_eq!(
            chainstate.get_block_index(&current_best).unwrap().unwrap().block_height(),
            (MAX_ORPHANS_COUNT_IN_TEST as u64).into()
        );
        // There should be no more orphan blocks left.
        assert_eq!(chainstate.orphan_blocks.len(), 0);
    });
}

#[test]
#[should_panic(expected = "Best block ID not initialized")]
fn empty_chainstate_no_genesis() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let chainstate = Chainstate::new_no_genesis(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        );

        // This panics
        let _ = chainstate.get_best_block_id();
    })
}

#[test]
fn spend_inputs_simple() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        // Create a new block
        let block = produce_test_block(TestBlockInfo::from_genesis(
            chainstate.chain_config.genesis_block(),
        ));

        // Check that all tx not in the main chain
        for tx in block.transactions() {
            assert_eq!(
                chainstate
                    .chainstate_storage
                    .get_mainchain_tx_index(&OutPointSourceId::from(tx.get_id()))
                    .expect(ERR_STORAGE_FAIL),
                None
            );
        }

        // Process the second block
        assert!(chainstate.process_block(block.clone(), BlockSource::Local).is_ok());
        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(<Id<GenBlock>>::from(block.get_id()))
        );

        // Check that the transactions are in the main-chain and their inputs are not spent.
        for tx in block.transactions() {
            let tx_index = chainstate
                .chainstate_storage
                .get_mainchain_tx_index(&OutPointSourceId::from(tx.get_id()))
                .unwrap()
                .expect(ERR_STORAGE_FAIL);

            for input in tx.inputs() {
                assert_eq!(
                    tx_index.get_spent_state(input.outpoint().output_index()).unwrap(),
                    OutputSpentState::Unspent
                );
            }
        }
    });
}

// Produce and process some blocks.
#[test]
fn straight_chain() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let genesis_index = chainstate
            .make_db_tx_ro()
            .get_gen_block_index(&chainstate.chain_config.genesis_block_id())
            .unwrap()
            .unwrap();

        assert_eq!(
            chainstate
                .chainstate_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(chainstate.chain_config.genesis_block_id())
        );
        assert_eq!(genesis_index.chain_trust(), &Uint256::from_u64(0));
        assert_eq!(genesis_index.block_height(), BlockHeight::new(0));

        let chain_config_clone = chainstate.chain_config.clone();
        let mut block_index = GenBlockIndex::Genesis(&chain_config_clone);
        let mut prev_block = TestBlockInfo::from_genesis(chainstate.chain_config.genesis_block());

        for _ in 0..random::make_pseudo_rng().gen_range(100..200) {
            assert_eq!(
                chainstate.chainstate_storage.get_best_block_id().unwrap().unwrap(),
                prev_block.id
            );
            let prev_block_id = block_index.block_id();
            let best_block_id = chainstate
                .chainstate_storage
                .get_best_block_id()
                .ok()
                .flatten()
                .expect("Unable to get best block ID");
            assert_eq!(best_block_id, block_index.block_id());
            let new_block = produce_test_block(prev_block);
            let new_block_index = chainstate
                .process_block(new_block.clone(), BlockSource::Peer)
                .ok()
                .flatten()
                .expect("Unable to process block");

            assert_eq!(new_block_index.prev_block_id(), &prev_block_id);
            assert!(new_block_index.chain_trust() > block_index.chain_trust());
            assert_eq!(
                new_block_index.block_height(),
                block_index.block_height().next_height()
            );

            block_index = GenBlockIndex::Block(new_block_index);
            prev_block = TestBlockInfo::from_block(&new_block);
        }
    });
}

#[test]
fn get_ancestor_invalid_height() {
    let mut btf = BlockTestFramework::new();
    let height = 1;
    btf.create_chain(&btf.genesis().get_id().into(), height).unwrap();
    let last_block_index = btf.block_indexes.last().expect("last block in first chain").clone();

    let invalid_height = height + 1;
    assert_eq!(
        PropertyQueryError::InvalidAncestorHeight {
            ancestor_height: u64::try_from(invalid_height).unwrap().into(),
            block_height: u64::try_from(height).unwrap().into(),
        },
        btf.chainstate
            .make_db_tx()
            .get_ancestor(
                &GenBlockIndex::Block(last_block_index),
                u64::try_from(invalid_height).unwrap().into()
            )
            .unwrap_err()
    );
}

#[test]
fn get_ancestor() {
    let mut btf = BlockTestFramework::new();

    // We will create two chains that split at height 100
    const SPLIT_HEIGHT: usize = 100;
    const ANCESTOR_HEIGHT: usize = 50;
    const FIRST_CHAIN_HEIGHT: usize = 500;
    const SECOND_CHAIN_LENGTH: usize = 300;
    btf.create_chain(&btf.genesis().get_id().into(), SPLIT_HEIGHT)
        .expect("Chain creation to succeed");

    let ancestor = GenBlockIndex::Block(btf.index_at(ANCESTOR_HEIGHT).clone());
    assert_eq!(
        ancestor.block_height(),
        BlockHeight::from(ANCESTOR_HEIGHT as u64)
    );

    let split = GenBlockIndex::Block(btf.index_at(SPLIT_HEIGHT).clone());
    assert_eq!(split.block_height(), BlockHeight::from(SPLIT_HEIGHT as u64));

    // we aggressively test the simple ancestor calculation for all previous heights up to genesis
    for i in 1..=split.block_height().into() {
        assert_eq!(
            <Id<GenBlock>>::from(*btf.index_at(i as usize).block_id()),
            btf.chainstate
                .make_db_tx()
                .get_ancestor(&split, i.into())
                .unwrap_or_else(|_| panic!("Ancestor of height {} not reached", i))
                .block_id()
        );
    }

    // Create the first chain and test get_ancestor for this chain's  last block
    btf.create_chain(&split.block_id(), FIRST_CHAIN_HEIGHT - SPLIT_HEIGHT)
        .expect("second chain");
    let last_block_in_first_chain =
        GenBlockIndex::Block(btf.block_indexes.last().expect("last block in first chain").clone());

    const ANCESTOR_IN_FIRST_CHAIN_HEIGHT: usize = 400;
    let ancestor_in_first_chain =
        GenBlockIndex::Block(btf.index_at(ANCESTOR_IN_FIRST_CHAIN_HEIGHT).clone());
    assert_eq!(
        ancestor_in_first_chain.block_height(),
        BlockHeight::from(ANCESTOR_IN_FIRST_CHAIN_HEIGHT as u64),
    );

    assert_eq!(
        last_block_in_first_chain.block_id(),
        btf.chainstate
            .make_db_tx()
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(FIRST_CHAIN_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );

    assert_eq!(
        ancestor.block_id(),
        btf.chainstate
            .make_db_tx()
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(ANCESTOR_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );

    assert_eq!(
        ancestor_in_first_chain.block_id(),
        btf.chainstate
            .make_db_tx()
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(ANCESTOR_IN_FIRST_CHAIN_HEIGHT).unwrap().into()
            )
            .expect("ancestor in first chain")
            .block_id()
    );

    // Create a second chain and test get_ancestor for this chain's last block
    btf.create_chain(&split.block_id(), SECOND_CHAIN_LENGTH - SPLIT_HEIGHT)
        .expect("second chain");
    let last_block_in_second_chain =
        GenBlockIndex::Block(btf.block_indexes.last().expect("last block in first chain").clone());
    assert_eq!(
        ancestor.block_id(),
        btf.chainstate
            .make_db_tx()
            .get_ancestor(
                &last_block_in_second_chain,
                u64::try_from(ANCESTOR_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );
}

// Create two chains that split at height 100.
#[test]
fn last_common_ancestor() {
    let mut btf = BlockTestFramework::new();

    const SPLIT_HEIGHT: usize = 100;
    const FIRST_CHAIN_HEIGHT: usize = 500;
    const SECOND_CHAIN_LENGTH: usize = 300;

    btf.create_chain(&btf.genesis().get_id().into(), SPLIT_HEIGHT)
        .expect("Chain creation to succeed");
    let config_clone = btf.chainstate.chain_config.clone();
    let genesis = GenBlockIndex::Genesis(&config_clone);
    let split = GenBlockIndex::Block(btf.index_at(SPLIT_HEIGHT).clone());

    // First branch of fork
    btf.create_chain(&split.block_id(), FIRST_CHAIN_HEIGHT - SPLIT_HEIGHT)
        .expect("Chain creation to succeed");
    let last_block_in_first_chain =
        GenBlockIndex::Block(btf.block_indexes.last().expect("last block in first chain").clone());

    // Second branch of fork
    btf.create_chain(&split.block_id(), SECOND_CHAIN_LENGTH - SPLIT_HEIGHT)
        .expect("second chain");
    let last_block_in_second_chain =
        GenBlockIndex::Block(btf.block_indexes.last().expect("last block in first chain").clone());

    assert_eq!(
        btf.chainstate
            .make_db_tx()
            .last_common_ancestor(&last_block_in_first_chain, &last_block_in_second_chain)
            .unwrap()
            .block_id(),
        split.block_id()
    );

    assert_eq!(
        btf.chainstate
            .make_db_tx()
            .last_common_ancestor(&last_block_in_second_chain, &last_block_in_first_chain)
            .unwrap()
            .block_id(),
        split.block_id()
    );

    assert_eq!(
        btf.chainstate
            .make_db_tx()
            .last_common_ancestor(&last_block_in_first_chain, &last_block_in_first_chain)
            .unwrap()
            .block_id(),
        last_block_in_first_chain.block_id()
    );

    assert_eq!(
        btf.chainstate
            .make_db_tx()
            .last_common_ancestor(&genesis, &split)
            .unwrap()
            .block_id(),
        genesis.block_id()
    );
}

#[test]
fn consensus_type() {
    let ignore_consensus = BlockHeight::new(0);
    let pow = BlockHeight::new(5);
    let ignore_again = BlockHeight::new(10);
    let pow_again = BlockHeight::new(15);

    let min_difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);

    let upgrades = vec![
        (
            ignore_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            }),
        ),
        (
            ignore_again,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow_again,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            }),
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid netupgrades");

    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because config::Builder by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsenssuData::None, which agreess with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();
    let chainstate_config = ChainstateConfig::new();
    let chainstate = chainstate_with_config(chain_config, chainstate_config);

    let mut btf = BlockTestFramework::with_chainstate(chainstate);

    // The next block will have height 1. At this height, we are still under IgnoreConsensus, so
    // processing a block with PoWData will fail
    let pow_block = produce_test_block_with_consensus_data(
        TestBlockInfo::from_genesis(btf.genesis()),
        ConsensusData::PoW(PoWData::new(Compact(0), 0, vec![])),
    );

    assert!(matches!(
        btf.add_special_block(pow_block).unwrap_err(),
        BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
            ConsensusVerificationError::ConsensusTypeMismatch(..)
        ))
    ));

    // Create 4 more blocks with Consensus Nonw
    btf.create_chain(&btf.genesis().get_id().into(), 4).expect("chain creation");

    // The next block will be at height 5, so it is expected to be a PoW block. Let's crate a block
    // with ConsensusData::None and see that adding it fails
    let block_without_consensus_data = produce_test_block_with_consensus_data(
        TestBlockInfo::from_block(&btf.get_block(*btf.index_at(4).block_id()).unwrap().unwrap()),
        ConsensusData::None,
    );

    assert!(matches!(
        btf.add_special_block(block_without_consensus_data).unwrap_err(),
        BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
            ConsensusVerificationError::ConsensusTypeMismatch(..)
        ))
    ));

    // Mine blocks 5-9 with minimal difficulty, as expected by net upgrades
    for i in 5..10 {
        let prev_block = btf.get_block(*btf.index_at(i - 1).block_id()).unwrap().unwrap();
        let mut mined_block = btf.random_block(TestBlockInfo::from_block(&prev_block), None);
        let bits = min_difficulty.into();
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        assert!(crate::detail::pow::work::mine(
            &mut mined_block,
            u128::MAX,
            bits,
            vec![TxOutput::new(
                Amount::from_atoms(10),
                OutputPurpose::Transfer(Destination::PublicKey(pub_key))
            )]
        )
        .expect("Unexpected conversion error"));
        btf.add_special_block(mined_block).unwrap();
    }

    // Block 10 should ignore consensus according to net upgrades. The following Pow block should
    // fail.
    let prev_block = btf.get_block(*btf.index_at(9).block_id()).unwrap().unwrap();
    let mut mined_block = btf.random_block(TestBlockInfo::from_block(&prev_block), None);
    let bits = min_difficulty.into();
    assert!(
        crate::detail::pow::work::mine(&mut mined_block, u128::MAX, bits, vec![])
            .expect("Unexpected conversion error")
    );

    assert!(matches!(
        btf.add_special_block(mined_block).unwrap_err(),
        BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
            ConsensusVerificationError::ConsensusTypeMismatch(..)
        ))
    ));

    // Create blocks 10-14 without consensus data as required by net_upgrades
    btf.create_chain(&prev_block.get_id().into(), 5).expect("chain creation");

    // At height 15 we are again proof of work, ignoring consensus should fail
    let prev_block = btf.get_block(*btf.index_at(14).block_id()).unwrap().unwrap();
    let block_without_consensus_data = produce_test_block_with_consensus_data(
        TestBlockInfo::from_block(&prev_block),
        ConsensusData::None,
    );

    assert!(matches!(
        btf.add_special_block(block_without_consensus_data).unwrap_err(),
        BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
            ConsensusVerificationError::ConsensusTypeMismatch(..)
        ))
    ));

    // Mining should work
    for i in 15..20 {
        let prev_block = btf.get_block(*btf.index_at(i - 1).block_id()).unwrap().unwrap();
        let mut mined_block = btf.random_block(TestBlockInfo::from_block(&prev_block), None);
        let bits = min_difficulty.into();
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        assert!(crate::detail::pow::work::mine(
            &mut mined_block,
            u128::MAX,
            bits,
            vec![TxOutput::new(
                Amount::from_atoms(10),
                OutputPurpose::Transfer(Destination::PublicKey(pub_key))
            )]
        )
        .expect("Unexpected conversion error"));
        btf.add_special_block(mined_block).unwrap();
    }
}

#[test]
fn pow() {
    let ignore_consensus = BlockHeight::new(0);
    let pow_consensus = BlockHeight::new(1);
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF]);

    let upgrades = vec![
        (
            ignore_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: difficulty.into(),
            }),
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid netupgrades");

    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because TestChainConfig by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsenssuData::None, which agreess with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();
    let chainstate_config = ChainstateConfig::new();
    let chainstate = chainstate_with_config(chain_config, chainstate_config);

    let mut btf = BlockTestFramework::with_chainstate(chainstate);

    // Let's create a block with random (invalid) PoW data and see that it fails the consensus
    // checks
    let prev_block = TestBlockInfo::from_genesis(btf.genesis());
    let mut random_invalid_block = btf.random_block(prev_block, None);
    make_invalid_pow_block(&mut random_invalid_block, u128::MAX, difficulty.into())
        .expect("generate invalid block");
    let res = btf.add_special_block(random_invalid_block.clone());
    assert!(matches!(
        res,
        Err(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoWError(
                ConsensusPoWError::InvalidPoW(_)
            ))
        ))
    ));

    // Now let's actually mine the block, i.e. find valid PoW and see that consensus checks pass
    let mut valid_block = random_invalid_block;
    let bits = difficulty.into();
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    assert!(crate::detail::pow::work::mine(
        &mut valid_block,
        u128::MAX,
        bits,
        vec![TxOutput::new(
            Amount::from_atoms(10),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key))
        )]
    )
    .expect("Unexpected conversion error"));
    btf.add_special_block(valid_block.clone()).unwrap();
}

#[test]
fn blocks_from_the_future() {
    common::concurrency::model(|| {
        // In this test, processing a few correct blocks in a single chain
        let config = Arc::new(create_unit_test_config());

        // current time is genesis time
        let current_time = Arc::new(std::sync::atomic::AtomicU64::new(
            config.genesis_block().timestamp().as_int_seconds() as u64,
        ));
        let chainstate_current_time = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(chainstate_current_time.load(Ordering::SeqCst))
        }));

        let storage = Store::new_empty().unwrap();
        let mut chainstate =
            Chainstate::new(config, ChainstateConfig::new(), storage, None, time_getter).unwrap();

        {
            // ensure no blocks are in chain, so that median time can be the genesis time
            let current_height: u64 =
                chainstate.get_best_block_index().unwrap().unwrap().block_height().into();
            assert_eq!(current_height, 0);
        }

        {
            // constrain the test to protect this test becoming legacy by changing the definition of median time for genesis
            let chainstate_ref = chainstate.make_db_tx_ro();
            assert_eq!(
                calculate_median_time_past(
                    &chainstate_ref,
                    &chainstate.chain_config.genesis_block_id()
                ),
                chainstate.chain_config.genesis_block().timestamp()
            );
        }

        {
            // submit a block on the threshold of being rejected for being from the future
            let max_future_offset =
                chainstate.chain_config.max_future_block_time_offset().as_secs();

            let good_block = Block::new(
                vec![],
                chainstate.chain_config.genesis_block_id(),
                BlockTimestamp::from_int_seconds(
                    current_time.load(Ordering::SeqCst) + max_future_offset,
                ),
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            chainstate.process_block(good_block, BlockSource::Local).unwrap().unwrap();
        }

        {
            // submit a block a second after the allowed threshold in the future
            let max_future_offset =
                chainstate.chain_config.max_future_block_time_offset().as_secs();

            let bad_block_in_future = Block::new(
                vec![],
                chainstate.chain_config.genesis_block_id(),
                BlockTimestamp::from_int_seconds(
                    current_time.load(Ordering::SeqCst) + max_future_offset + 1,
                ),
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            assert_eq!(
                chainstate.process_block(bad_block_in_future, BlockSource::Local).unwrap_err(),
                BlockError::CheckBlockFailed(CheckBlockError::BlockFromTheFuture)
            );
        }

        {
            // submit a block one second before genesis in time
            let bad_block_from_past = Block::new(
                vec![],
                chainstate.chain_config.genesis_block_id(),
                BlockTimestamp::from_int_seconds(current_time.load(Ordering::SeqCst) - 1),
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            assert_eq!(
                chainstate.process_block(bad_block_from_past, BlockSource::Local).unwrap_err(),
                BlockError::CheckBlockFailed(CheckBlockError::BlockTimeOrderInvalid)
            );
        }
    });
}

#[test]
fn mainnet_initialization() {
    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let chainstate_config = ChainstateConfig::new();
    let storage = Store::new_empty().unwrap();
    make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        None,
        Default::default(),
    )
    .unwrap();
}

fn make_invalid_pow_block(
    block: &mut Block,
    max_nonce: u128,
    bits: Compact,
) -> Result<bool, ConsensusPoWError> {
    let mut data = PoWData::new(bits, 0, vec![]);
    for nonce in 0..max_nonce {
        data.update_nonce(nonce);
        block.update_consensus_data(ConsensusData::PoW(data.clone()));

        if !crate::detail::pow::work::check_proof_of_work(block.get_id().get(), bits)? {
            return Ok(true);
        }
    }

    Ok(false)
}
