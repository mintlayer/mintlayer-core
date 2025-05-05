// Copyright (c) 2023 RBB S.r.l
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

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use super::helpers::new_pub_key_destination;

use accounting::{DataDelta, DeltaAmountCollection, DeltaDataCollection};
use chainstate::BlockSource;
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TestStore, TransactionBuilder,
};
use common::{
    chain::{
        config::Builder as ConfigBuilder, output_value::OutputValue, stakelock::StakePoolData,
        Destination, OutPointSourceId, PoolId, SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Idable},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use pos_accounting::PoolData;
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use utxo::UtxosStorageRead;

fn create_pool_data(
    rng: &mut (impl Rng + CryptoRng),
    decommission_destination: Destination,
    pledged_amount: Amount,
) -> PoolData {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let margin_ratio = PerThousand::new_from_rng(rng);
    let cost_per_block = Amount::from_atoms(rng.gen_range(0..1000));
    PoolData::new(
        decommission_destination,
        pledged_amount,
        Amount::ZERO,
        vrf_pk,
        margin_ratio,
        cost_per_block,
    )
}

fn make_tx_with_stake_pool_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    amount_to_stake: Amount,
    amount_to_transfer: Amount,
) -> (SignedTransaction, PoolId, PoolData, UtxoOutPoint) {
    let outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
    make_tx_with_stake_pool(
        rng,
        UtxoOutPoint::new(outpoint_id, 0),
        amount_to_stake,
        amount_to_transfer,
    )
}

fn make_tx_with_stake_pool(
    rng: &mut (impl Rng + CryptoRng),
    input0_outpoint: UtxoOutPoint,
    amount_to_stake: Amount,
    amount_to_transfer: Amount,
) -> (SignedTransaction, PoolId, PoolData, UtxoOutPoint) {
    let destination = new_pub_key_destination(rng);
    let pool_id = PoolId::from_utxo(&input0_outpoint);
    let pool_data = create_pool_data(rng, destination, amount_to_stake);
    let stake_output = TxOutput::CreateStakePool(
        pool_id,
        Box::new(StakePoolData::new(
            amount_to_stake,
            anyonecanspend_address(),
            pool_data.vrf_public_key().clone(),
            pool_data.decommission_destination().clone(),
            pool_data.margin_ratio_per_thousand(),
            pool_data.cost_per_block(),
        )),
    );

    let transfer_output = TxOutput::Transfer(
        OutputValue::Coin(amount_to_transfer),
        anyonecanspend_address(),
    );

    let tx_builder =
        TransactionBuilder::new().add_input(input0_outpoint.into(), empty_witness(rng));

    // random order of transfer and stake outputs so that tests can use different outpoint 0 or 1
    // to make the next pool
    let (tx, transfer_output_idx) = if rng.gen::<bool>() {
        (
            tx_builder.add_output(transfer_output).add_output(stake_output).build(),
            0,
        )
    } else {
        (
            tx_builder.add_output(stake_output).add_output(transfer_output).build(),
            1,
        )
    };
    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(tx.transaction().get_id()),
        transfer_output_idx,
    );

    (tx, pool_id, pool_data, transfer_outpoint)
}

// Process a tx with a stake pool. Check that new pool balance and data are stored
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_pool_data_and_balance(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_storage(storage.clone()).build();
        let amount_to_stake = tf.chainstate.get_chain_config().min_stake_pool_pledge();

        let (tx, pool_id, pool_data, tx_utxo_outpoint) = make_tx_with_stake_pool_from_genesis(
            &mut rng,
            &mut tf,
            amount_to_stake,
            Amount::from_atoms(1),
        );

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        // check that result is stored
        let db_tx = storage.transaction_ro().unwrap();

        // utxo is stored
        db_tx.get_utxo(&tx_utxo_outpoint).expect("ok").expect("some");
        assert_eq!(
            db_tx.get_undo_data(block_id).expect("ok").expect("some").tx_undos().len(),
            1
        );

        let expected_tip_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([(pool_id, pool_data)]),
            pool_balances: BTreeMap::from([(pool_id, amount_to_stake)]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };

        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_tip().unwrap(),
            expected_tip_storage_data
        );

        assert!(storage
            .transaction_ro()
            .unwrap()
            .read_pos_accounting_data_sealed()
            .unwrap()
            .is_empty());
    });
}

// Create block1 from genesis and block2 from block1 using chain config
// that will put them in the same epoch.
// Every block creates a pool.
// Check that block1 and block2 belong to the same epochs and no epoch was sealed.
// Check that accounting info from both blocks got into tip and not into sealed storage.
// Check that deltas from both blocks is stored.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_storage_two_blocks_one_epoch_no_seal(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(NonZeroU64::new(3).unwrap())
            .sealed_epoch_distance_from_tip(2)
            .build();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(chain_config)
            .build();
        let amount_to_stake = tf.chainstate.get_chain_config().min_stake_pool_pledge();
        let expected_epoch_index = 0;

        let (tx1, pool_id1, pool_data1, tx_utxo_outpoint) = make_tx_with_stake_pool_from_genesis(
            &mut rng,
            &mut tf,
            amount_to_stake,
            (amount_to_stake * 3).unwrap(),
        );

        let (tx2, pool_id2, pool_data2, _) = make_tx_with_stake_pool(
            &mut rng,
            tx_utxo_outpoint,
            amount_to_stake,
            (amount_to_stake * 2).unwrap(),
        );

        let block1_index = tf
            .make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block1_index.block_height()),
            expected_epoch_index
        );
        let block2_index = tf
            .make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block2_index.block_height()),
            expected_epoch_index
        );

        // check that result is stored to tip
        let expected_tip_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([
                (pool_id1, pool_data1.clone()),
                (pool_id2, pool_data2.clone()),
            ]),
            pool_balances: BTreeMap::from([
                (pool_id1, amount_to_stake),
                (pool_id2, amount_to_stake),
            ]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };

        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_tip().unwrap(),
            expected_tip_storage_data
        );

        // check that result is not stored to sealed
        assert!(storage
            .transaction_ro()
            .unwrap()
            .read_pos_accounting_data_sealed()
            .unwrap()
            .is_empty());

        // check that delta for epoch is stored
        let expected_epoch_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [
                    (pool_id1, DataDelta::new(None, Some(pool_data1))),
                    (pool_id2, DataDelta::new(None, Some(pool_data2))),
                ]
                .into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [
                    (pool_id1, amount_to_stake.into_signed().unwrap()),
                    (pool_id2, amount_to_stake.into_signed().unwrap()),
                ]
                .into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch_delta = storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_delta(expected_epoch_index)
            .expect("ok")
            .expect("some");
        assert_eq!(epoch_delta, expected_epoch_delta);

        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(0)
            .unwrap()
            .is_none());
    });
}

// Config chain to seal an epoch every block.
// Create block1 from genesis and block2 from block1.
// Every block creates a stake pool.
// Check that block1 and block2 belong to different epochs, but no epoch was sealed.
// Check that accounting info from both blocks got into tip and but not into sealed storage.
// Check that deltas from both blocks is stored.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_storage_two_epochs_no_seal(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let chain_config =
            ConfigBuilder::test_chain().epoch_length(NonZeroU64::new(1).unwrap()).build();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(chain_config)
            .build();
        let amount_to_stake = tf.chainstate.get_chain_config().min_stake_pool_pledge();
        // genesis block takes epoch 0, so new blocks start from epoch 1
        let block1_epoch_index = 1;
        let block2_epoch_index = 2;

        let (tx1, pool_id1, pool_data1, tx_utxo_outpoint) = make_tx_with_stake_pool_from_genesis(
            &mut rng,
            &mut tf,
            amount_to_stake,
            (amount_to_stake * 3).unwrap(),
        );

        let (tx2, pool_id2, pool_data2, _) = make_tx_with_stake_pool(
            &mut rng,
            tx_utxo_outpoint,
            amount_to_stake,
            (amount_to_stake * 2).unwrap(),
        );

        let block1_index = tf
            .make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block1_index.block_height()),
            block1_epoch_index
        );
        let block2_index = tf
            .make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block2_index.block_height()),
            block2_epoch_index
        );

        // check that result is stored to tip
        let expected_tip_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([
                (pool_id1, pool_data1.clone()),
                (pool_id2, pool_data2.clone()),
            ]),
            pool_balances: BTreeMap::from([
                (pool_id1, amount_to_stake),
                (pool_id2, amount_to_stake),
            ]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };

        let db_tx = storage.transaction_ro().unwrap();

        assert_eq!(
            db_tx.read_pos_accounting_data_tip().unwrap(),
            expected_tip_storage_data
        );

        // check that result is not stored to sealed
        assert!(db_tx.read_pos_accounting_data_sealed().unwrap().is_empty());

        // check that deltas per block are stored
        let expected_epoch1_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [(pool_id1, DataDelta::new(None, Some(pool_data1)))].into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [(pool_id1, amount_to_stake.into_signed().unwrap())].into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch1_delta =
            db_tx.get_accounting_epoch_delta(block1_epoch_index).expect("ok").expect("some");
        assert_eq!(epoch1_delta, expected_epoch1_delta);

        let expected_epoch2_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [(pool_id2, DataDelta::new(None, Some(pool_data2)))].into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [(pool_id2, amount_to_stake.into_signed().unwrap())].into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch2_delta =
            db_tx.get_accounting_epoch_delta(block2_epoch_index).expect("ok").expect("some");
        assert_eq!(epoch2_delta, expected_epoch2_delta);

        assert!(db_tx.get_accounting_epoch_undo_delta(0).unwrap().is_none());
        assert!(db_tx.get_accounting_epoch_undo_delta(block1_epoch_index).unwrap().is_none());
        assert!(db_tx.get_accounting_epoch_undo_delta(block2_epoch_index).unwrap().is_none());
    });
}

// Config chain to seal an epoch every block and the distance between tip and sealed to 1.
// Create block1 from genesis and block2 from block1.
// Every block creates a stake pool.
// Check that block1 and block2 belong to different epochs, and that epoch1 was sealed.
// Check that accounting info from both blocks got into tip.
// Check that only accounting info from block1 got into sealed storage.
// Check that deltas from both blocks is stored.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_storage_seal_one_epoch(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(NonZeroU64::new(1).unwrap())
            .sealed_epoch_distance_from_tip(1)
            .build();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(chain_config)
            .build();
        let amount_to_stake = tf.chainstate.get_chain_config().min_stake_pool_pledge();
        // genesis block takes epoch 0, so new blocks start from epoch 1
        let block1_epoch_index = 1;
        let block2_epoch_index = 2;

        let (tx1, pool_id1, pool_data1, tx_utxo_outpoint) = make_tx_with_stake_pool_from_genesis(
            &mut rng,
            &mut tf,
            amount_to_stake,
            (amount_to_stake * 3).unwrap(),
        );

        let (tx2, pool_id2, pool_data2, _) = make_tx_with_stake_pool(
            &mut rng,
            tx_utxo_outpoint,
            amount_to_stake,
            (amount_to_stake * 2).unwrap(),
        );

        let block1_index = tf
            .make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block1_index.block_height()),
            block1_epoch_index
        );
        let block2_index = tf
            .make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block2_index.block_height()),
            block2_epoch_index
        );

        // check that result is stored to tip
        let expected_tip_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([
                (pool_id1, pool_data1.clone()),
                (pool_id2, pool_data2.clone()),
            ]),
            pool_balances: BTreeMap::from([
                (pool_id1, amount_to_stake),
                (pool_id2, amount_to_stake),
            ]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_tip().unwrap(),
            expected_tip_storage_data
        );

        // check that epoch1 is stored to sealed
        let expected_sealed_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([(pool_id1, pool_data1.clone())]),
            pool_balances: BTreeMap::from([(pool_id1, amount_to_stake)]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_sealed().unwrap(),
            expected_sealed_storage_data
        );

        // check that deltas per block are stored
        let expected_epoch1_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [(pool_id1, DataDelta::new(None, Some(pool_data1)))].into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [(pool_id1, amount_to_stake.into_signed().unwrap())].into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch1_delta = storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_delta(block1_epoch_index)
            .expect("ok")
            .expect("some");
        assert_eq!(epoch1_delta, expected_epoch1_delta);

        let expected_epoch2_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [(pool_id2, DataDelta::new(None, Some(pool_data2)))].into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [(pool_id2, amount_to_stake.into_signed().unwrap())].into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch2_delta = storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_delta(block2_epoch_index)
            .expect("ok")
            .expect("some");
        assert_eq!(epoch2_delta, expected_epoch2_delta);

        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(0)
            .unwrap()
            .is_none());
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(1)
            .unwrap()
            .is_some());
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(2)
            .unwrap()
            .is_none());
    });
}

// Config chain to seal an epoch every block and the distance between tip and sealed to 0
// (meaning every block is sealed thus tip == sealed).
// Create block1 from genesis that creates a stake pool.
// Check that the info is stored to the tip and sealed storage.
// Check that delta from block is stored.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_storage_seal_every_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(NonZeroU64::new(1).unwrap())
            .sealed_epoch_distance_from_tip(0)
            .build();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(chain_config)
            .build();
        let amount_to_stake = tf.chainstate.get_chain_config().min_stake_pool_pledge();
        // genesis block takes epoch 0, so new blocks start from epoch 1
        let block1_epoch_index = 1;

        let (tx1, pool_id, pool_data, _tx_utxo_outpoint) = make_tx_with_stake_pool_from_genesis(
            &mut rng,
            &mut tf,
            amount_to_stake,
            Amount::from_atoms(1),
        );

        let block1_index = tf
            .make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block1_index.block_height()),
            block1_epoch_index
        );

        // check that result is stored to tip and sealed
        let expected_storage_data = pos_accounting::PoSAccountingData {
            pool_data: BTreeMap::from([(pool_id, pool_data.clone())]),
            pool_balances: BTreeMap::from([(pool_id, amount_to_stake)]),
            delegation_balances: Default::default(),
            delegation_data: Default::default(),
            pool_delegation_shares: Default::default(),
        };
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_tip().unwrap(),
            expected_storage_data
        );
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_sealed().unwrap(),
            expected_storage_data
        );

        // check that deltas per block are stored
        let expected_epoch1_delta = pos_accounting::PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [(pool_id, DataDelta::new(None, Some(pool_data)))].into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [(pool_id, amount_to_stake.into_signed().unwrap())].into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        };

        let epoch1_delta = storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_delta(block1_epoch_index)
            .expect("ok")
            .expect("some");
        assert_eq!(epoch1_delta, expected_epoch1_delta);

        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(0)
            .unwrap()
            .is_none());
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(1)
            .unwrap()
            .is_some());
    });
}

// Config chain to seal an epoch every block and the distance between tip and sealed to 0
// (meaning every block is sealed thus tip == sealed).
// Create block1 from genesis that spend a coin (no accounting data).
// Check that epoch is changed, but tip and sealed storages are empty.
// Check that deltas per block and undo per epoch are empty.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_storage_no_accounting_data(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(NonZeroU64::new(1).unwrap())
            .sealed_epoch_distance_from_tip(0)
            .build();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(chain_config)
            .build();
        // genesis block takes epoch 0, so new blocks start from epoch 1
        let block1_epoch_index = 1;

        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                anyonecanspend_address(),
            ))
            .build();

        let block1_index = tf
            .make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .expect("ok")
            .expect("some");
        assert_eq!(
            tf.chainstate
                .get_chain_config()
                .epoch_index_from_height(&block1_index.block_height()),
            block1_epoch_index
        );

        // check that result is stored to tip and sealed
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_tip().unwrap(),
            pos_accounting::PoSAccountingData::new()
        );
        assert_eq!(
            storage.transaction_ro().unwrap().read_pos_accounting_data_sealed().unwrap(),
            pos_accounting::PoSAccountingData::new()
        );

        // check that deltas per epoch are not stored
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_delta(block1_epoch_index)
            .unwrap()
            .is_none());

        // check that undo per epoch are not stored
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(0)
            .unwrap()
            .is_none());
        assert!(storage
            .transaction_ro()
            .unwrap()
            .get_accounting_epoch_undo_delta(1)
            .unwrap()
            .is_none());
    });
}
