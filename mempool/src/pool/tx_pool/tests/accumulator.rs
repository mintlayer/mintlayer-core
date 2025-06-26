// Copyright (c) 2022 RBB S.r.l
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

use std::borrow::Cow;

use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        htlc::{HashedTimelockContract, HtlcSecret},
        signature::{
            inputsig::{
                classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                htlc::produce_classical_multisig_signature_for_htlc_input,
            },
            sighash::{
                input_commitments::SighashInputCommitment, sighashtype::SigHashType, signature_hash,
            },
        },
        timelock::OutputTimeLock,
    },
};
use crypto::key::{KeyKind, PrivateKey};
use serialization::Compact;

use super::*;
use crate::tx_accumulator::DefaultTxAccumulator;

// Useful for testing cases where timestamp is irrelevant.
const DUMMY_TIMESTAMP: BlockTimestamp = BlockTimestamp::from_int_seconds(0u64);

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_accumulator(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();
    let size_limit = rng.gen_range(10_000..=200_000);

    let mut accumulator = DefaultTxAccumulator::new(size_limit, genesis_id.into(), DUMMY_TIMESTAMP);

    // Create a bunch of transactions that leave a small amount of space in the block
    let mut amount = 900_000_000_000;
    let mut source = OutPointSourceId::BlockReward(genesis_id.into());
    while accumulator.transactions().encoded_size() + 15_000 <= size_limit {
        let tx = make_tx(&mut rng, &[(source, 0)], &[amount]);
        source = OutPointSourceId::Transaction(tx.transaction().get_id());
        amount -= rng.gen_range(1_000_000..=5_000_000);
        accumulator.add_tx(tx, Fee::new(Amount::from_atoms(0))).unwrap();
        assert!(!accumulator.done());
    }

    // How much size is there left in the block
    let size_left = {
        let empty = size_limit - accumulator.transactions().encoded_size();
        let len = accumulator.transactions().len() as u64;
        let correction = Compact(len + 1).encoded_size() - Compact(len).encoded_size();
        empty - correction
    };

    // Create a transaction that exactly fits the size
    let make_sized_tx = move |witness_size| {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(source.clone(), 0),
                InputWitness::NoSignature(Some(vec![0xffu8; witness_size])),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(amount)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    };

    let tx_100_size = make_sized_tx(100).encoded_size();
    let last_tx = make_sized_tx(size_left - tx_100_size + 100);
    let source = OutPointSourceId::Transaction(last_tx.transaction().get_id());

    accumulator.add_tx(last_tx, Fee::new(Amount::from_atoms(0))).unwrap();
    assert_eq!(accumulator.total_size(), size_limit);

    let leftover_tx = make_tx(&mut rng, &[(source, 0)], &[100_000_000_000]);
    accumulator.add_tx(leftover_tx, Fee::new(Amount::from_atoms(0))).unwrap();
    assert_eq!(accumulator.total_size(), size_limit);
    assert!(accumulator.done());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_order_respects_deps(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let tx0 = make_tx(&mut rng, &[(genesis_id.into(), 0)], &[900_000_000_000]);
    let tx0_id = tx0.transaction().get_id();

    let tx1 = make_tx(&mut rng, &[(tx0_id.into(), 0)], &[800_000_000_000]);
    let tx1_id = tx1.transaction().get_id();

    let tx2 = make_tx(&mut rng, &[(tx1_id.into(), 0)], &[500_000_000_000]);
    let tx2_id = tx2.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    assert_eq!(mempool.add_transaction_test(tx0), Ok(TxStatus::InMempool));
    assert_eq!(mempool.add_transaction_test(tx1), Ok(TxStatus::InMempool));
    assert_eq!(mempool.add_transaction_test(tx2), Ok(TxStatus::InMempool));
    assert!(mempool.contains_transaction(&tx2_id));

    let accumulator = Box::new(DefaultTxAccumulator::new(
        1_000_000,
        genesis_id.into(),
        DUMMY_TIMESTAMP,
    ));
    let accumulator = mempool
        .collect_txs(accumulator, vec![], PackingStrategy::FillSpaceFromMempool)
        .unwrap();
    let tx_ids: Vec<_> = accumulator
        .unwrap()
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect();

    assert_eq!(tx_ids, vec![tx0_id, tx1_id, tx2_id]);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_graph_respects_deps(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();
    let time = tf.genesis().timestamp();

    let txs: Vec<_> = generate_transaction_graph(&mut rng, time.into_time()).take(15).collect();

    let mut mempool = setup_with_chainstate(tf.chainstate());

    for tx in &txs {
        let res = mempool.add_transaction_test(tx.transaction().clone());
        assert_eq!(res, Ok(TxStatus::InMempool));
    }

    let txs_by_id: BTreeMap<_, _> = txs.into_iter().map(|tx| (*tx.tx_id(), tx)).collect();

    // Pick a number of transaction IDs to be explicitly requested by the user.
    let user_tx_ids = txs_by_id.keys().filter(|_| rng.gen_bool(0.1)).copied().collect();

    let accumulator = Box::new(DefaultTxAccumulator::new(
        10_000_000,
        genesis_id.into(),
        DUMMY_TIMESTAMP,
    ));
    let accumulator = mempool
        .collect_txs(
            accumulator,
            user_tx_ids,
            PackingStrategy::FillSpaceFromMempool,
        )
        .unwrap();
    let position_map: BTreeMap<Id<Transaction>, usize> = accumulator
        .unwrap()
        .transactions()
        .iter()
        .enumerate()
        .map(|(pos, tx)| (tx.transaction().get_id(), pos))
        .collect();

    for (tx_id, tx_pos) in position_map.iter() {
        let tx = txs_by_id[tx_id].transaction().transaction();
        tx.inputs()
            .iter()
            .filter_map(|i| i.utxo_outpoint().and_then(|o| o.source_id().get_tx_id().cloned()))
            .for_each(|parent_tx_id| assert!(position_map[&parent_tx_id] < *tx_pos));
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collect_transactions(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut mempool = setup_with_chainstate(tf.chainstate());

    let size_limit: usize = 1_000;
    let tx_accumulator =
        DefaultTxAccumulator::new(size_limit, mempool.best_block_id(), DUMMY_TIMESTAMP);
    let returned_accumulator = mempool
        .collect_txs(
            Box::new(tx_accumulator),
            vec![],
            PackingStrategy::FillSpaceFromMempool,
        )
        .unwrap();
    let collected_txs = returned_accumulator.unwrap();
    let collected_txs = collected_txs.transactions();
    let expected_num_txs_collected: usize = 0;
    assert_eq!(collected_txs.len(), expected_num_txs_collected);

    let target_txs = 10;

    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );
    for i in 0..target_txs {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000 * (target_txs + 1 - i))),
            Destination::AnyoneCanSpend,
        ))
    }
    let initial_tx = tx_builder.build();
    let initial_tx_id = initial_tx.transaction().get_id();
    mempool.add_transaction_test(initial_tx)?.assert_in_mempool();
    for i in 0..target_txs {
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(initial_tx_id), i as u32),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(0)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        mempool.add_transaction_test(tx.clone())?.assert_in_mempool();
    }

    let size_limit = 1_000;
    let tx_accumulator =
        DefaultTxAccumulator::new(size_limit, mempool.best_block_id(), DUMMY_TIMESTAMP);
    let returned_accumulator = mempool
        .collect_txs(
            Box::new(tx_accumulator),
            vec![],
            PackingStrategy::FillSpaceFromMempool,
        )
        .unwrap();
    let collected_txs = returned_accumulator.unwrap();
    let collected_txs = collected_txs.transactions();
    log::debug!("ancestor index: {:?}", mempool.store.txs_by_ancestor_score);
    let expected_num_txs_collected = 6;
    assert_eq!(collected_txs.len(), expected_num_txs_collected);
    let total_tx_size: usize = collected_txs.iter().map(|tx| tx.encoded_size()).sum();
    assert!(total_tx_size <= size_limit);

    let tx_accumulator = DefaultTxAccumulator::new(0, mempool.best_block_id(), DUMMY_TIMESTAMP);
    let returned_accumulator = mempool
        .collect_txs(
            Box::new(tx_accumulator),
            vec![],
            PackingStrategy::FillSpaceFromMempool,
        )
        .unwrap();
    let collected_txs = returned_accumulator.unwrap();
    let collected_txs = collected_txs.transactions();
    assert_eq!(collected_txs.len(), 0);

    let tx_accumulator = DefaultTxAccumulator::new(1, mempool.best_block_id(), DUMMY_TIMESTAMP);
    let returned_accumulator = mempool
        .collect_txs(
            Box::new(tx_accumulator),
            vec![],
            PackingStrategy::FillSpaceFromMempool,
        )
        .unwrap();
    let collected_txs = returned_accumulator.unwrap();
    let collected_txs = collected_txs.transactions();
    assert_eq!(collected_txs.len(), 0);
    Ok(())
}

fn timelock_secs_after_genesis(n: u64) -> OutputTimeLock {
    let mut rng = make_seedable_rng(Seed::from_u64(0));
    let t0 = TestFramework::builder(&mut rng).build().genesis().timestamp();
    OutputTimeLock::UntilTime(t0.add_int_seconds(n).unwrap())
}

#[rstest]
#[trace]
#[case::until_blk1(Seed::from_entropy(), OutputTimeLock::UntilHeight(1.into()), 0b1111)]
#[trace]
#[case::until_blk2(Seed::from_entropy(), OutputTimeLock::UntilHeight(2.into()), 0b1011)]
#[trace]
#[case::until_blk4(Seed::from_entropy(), OutputTimeLock::UntilHeight(4.into()), 0b1010)]
#[trace]
#[case::until_blk20(Seed::from_entropy(), OutputTimeLock::UntilHeight(20.into()), 0b0000)]
#[trace]
#[case::for_1blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(1), 0b0011)]
#[trace]
#[case::for_2blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(2), 0b0010)]
#[trace]
#[case::for_20blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(20), 0b0000)]
#[trace]
#[case::until_5s(Seed::from_entropy(), timelock_secs_after_genesis(5), 0b1111)]
#[trace]
#[case::until_10s(Seed::from_entropy(), timelock_secs_after_genesis(10), 0b1111)]
#[trace]
#[case::until_11s(Seed::from_entropy(), timelock_secs_after_genesis(11), 0b1011)]
#[trace]
#[case::until_30s(Seed::from_entropy(), timelock_secs_after_genesis(30), 0b1011)]
#[trace]
#[case::until_31s(Seed::from_entropy(), timelock_secs_after_genesis(31), 0b1010)]
#[trace]
#[case::until_500s(Seed::from_entropy(), timelock_secs_after_genesis(500), 0b0000)]
#[trace]
#[case::for_1s(Seed::from_entropy(), OutputTimeLock::ForSeconds(1), 0b0011)]
#[trace]
#[case::for_10s(Seed::from_entropy(), OutputTimeLock::ForSeconds(10), 0b0011)]
#[trace]
#[case::for_20s(Seed::from_entropy(), OutputTimeLock::ForSeconds(20), 0b0011)]
#[trace]
#[case::for_21s(Seed::from_entropy(), OutputTimeLock::ForSeconds(21), 0b0010)]
#[trace]
#[case::for_500s(Seed::from_entropy(), OutputTimeLock::ForSeconds(500), 0b0000)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timelocked(#[case] seed: Seed, #[case] timelock: OutputTimeLock, #[case] expected: u32) {
    // Unpack expected results:
    let in_mempool_at0 = (expected & 0b1000) != 0;
    let in_accumulator_at0 = (expected & 0b0100) != 0;
    let in_mempool_at1 = (expected & 0b0010) != 0;
    let in_accumulator_at1 = (expected & 0b0001) != 0;

    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let genesis_time = tf.genesis().timestamp();
    let block1_time = genesis_time.add_int_seconds(10).unwrap();
    let block2_time = genesis_time.add_int_seconds(30).unwrap();

    let tx0 = {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_id.into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(900_000_000)),
                Destination::AnyoneCanSpend,
                timelock,
            ))
            .build()
    };
    let tx0_id = tx0.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.clock = mocked_time_getter_seconds(Arc::new(block1_time.as_int_seconds().into()));
    let chainstate = mempool.chainstate_handle().shallow_clone();

    let res = mempool.add_transaction_test(tx0.clone());
    assert_eq!(res, Ok(TxStatus::InMempool));

    let tx1 = make_tx(&mut rng, &[(tx0_id.into(), 0)], &[800_000_000]);
    let tx1_id = tx1.transaction().get_id();

    let res = mempool.add_transaction_test(tx1.clone());
    assert_eq!(
        res.is_ok(),
        in_mempool_at0,
        "Unexpected mempool acceptance {res:?}"
    );

    let accumulator = Box::new(DefaultTxAccumulator::new(
        1_000_000,
        genesis_id.into(),
        block1_time,
    ));
    let accumulator = mempool
        .collect_txs(accumulator, vec![], PackingStrategy::FillSpaceFromMempool)
        .unwrap();
    let accumulated_ids: BTreeSet<_> = accumulator
        .unwrap()
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect();

    assert!(accumulated_ids.contains(&tx0_id));
    assert_eq!(accumulated_ids.contains(&tx1_id), in_accumulator_at0);

    // Submit a block with the transaction that defines the time-locked output
    let block1 = make_test_block(vec![tx0], genesis_id, block1_time);
    let block1_id = block1.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block1, BlockSource::Local))
        .await
        .unwrap()
        .expect("block1");
    mempool.on_new_tip(block1_id, BlockHeight::new(1)).unwrap();

    let in_mempool = if !in_mempool_at0 {
        mempool.add_transaction_test(tx1.clone()).is_ok()
    } else {
        mempool.contains_transaction(&tx1_id)
    };

    assert_eq!(in_mempool, in_mempool_at1);

    // Check if the transaction spending time locked output is in the accumulator now
    let accumulator = Box::new(DefaultTxAccumulator::new(
        1_000_000,
        block1_id.into(),
        block2_time,
    ));
    let accumulator = mempool
        .collect_txs(accumulator, vec![], PackingStrategy::FillSpaceFromMempool)
        .unwrap()
        .unwrap();
    let has_tx1 = accumulator.transactions().iter().any(|tx| tx.transaction().get_id() == tx1_id);

    assert_eq!(has_tx1, in_accumulator_at1);
    assert!(accumulator.transactions().len() <= 1);
}

#[rstest]
#[trace]
#[case::until_blk1(Seed::from_entropy(), OutputTimeLock::UntilHeight(1.into()), 0b1111)]
#[trace]
#[case::until_blk2(Seed::from_entropy(), OutputTimeLock::UntilHeight(2.into()), 0b1011)]
#[trace]
#[case::until_blk4(Seed::from_entropy(), OutputTimeLock::UntilHeight(4.into()), 0b1010)]
#[trace]
#[case::until_blk20(Seed::from_entropy(), OutputTimeLock::UntilHeight(20.into()), 0b0000)]
#[trace]
#[case::for_1blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(1), 0b0011)]
#[trace]
#[case::for_2blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(2), 0b0010)]
#[trace]
#[case::for_20blk(Seed::from_entropy(), OutputTimeLock::ForBlockCount(20), 0b0000)]
#[trace]
#[case::until_5s(Seed::from_entropy(), timelock_secs_after_genesis(5), 0b1111)]
#[trace]
#[case::until_10s(Seed::from_entropy(), timelock_secs_after_genesis(10), 0b1111)]
#[trace]
#[case::until_11s(Seed::from_entropy(), timelock_secs_after_genesis(11), 0b1011)]
#[trace]
#[case::until_30s(Seed::from_entropy(), timelock_secs_after_genesis(30), 0b1011)]
#[trace]
#[case::until_31s(Seed::from_entropy(), timelock_secs_after_genesis(31), 0b1010)]
#[trace]
#[case::until_500s(Seed::from_entropy(), timelock_secs_after_genesis(500), 0b0000)]
#[trace]
#[case::for_1s(Seed::from_entropy(), OutputTimeLock::ForSeconds(1), 0b0011)]
#[trace]
#[case::for_10s(Seed::from_entropy(), OutputTimeLock::ForSeconds(10), 0b0011)]
#[trace]
#[case::for_20s(Seed::from_entropy(), OutputTimeLock::ForSeconds(20), 0b0011)]
#[trace]
#[case::for_21s(Seed::from_entropy(), OutputTimeLock::ForSeconds(21), 0b0010)]
#[trace]
#[case::for_500s(Seed::from_entropy(), OutputTimeLock::ForSeconds(500), 0b0000)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timelocked_htlc_refund(
    #[case] seed: Seed,
    #[case] timelock: OutputTimeLock,
    #[case] expected: u32,
) {
    // Unpack expected results:
    let in_mempool_at0 = (expected & 0b1000) != 0;
    let in_accumulator_at0 = (expected & 0b0100) != 0;
    let in_mempool_at1 = (expected & 0b0010) != 0;
    let in_accumulator_at1 = (expected & 0b0001) != 0;

    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let chain_config = tf.chain_config().shallow_clone();
    let genesis_id = tf.genesis().get_id();

    let genesis_time = tf.genesis().timestamp();
    let block1_time = genesis_time.add_int_seconds(10).unwrap();
    let block2_time = genesis_time.add_int_seconds(30).unwrap();

    // Setup tx with htlc
    let (alice_sk, alice_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let secret = HtlcSecret::new_from_rng(&mut rng);
    let refund_challenge = ClassicMultisigChallenge::new(
        &chain_config,
        ::utils::const_nz_u8!(2),
        vec![alice_pk.clone(), bob_pk.clone()],
    )
    .unwrap();
    let destination_multisig: PublicKeyHash = (&refund_challenge).into();

    let htlc = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::PublicKeyHash((&bob_pk).into()),
        refund_timelock: timelock,
        refund_key: Destination::ClassicMultisig(destination_multisig),
    };

    let tx0 = {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_id.into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::Coin(Amount::from_atoms(900_000_000)),
                Box::new(htlc),
            ))
            .build()
    };
    let tx0_id = tx0.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.clock = mocked_time_getter_seconds(Arc::new(block1_time.as_int_seconds().into()));
    let chainstate = mempool.chainstate_handle().shallow_clone();

    let res = mempool.add_transaction_test(tx0.clone());
    assert_eq!(res, Ok(TxStatus::InMempool));

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx0_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            Destination::AnyoneCanSpend,
        ))
        .build()
        .take_transaction();

    let authorization = {
        let mut authorization = AuthorizedClassicalMultisigSpend::new_empty(refund_challenge);

        let sighash = signature_hash(
            SigHashType::all(),
            &tx,
            &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx0.transaction().outputs()[0]))],
            0,
        )
        .unwrap();
        let sighash = sighash.encode();

        let signature = alice_sk.sign_message(&sighash, &mut rng).unwrap();
        authorization.add_signature(0, signature);
        let signature = bob_sk.sign_message(&sighash, &mut rng).unwrap();
        authorization.add_signature(1, signature);

        authorization
    };

    let input_sign = produce_classical_multisig_signature_for_htlc_input(
        &chain_config,
        &authorization,
        SigHashType::all(),
        &tx,
        &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx0.transaction().outputs()[0]))],
        0,
    )
    .unwrap();
    let tx1 = SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap();
    let tx1_id = tx1.transaction().get_id();

    let res = mempool.add_transaction_test(tx1.clone());
    assert_eq!(
        res.is_ok(),
        in_mempool_at0,
        "Unexpected mempool acceptance {res:?}"
    );

    let accumulator = Box::new(DefaultTxAccumulator::new(
        1_000_000,
        genesis_id.into(),
        block1_time,
    ));
    let accumulator = mempool
        .collect_txs(accumulator, vec![], PackingStrategy::FillSpaceFromMempool)
        .unwrap();
    let accumulated_ids: BTreeSet<_> = accumulator
        .unwrap()
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect();

    assert!(accumulated_ids.contains(&tx0_id));
    assert_eq!(accumulated_ids.contains(&tx1_id), in_accumulator_at0);

    // Submit a block with the transaction that defines the time-locked output
    let block1 = make_test_block(vec![tx0], genesis_id, block1_time);
    let block1_id = block1.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block1, BlockSource::Local))
        .await
        .unwrap()
        .expect("block1");
    mempool.on_new_tip(block1_id, BlockHeight::new(1)).unwrap();

    let in_mempool = if !in_mempool_at0 {
        mempool.add_transaction_test(tx1.clone()).is_ok()
    } else {
        mempool.contains_transaction(&tx1_id)
    };

    assert_eq!(in_mempool, in_mempool_at1);

    // Check if the transaction spending time locked output is in the accumulator now
    let accumulator = Box::new(DefaultTxAccumulator::new(
        1_000_000,
        block1_id.into(),
        block2_time,
    ));
    let accumulator = mempool
        .collect_txs(accumulator, vec![], PackingStrategy::FillSpaceFromMempool)
        .unwrap()
        .unwrap();
    let has_tx1 = accumulator.transactions().iter().any(|tx| tx.transaction().get_id() == tx1_id);

    assert_eq!(has_tx1, in_accumulator_at1);
    assert!(accumulator.transactions().len() <= 1);
}
