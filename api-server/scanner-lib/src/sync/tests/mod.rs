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

mod simulation;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use rstest::rstest;
use tokio::sync::mpsc;

use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{
        ApiServerStorageRead, ApiServerStorageWrite, ApiServerTransactionRw, Transactional,
    },
};
use chainstate::{BlockSource, ChainInfo};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    address::Address,
    chain::{
        htlc::{HashedTimelockContract, HtlcSecret},
        make_delegation_id, make_order_id, make_token_id,
        output_value::OutputValue,
        signature::inputsig::authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
        signature::{
            inputsig::{
                authorize_pubkey_spend::sign_public_key_spending,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::{
                input_commitments::{
                    make_sighash_input_commitments_for_transaction_inputs_at_height, OrderInfo,
                    PoolInfo, SighashInputCommitment, TrivialUtxoProvider,
                },
                sighashtype::SigHashType,
                signature_hash,
            },
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{IsTokenUnfreezable, TokenIssuance},
        AccountCommand, AccountNonce, CoinUnit, Destination, OrderAccountCommand, OrderData,
        OrderId, OutPointSourceId, PoolId, SignedTransaction, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, CoinOrTokenId, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use logging::log;
use mempool::FeeRate;
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};

use crate::blockchain_state::BlockchainState;

use super::*;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

struct MockLocalState {
    genesis_id: Id<GenBlock>,
    blocks: Vec<Id<Block>>,
    new_tip_tx: mpsc::UnboundedSender<Id<Block>>,
}

impl MockLocalState {
    fn new(chain_config: &ChainConfig, new_tip_tx: mpsc::UnboundedSender<Id<Block>>) -> Self {
        Self {
            genesis_id: chain_config.genesis_block_id(),
            blocks: Vec::new(),
            new_tip_tx,
        }
    }

    fn get_best_block_id(&self) -> Id<GenBlock> {
        self.blocks.last().cloned().map_or(self.genesis_id, Into::into)
    }

    fn get_block_height(&self) -> BlockHeight {
        BlockHeight::from(self.blocks.len() as u64)
    }
}

#[async_trait::async_trait]
impl LocalBlockchainState for MockLocalState {
    type Error = Infallible;

    async fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        Ok((self.get_block_height(), self.get_best_block_id()))
    }

    async fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        assert!(!blocks.is_empty());
        assert!(
            common_block_height <= self.get_block_height(),
            "Invalid common block height: {common_block_height}, max: {}",
            self.get_block_height()
        );

        self.blocks.truncate(common_block_height.into_int() as usize);
        for block in blocks {
            assert_eq!(*block.header().prev_block_id(), self.get_best_block_id());
            self.blocks.push(block.header().block_id());
            let _ = self.new_tip_tx.send(block.header().block_id());
        }

        log::debug!(
            "new block added to local state: {}, block height: {}",
            self.get_best_block_id(),
            self.get_block_height()
        );

        Ok(())
    }
}

#[derive(Clone)]
struct MockRemoteNode {
    tf: Arc<Mutex<TestFramework>>,
}

impl MockRemoteNode {
    fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let tf = Arc::new(Mutex::new(TestFramework::builder(rng).build()));
        Self { tf }
    }
}

#[async_trait::async_trait]
impl RemoteNode for MockRemoteNode {
    type Error = Infallible;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.info().unwrap())
    }
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        Ok(self
            .tf
            .lock()
            .unwrap()
            .chainstate
            .last_common_ancestor_by_id(&first_block, &second_block)
            .unwrap())
    }

    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        Ok(self
            .tf
            .lock()
            .unwrap()
            .chainstate
            .get_mainchain_blocks(from, max_count)
            .unwrap())
    }

    async fn mempool_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        Ok(vec![(
            1,
            FeeRate::from_amount_per_kb(Amount::from_atoms(1)),
        )])
    }
}

fn create_chain(
    node: &MockRemoteNode,
    rng: &mut (impl Rng + CryptoRng),
    parent: u64,
    count: usize,
) {
    let mut tf = node.tf.lock().unwrap();
    let parent_id = tf.chainstate.get_block_id_from_height(&parent.into()).unwrap().unwrap();
    tf.create_chain(&parent_id, count, rng).unwrap();
}

async fn wait_new_tip(node: &MockRemoteNode, new_tip_tx: &mut mpsc::UnboundedReceiver<Id<Block>>) {
    let expected_block_id = node.tf.lock().unwrap().best_block_id();
    let wait_fut = async move { while new_tip_tx.recv().await.unwrap() != expected_block_id {} };
    tokio::time::timeout(Duration::from_secs(60), wait_fut).await.unwrap();
}

fn run_sync(chain_config: Arc<ChainConfig>, node: MockRemoteNode, mut local_state: MockLocalState) {
    tokio::spawn(async move {
        loop {
            let _ = sync_once(&chain_config, &node, &mut local_state).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn basic_sync(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockRemoteNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
    let local_state = MockLocalState::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), local_state);

    // Build blocks
    for height in 1..10 {
        create_chain(&node, &mut rng, height - 1, 1);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // Reorgs
    for height in 10..20 {
        create_chain(&node, &mut rng, height - 5, 5);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // More blocks
    for height in 20..30 {
        create_chain(&node, &mut rng, height - 1, 1);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // More reorgs
    for height in 30..40 {
        create_chain(&node, &mut rng, height - 5, 5);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn restart_from_genesis(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockRemoteNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
    let local_state = MockLocalState::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), local_state);

    create_chain(&node, &mut rng, 0, 10);
    wait_new_tip(&node, &mut new_tip_rx).await;

    *node.tf.lock().unwrap() = TestFramework::builder(&mut rng).build();

    create_chain(&node, &mut rng, 0, 10);
    wait_new_tip(&node, &mut new_tip_rx).await;
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockRemoteNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
    let local_state = MockLocalState::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), local_state);

    create_chain(&node, &mut rng, 0, 1);
    wait_new_tip(&node, &mut new_tip_rx).await;

    for _ in 0..100 {
        let new_tip = {
            let mut tf = node.tf.lock().unwrap();
            let old_best_block = tf.best_block_id();
            // Select a random block from the 5 latest to build a new chain
            let parent =
                *tf.block_indexes.iter().rev().take(5).choose(&mut rng).unwrap().block_id();
            tf.create_chain(&parent.into(), 1, &mut rng).unwrap();
            old_best_block != tf.best_block_id()
        };

        if new_tip {
            wait_new_tip(&node, &mut new_tip_rx).await;
        }
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn compare_pool_rewards_with_chainstate_real_state(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let initial_pledge = 40_000 * CoinUnit::ATOMS_PER_COIN + rng.gen_range(10000..100000);
    let (staking_sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let staking_key = Destination::PublicKey(pk.clone());
    let pool_data = StakePoolData::new(
        Amount::from_atoms(initial_pledge),
        staking_key.clone(),
        vrf_pk,
        staking_key.clone(),
        PerThousand::new_from_rng(&mut rng),
        Amount::from_atoms(rng.gen_range(0..100)),
    );
    let pool_id = PoolId::new(H256::random_using(&mut rng));

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        Amount::from_atoms(initial_pledge * 2),
        pool_id,
        pool_data,
    )
    .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let chain_config = Arc::clone(tf.chainstate.get_chain_config());
    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        storage
    };
    let mut local_state = BlockchainState::new(chain_config.clone(), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let remaining_coins = initial_pledge;
    eprintln!("coins: {remaining_coins}");
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                0,
            ),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let prev_block_hash = chain_config.genesis_block_id();
    let prev_tx_id = transaction.transaction().get_id();
    let target_block_time = chain_config.target_block_spacing();
    let block = create_block(
        &mut rng,
        &mut tf,
        target_block_time,
        prev_block_hash,
        staking_sk.clone(),
        vrf_sk.clone(),
        pool_id,
        vec![transaction],
    );

    let prev_block_hash = block.get_id();
    sync_and_compare(&mut tf, block, &mut local_state, pool_id).await;

    let remaining_coins = remaining_coins - rng.gen_range(0..10);
    eprintln!("coins: {remaining_coins}");
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let prev_tx_id = transaction.transaction().get_id();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = create_block(
        &mut rng,
        &mut tf,
        target_block_time,
        prev_block_hash.into(),
        staking_sk.clone(),
        vrf_sk.clone(),
        pool_id,
        vec![transaction],
    );

    let prev_block_hash = block.get_id();
    sync_and_compare(&mut tf, block, &mut local_state, pool_id).await;

    let remaining_coins = remaining_coins - rng.gen_range(0..10);
    eprintln!("coins: {remaining_coins}");
    let (_, deleg_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateDelegationId(
            Destination::PublicKeyHash((&deleg_pk).into()),
            pool_id,
        ))
        .build();
    let delegation_id = make_delegation_id(transaction.inputs()).unwrap();
    let prev_tx_id = transaction.transaction().get_id();

    let amount_to_stake = rng.gen_range(100..1000);
    let remaining_coins = remaining_coins - amount_to_stake - rng.gen_range(0..10);
    eprintln!("coins: {remaining_coins} {amount_to_stake}");
    let stake_transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::DelegateStaking(
            Amount::from_atoms(amount_to_stake),
            delegation_id,
        ))
        .build();
    let prev_tx_id = stake_transaction.transaction().get_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = create_block(
        &mut rng,
        &mut tf,
        target_block_time,
        prev_block_hash.into(),
        staking_sk.clone(),
        vrf_sk.clone(),
        pool_id,
        vec![transaction, stake_transaction],
    );

    let prev_block_hash = block.get_id();
    sync_and_compare(&mut tf, block, &mut local_state, pool_id).await;

    let remaining_coins = remaining_coins - rng.gen_range(0..10);
    eprintln!("coins: {remaining_coins}");
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let prev_tx_id = transaction.transaction().get_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = create_block(
        &mut rng,
        &mut tf,
        target_block_time,
        prev_block_hash.into(),
        staking_sk.clone(),
        vrf_sk.clone(),
        pool_id,
        vec![transaction],
    );

    let prev_block_hash = block.get_id();
    sync_and_compare(&mut tf, block, &mut local_state, pool_id).await;

    let initial_pledge = 40_000 * CoinUnit::ATOMS_PER_COIN
        + rng.gen_range(
            0..remaining_coins - chain_config.min_stake_pool_pledge().into_atoms() - 100,
        );
    let (new_staking_sk, new_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (new_vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let staking_key = Destination::PublicKey(new_pk);
    let pool_data = StakePoolData::new(
        Amount::from_atoms(initial_pledge),
        staking_key.clone(),
        vrf_pk,
        staking_key.clone(),
        PerThousand::new_from_rng(&mut rng),
        Amount::from_atoms(rng.gen_range(0..100)),
    );
    let new_pool_id = PoolId::from_utxo(&UtxoOutPoint::new(
        OutPointSourceId::Transaction(prev_tx_id),
        0,
    ));

    eprintln!("coins {remaining_coins}, {initial_pledge}");
    let remaining_coins = remaining_coins - initial_pledge - rng.gen_range(0..10);
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateStakePool(new_pool_id, Box::new(pool_data)))
        .build();
    let prev_tx_id = transaction.transaction().get_id();
    let new_pool_tx_id = prev_tx_id;
    let coin_tx_out = transaction.transaction().outputs()[0].clone();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = create_block(
        &mut rng,
        &mut tf,
        target_block_time,
        prev_block_hash.into(),
        staking_sk.clone(),
        vrf_sk.clone(),
        pool_id,
        vec![transaction],
    );
    let from_block_output = block.block_reward().outputs()[0].clone();

    let prev_block_hash = block.get_id();
    sync_and_compare(&mut tf, block, &mut local_state, pool_id).await;

    let remaining_coins = remaining_coins - rng.gen_range(0..10);
    let input1 = TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0);
    let input2 = TxInput::from_utxo(OutPointSourceId::BlockReward(prev_block_hash.into()), 0);
    let transaction = TransactionBuilder::new()
        .add_input(input1.clone(), InputWitness::NoSignature(None))
        .add_input(input2.clone(), InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let utxos = [Some(coin_tx_out), Some(from_block_output)];
    let decommissioned_pool_staker_balance = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_pool_data(pool_id)
        .await
        .unwrap()
        .unwrap()
        .staker_balance()
        .unwrap();
    let input_commitments = make_sighash_input_commitments_for_transaction_inputs_at_height(
        &[input1, input2],
        &TrivialUtxoProvider(&utxos),
        &BTreeMap::<PoolId, PoolInfo>::from([(
            pool_id,
            PoolInfo {
                staker_balance: decommissioned_pool_staker_balance,
            },
        )]),
        &BTreeMap::<OrderId, OrderInfo>::new(),
        &chain_config,
        tf.next_block_height(),
    )
    .unwrap();
    let sighash = signature_hash(
        SigHashType::default(),
        transaction.transaction(),
        &input_commitments,
        1,
    )
    .unwrap();

    let signature = sign_public_key_spending(&staking_sk, &pk, &sighash, &mut rng).unwrap();

    let input_witness = InputWitness::Standard(StandardInputSignature::new(
        SigHashType::default(),
        signature.encode(),
    ));

    let transaction = SignedTransaction::new(
        transaction.transaction().clone(),
        vec![InputWitness::NoSignature(None), input_witness],
    )
    .unwrap();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_pos_block_builder()
        .with_parent(prev_block_hash.into())
        .with_stake_spending_key(new_staking_sk)
        .with_vrf_key(new_vrf_sk.clone())
        .with_stake_pool_id(new_pool_id)
        .with_kernel_input(UtxoOutPoint::new(
            OutPointSourceId::Transaction(new_pool_tx_id),
            1,
        ))
        .with_transactions(vec![transaction])
        .build(&mut rng);

    sync_and_compare(&mut tf, block, &mut local_state, new_pool_id).await;
    let decommissioned_pool = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_pool_data(pool_id)
        .await
        .unwrap()
        .unwrap();

    // after decommission the staker balance is 0
    assert_eq!(decommissioned_pool.staker_balance().unwrap(), Amount::ZERO);
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn reorg_locked_balance(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();

    let chain_config = Arc::clone(tf.chainstate.get_chain_config());
    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        storage
    };
    let mut local_state = BlockchainState::new(chain_config.clone(), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let target_block_time = chain_config.target_block_spacing();

    let (priv_key, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let destination = Destination::PublicKey(pub_key.clone());

    let lock_for_block_count = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        destination.clone(),
        OutputTimeLock::ForBlockCount(1),
    );
    let lock_until_height = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(2)),
        destination.clone(),
        OutputTimeLock::UntilHeight(BlockHeight::new(2)),
    );
    let lock_for_sec = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(3)),
        destination.clone(),
        OutputTimeLock::ForSeconds(rng.gen_range(1..=target_block_time.as_secs())),
    );
    let lock_until_time = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(4)),
        destination.clone(),
        OutputTimeLock::UntilTime(
            chain_config
                .genesis_block()
                .timestamp()
                .add_int_seconds(
                    target_block_time.as_secs() + rng.gen_range(1..=target_block_time.as_secs()),
                )
                .unwrap(),
        ),
    );
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                0,
            ),
            InputWitness::NoSignature(None),
        )
        // Add all different Time locks to unlock after the next block
        .add_output(lock_for_block_count.clone())
        .add_output(lock_until_height.clone())
        .add_output(lock_for_sec.clone())
        .add_output(lock_until_time.clone())
        // Add all different time locks but already unlocked
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(10)),
            destination.clone(),
            OutputTimeLock::UntilHeight(BlockHeight::new(0)),
        ))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(20)),
            destination.clone(),
            OutputTimeLock::UntilTime(chain_config.genesis_block().timestamp()),
        ))
        .build();

    let already_unlocked_coins = 10 + 20;
    let already_unlocked_utxos = 2;

    let prev_block_hash = chain_config.genesis_block_id();
    let prev_tx_id = transaction.transaction().get_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_block_builder()
        .with_parent(prev_block_hash)
        .with_transactions(vec![transaction])
        .build(&mut rng);

    let prev_block_hash = block.get_id();
    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_best_block()
        .await
        .unwrap()
        .block_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    // Check all the outputs are locked and the locked balance is updated
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::from_atoms(1 + 2 + 3 + 4)));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();
    assert_eq!(balance, Some(Amount::from_atoms(already_unlocked_coins)));
    // check there are only 2 available utxos
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), already_unlocked_utxos);
    drop(db_tx);

    // create an empty block
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf.make_block_builder().with_parent(prev_block_hash.into()).build(&mut rng);

    let prev_block_hash = block.get_id();
    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = block_height.next_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    // Check all the height outputs are unlocked, but the time based ones are still not
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::from_atoms(3 + 4)));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();
    assert_eq!(
        balance,
        Some(Amount::from_atoms(1 + 2 + already_unlocked_coins))
    );
    // check all of the UTXOs are available
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), 2 + already_unlocked_utxos);
    drop(db_tx);

    // check we can spend all of the height locked utxos as they are unlocked
    let spend_transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 1),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let input_witnesses = (0..spend_transaction.inputs().len())
        .map(|idx| {
            let sighash = signature_hash(
                SigHashType::default(),
                spend_transaction.transaction(),
                &[
                    SighashInputCommitment::Utxo(Cow::Borrowed(&lock_for_block_count)),
                    SighashInputCommitment::Utxo(Cow::Borrowed(&lock_until_height)),
                ],
                idx,
            )
            .unwrap();
            let signature =
                sign_public_key_spending(&priv_key, &pub_key, &sighash, &mut rng).unwrap();
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::default(),
                signature.encode(),
            ))
        })
        .collect();

    let spend_transaction =
        SignedTransaction::new(spend_transaction.take_transaction(), input_witnesses).unwrap();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_block_builder()
        .with_parent(prev_block_hash.into())
        .with_transactions(vec![spend_transaction])
        .build(&mut rng);

    let _prev_block_hash = block.get_id();
    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_best_block()
        .await
        .unwrap()
        .block_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    // Check the time based ones are now unlocked as well
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::ZERO));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();

    assert_eq!(
        balance,
        Some(Amount::from_atoms(3 + 4 + already_unlocked_coins))
    );
    // check all of the UTXOs are available
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), 2 + already_unlocked_utxos);
    drop(db_tx);

    // check we can spend all of the time locked utxos as they are unlocked
    let spend_time_locked = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 2),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 3),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let input_witnesses = (0..spend_time_locked.inputs().len())
        .map(|idx| {
            let sighash = signature_hash(
                SigHashType::default(),
                spend_time_locked.transaction(),
                &[
                    SighashInputCommitment::Utxo(Cow::Borrowed(&lock_for_sec)),
                    SighashInputCommitment::Utxo(Cow::Borrowed(&lock_until_time)),
                ],
                idx,
            )
            .unwrap();
            let signature =
                sign_public_key_spending(&priv_key, &pub_key, &sighash, &mut rng).unwrap();
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::default(),
                signature.encode(),
            ))
        })
        .collect();

    let spend_time_locked_signed =
        SignedTransaction::new(spend_time_locked.take_transaction(), input_witnesses).unwrap();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_block_builder()
        .with_parent(prev_block_hash.into())
        .with_transactions(vec![spend_time_locked_signed])
        .build(&mut rng);

    let _prev_block_hash = block.get_id();
    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_best_block()
        .await
        .unwrap()
        .block_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    // check there are no more available utxos, and both balance and locked balance are 0
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::ZERO));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();

    assert_eq!(balance, Some(Amount::from_atoms(already_unlocked_coins)));
    // check there are no utxos as all are spent
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), already_unlocked_utxos);
    drop(db_tx);

    // delete last block
    local_state.scan_blocks(block_height, vec![]).await.unwrap();

    // we are back to 2 available utxos and balance is updated
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::ZERO));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();
    assert_eq!(
        balance,
        Some(Amount::from_atoms(3 + 4 + already_unlocked_coins))
    );
    // check all of the UTXOs are available
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), 2 + already_unlocked_utxos);
    drop(db_tx);

    // delete one more block
    local_state
        .scan_blocks(block_height.prev_height().unwrap(), vec![])
        .await
        .unwrap();

    // Check all the height outputs are unlocked, but the time based ones now back to locked
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination.clone()).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::from_atoms(3 + 4)));

    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();

    assert_eq!(
        balance,
        Some(Amount::from_atoms(1 + 2 + already_unlocked_coins))
    );
    // check all of the UTXOs are available
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), 2 + already_unlocked_utxos);
    drop(db_tx);

    // delete one more block
    local_state
        .scan_blocks(
            block_height.prev_height().unwrap().prev_height().unwrap(),
            vec![],
        )
        .await
        .unwrap();

    // Check all the outputs are locked and the locked balance is updated
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let address = Address::new(&chain_config, destination).unwrap();
    let locked_amount = db_tx
        .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap();

    assert_eq!(locked_amount, Some(Amount::from_atoms(1 + 2 + 3 + 4)));
    let balance = db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();
    assert_eq!(balance, Some(Amount::from_atoms(already_unlocked_coins)));
    // check there are no available UTXOs as all are locked
    let utxos = db_tx.get_address_available_utxos(address.as_str()).await.unwrap();
    assert_eq!(utxos.len(), already_unlocked_utxos);
    drop(db_tx);
}

#[allow(clippy::too_many_arguments)]
fn create_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    target_block_time: Duration,
    prev_block_hash: Id<GenBlock>,
    staking_sk: PrivateKey,
    vrf_sk: VRFPrivateKey,
    pool_id: PoolId,
    transactions: Vec<SignedTransaction>,
) -> Block {
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_pos_block_builder()
        .with_parent(prev_block_hash)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk.clone())
        .with_stake_pool_id(pool_id)
        .with_transactions(transactions)
        .build(&mut *rng);
    block
}

async fn sync_and_compare(
    tf: &mut TestFramework,
    block: Block,
    local_state: &mut BlockchainState<TransactionalApiServerInMemoryStorage>,
    pool_id: PoolId,
) {
    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_best_block()
        .await
        .unwrap()
        .block_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    let node_data = tf.chainstate.get_stake_pool_data(pool_id).unwrap().unwrap();

    let tx = local_state.storage().transaction_ro().await.unwrap();
    let scanner_data = tx.get_pool_data(pool_id).await.unwrap().unwrap();

    assert_eq!(node_data.staker_balance(), scanner_data.staker_balance());

    let address = Address::<Destination>::new(
        tf.chain_config(),
        scanner_data.decommission_destination().clone(),
    )
    .expect("Unable to encode destination");

    let balance = tx
        .get_address_balance(address.as_str(), CoinOrTokenId::Coin)
        .await
        .unwrap()
        .unwrap_or(Amount::ZERO);

    // address balance is not updated
    assert_eq!(balance, Amount::ZERO);

    let node_delegations = tf
        .chainstate
        .get_stake_pool_delegations_shares(pool_id)
        .unwrap()
        .unwrap_or_default();

    let scanner_delegations = tx.get_pool_delegations(pool_id).await.unwrap();

    assert_eq!(node_delegations.len(), scanner_delegations.len());

    for (id, share) in node_delegations {
        let scanner_delegation = scanner_delegations.get(&id).unwrap();
        assert_eq!(&share, scanner_delegation.balance());

        let address = Address::<Destination>::new(
            tf.chain_config(),
            scanner_delegation.spend_destination().clone(),
        )
        .expect("Unable to encode destination");

        let balance = tx
            .get_address_balance(address.as_str(), CoinOrTokenId::Coin)
            .await
            .unwrap()
            .unwrap_or(Amount::ZERO);

        // address balance is not updated
        assert_eq!(balance, Amount::ZERO);
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn check_all_destinations_are_tracked(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();

    let chain_config = Arc::clone(tf.chainstate.get_chain_config());
    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        storage
    };
    let mut local_state = BlockchainState::new(chain_config.clone(), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let target_block_time = chain_config.target_block_spacing();

    let (_priv_key, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let public_key_dest = Destination::PublicKey(pub_key.clone());
    let public_key_hash_dest = Destination::PublicKeyHash((&pub_key).into());
    let classic_multisig_dest = Destination::ClassicMultisig((&pub_key).into());
    let script_dest = Destination::ScriptHash(Id::new(H256::from_slice(&rng.gen::<[u8; 32]>())));

    let with_public_key = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        public_key_dest.clone(),
    );
    let with_public_key_hash = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        public_key_hash_dest.clone(),
    );
    let with_multisig = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        classic_multisig_dest.clone(),
    );
    let with_script = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        script_dest.clone(),
    );

    let locked_with_public_key = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        public_key_dest.clone(),
        OutputTimeLock::ForBlockCount(1),
    );
    let locked_with_public_key_hash = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        public_key_hash_dest.clone(),
        OutputTimeLock::ForBlockCount(1),
    );
    let locked_with_multisig = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        classic_multisig_dest.clone(),
        OutputTimeLock::ForBlockCount(1),
    );
    let locked_with_script = TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        script_dest.clone(),
        OutputTimeLock::ForBlockCount(1),
    );

    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                0,
            ),
            InputWitness::NoSignature(None),
        )
        // Add all different destinations
        .add_output(with_script.clone())
        .add_output(with_multisig.clone())
        .add_output(with_public_key.clone())
        .add_output(with_public_key_hash.clone())
        // Add all different destinations while locked
        .add_output(locked_with_script.clone())
        .add_output(locked_with_multisig.clone())
        .add_output(locked_with_public_key.clone())
        .add_output(locked_with_public_key_hash.clone())
        .build();

    let prev_block_hash = chain_config.genesis_block_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_block_builder()
        .with_parent(prev_block_hash)
        .with_transactions(vec![transaction])
        .build(&mut rng);

    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    let block_height = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_best_block()
        .await
        .unwrap()
        .block_height();
    local_state.scan_blocks(block_height, vec![block]).await.unwrap();

    // Check all the utxos have been added in both locked and unlocked and balance has been updated
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    for dest in [script_dest, classic_multisig_dest, public_key_dest, public_key_hash_dest] {
        let address = Address::new(&chain_config, dest.clone()).unwrap();
        let amount =
            db_tx.get_address_balance(address.as_str(), CoinOrTokenId::Coin).await.unwrap();

        assert_eq!(amount, Some(Amount::from_atoms(1)));

        let locked_amount = db_tx
            .get_address_locked_balance(address.as_str(), CoinOrTokenId::Coin)
            .await
            .unwrap();

        assert_eq!(locked_amount, Some(Amount::from_atoms(1)));

        let utxos = db_tx.get_address_all_utxos(address.as_str()).await.unwrap();
        // check we have 2 utxos one locked and one unlocked
        assert_eq!(utxos.len(), 2);
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn token_transactions_storage_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();
    let chain_config = Arc::clone(tf.chainstate.get_chain_config());

    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);
        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
        storage
    };
    let mut local_state = BlockchainState::new(chain_config.clone(), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let target_block_time = chain_config.target_block_spacing();
    let genesis_id = chain_config.genesis_block_id();
    let mut coins_amount = Amount::from_atoms(100_000_000_000_000);

    // ------------------------------------------------------------------------
    // 1. Setup: Issue a Token and Mint it
    // ------------------------------------------------------------------------
    // 1a. Issue Token
    let tx_issue = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
            common::chain::tokens::TokenIssuanceV1 {
                token_ticker: "TEST".as_bytes().to_vec(),
                number_of_decimals: 2,
                metadata_uri: "http://uri".as_bytes().to_vec(),
                total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
                authority: Destination::AnyoneCanSpend,
                is_freezable: common::chain::tokens::IsTokenFreezable::Yes,
            },
        ))))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let token_id = make_token_id(&chain_config, BlockHeight::one(), tx_issue.inputs()).unwrap();
    let tx_issue_id = tx_issue.transaction().get_id();

    let block1 = tf
        .make_block_builder()
        .with_parent(genesis_id)
        .with_transactions(vec![tx_issue.clone()])
        .build(&mut rng);
    tf.process_block(block1.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(1), vec![block1]).await.unwrap();

    // 1b. Mint Token (Account Command)
    // We mint to an address we control so we can spend it later as an input
    let nonce = AccountNonce::new(0);
    let mint_amount = Amount::from_atoms(1000);

    // Construct Mint Tx
    let token_supply_change_fee = chain_config.token_supply_change_fee(BlockHeight::one());
    eprintln!("amounts: {coins_amount:?} {token_supply_change_fee:?}");
    coins_amount = (coins_amount - token_supply_change_fee).unwrap();
    let tx_mint = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_issue_id), 1),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::AccountCommand(nonce, AccountCommand::MintTokens(token_id, mint_amount)),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_amount),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, mint_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let tx_mint_id = tx_mint.transaction().get_id();

    let best_block_id = tf.best_block_id();
    let block2 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_mint])
        .build(&mut rng);
    tf.process_block(block2.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(2), vec![block2]).await.unwrap();

    let mut token_txs = BTreeSet::new();
    token_txs.insert(tx_issue_id);
    token_txs.insert(tx_mint_id);

    // Check count: Issue(1) + Mint(1) = 2
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // ------------------------------------------------------------------------
    // 2. Token Authority Management Commands
    // ------------------------------------------------------------------------

    // Helper to create simple command txs

    let mut current_nonce = nonce.increment().unwrap();

    // 2a. Freeze Token
    let token_freeze_fee = chain_config.token_freeze_fee(BlockHeight::one());
    coins_amount = (coins_amount - token_freeze_fee).unwrap();
    let tx_freeze = create_command_tx(
        current_nonce,
        AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        tx_mint_id,
        coins_amount,
    );
    let tx_freeze_id = tx_freeze.transaction().get_id();
    current_nonce = current_nonce.increment().unwrap();

    // 2b. Unfreeze Token
    coins_amount = (coins_amount - token_freeze_fee).unwrap();
    let tx_unfreeze = create_command_tx(
        current_nonce,
        AccountCommand::UnfreezeToken(token_id),
        tx_freeze_id,
        coins_amount,
    );
    let tx_unfreeze_id = tx_unfreeze.transaction().get_id();
    current_nonce = current_nonce.increment().unwrap();

    // 2c. Change Metadata
    let token_change_metadata_uri_fee = chain_config.token_change_metadata_uri_fee();
    coins_amount = (coins_amount - token_change_metadata_uri_fee).unwrap();
    let tx_metadata = create_command_tx(
        current_nonce,
        AccountCommand::ChangeTokenMetadataUri(token_id, "http://new-uri".as_bytes().to_vec()),
        tx_unfreeze_id,
        coins_amount,
    );
    let tx_metadata_id = tx_metadata.transaction().get_id();
    current_nonce = current_nonce.increment().unwrap();

    // 2d. Change Authority
    let token_change_authority_fee = chain_config.token_change_authority_fee(BlockHeight::new(3));
    coins_amount = (coins_amount - token_change_authority_fee).unwrap();
    let (_new_auth_sk, new_auth_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let new_auth_dest = Destination::PublicKey(new_auth_pk);
    let tx_authority = create_command_tx(
        current_nonce,
        AccountCommand::ChangeTokenAuthority(token_id, new_auth_dest),
        tx_metadata_id,
        coins_amount,
    );
    let tx_authority_id = tx_authority.transaction().get_id();

    eprintln!("{tx_mint_id:?}, {tx_freeze_id:?}, {tx_unfreeze_id:?}, {tx_metadata_id:?}, {tx_authority_id}");
    // Process Block 3 with all management commands
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block3 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![
            tx_freeze.clone(),
            tx_unfreeze.clone(),
            tx_metadata.clone(),
            tx_authority.clone(),
        ])
        .build(&mut rng);
    tf.process_block(block3.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(3), vec![block3]).await.unwrap();

    token_txs.insert(tx_freeze_id);
    token_txs.insert(tx_unfreeze_id);
    token_txs.insert(tx_metadata_id);
    token_txs.insert(tx_authority_id);

    // Verify Storage: 2 previous + 4 new = 6 transactions
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // ------------------------------------------------------------------------
    // 3. Input Spending (Using Token as Input)
    // ------------------------------------------------------------------------

    // We spend the output from Block 2 (Mint) which holds tokens.
    let tx_spend = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_mint_id), 1),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, mint_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_spend_id = tx_spend.transaction().get_id();

    // Process Block 4
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block4 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_spend.clone()])
        .build(&mut rng);
    tf.process_block(block4.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(4), vec![block4]).await.unwrap();

    // Verify Storage: 6 previous + 1 spend = 7
    token_txs.insert(tx_spend_id);
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // ------------------------------------------------------------------------
    // 4. Orders (Create, Fill, Conclude)
    // ------------------------------------------------------------------------

    // 4a. Create Order
    // We want to sell our Tokens (Ask Coin, Give Token).

    // Order: Give 500 Token, Ask 500 Coins.
    let give_amount = Amount::from_atoms(500);
    let ask_amount = Amount::from_atoms(500);

    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(ask_amount),
        OutputValue::TokenV1(token_id, give_amount),
    );

    // Note: The input has 1000 tokens. We give 500 to order, keep 500 change.
    let tx_create_order = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_spend_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::CreateOrder(Box::new(order_data)))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(500)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_create_order_id = tx_create_order.transaction().get_id();
    let order_id = make_order_id(tx_create_order.inputs()).unwrap();

    // Process Block 5
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block5 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_create_order.clone()])
        .build(&mut rng);
    tf.process_block(block5.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(5), vec![block5]).await.unwrap();

    // Verify Storage: Order creation involves the token (in 'Give'), so it should be indexed.
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    // 7 prev + 1 creation = 8
    token_txs.insert(tx_create_order_id);
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // 4b. Fill Order
    // Someone fills the order by paying Coins (Ask).
    // For the Token ID index, this transaction is relevant because the Order involves the Token.
    // The code `calculate_tx_fee_and_collect_token_info` and `update_tables_from_transaction_inputs`
    // checks `OrderAccountCommand::FillOrder`, loads the order, checks currencies, and adds the tx.

    let fill_amount = Amount::from_atoms(100); // Partial fill

    coins_amount = (coins_amount - fill_amount).unwrap();
    let tx_fill = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_authority_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(order_id, fill_amount)),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_fill_id = tx_fill.transaction().get_id();

    // Process Block 6
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block6 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_fill.clone()])
        .build(&mut rng);
    tf.process_block(block6.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(6), vec![block6]).await.unwrap();

    // Verify Storage: Fill Order should be indexed for the token
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    // 8 prev + 1 fill = 9
    token_txs.insert(tx_fill_id);
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // 4c. Freeze Order
    let tx_freeze = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_fill_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id)),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_freeze_id = tx_freeze.transaction().get_id();

    // Process Block 7
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block7 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_freeze.clone()])
        .build(&mut rng);
    tf.process_block(block7.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(7), vec![block7]).await.unwrap();

    // Verify Storage: Conclude Order should be indexed for the token
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    // 9 prev + 1 freeze = 10
    token_txs.insert(tx_freeze_id);
    assert_eq!(txs, token_txs);
    drop(db_tx);

    // 4d. Conclude Order
    let tx_conclude = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx_freeze_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(80000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_conclude_id = tx_conclude.transaction().get_id();

    // Process Block 8
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block8 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_conclude.clone()])
        .build(&mut rng);
    tf.process_block(block8.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(8), vec![block8]).await.unwrap();

    // Verify Storage: Conclude Order should be indexed for the token
    let db_tx = local_state.storage().transaction_ro().await.unwrap();
    let txs = db_tx
        .get_token_transactions(token_id, 100, u64::MAX)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tx_id)
        .collect::<BTreeSet<_>>();
    // 10 prev + 1 conclude = 10
    token_txs.insert(tx_conclude_id);
    assert_eq!(txs, token_txs);
    drop(db_tx);
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn htlc_addresses_storage_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();
    let chain_config = Arc::clone(tf.chainstate.get_chain_config());

    // Initialize Storage and BlockchainState
    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);
        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
        storage
    };
    let mut local_state = BlockchainState::new(chain_config.clone(), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let target_block_time = chain_config.target_block_spacing();
    let genesis_id = chain_config.genesis_block_id();

    // Create Spend and Refund destinations
    let (spend_sk, spend_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let spend_dest = Destination::PublicKey(spend_pk.clone());

    let (refund_sk, refund_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let refund_dest = Destination::PublicKey(refund_pk.clone());

    // Construct HTLC Data
    let secret = HtlcSecret::new_from_rng(&mut rng);
    let secret_hash = secret.hash();

    let htlc_data = HashedTimelockContract {
        secret_hash,
        spend_key: spend_dest.clone(),
        refund_key: refund_dest.clone(),
        refund_timelock: OutputTimeLock::ForBlockCount(1),
    };

    // Create Transaction with 2 HTLC outputs
    let tx_fund = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Htlc(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Box::new(htlc_data.clone()),
        ))
        .add_output(TxOutput::Htlc(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Box::new(htlc_data),
        ))
        .build();

    let tx_fund_id = tx_fund.transaction().get_id();

    // Create and Process Block
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let block = tf
        .make_block_builder()
        .with_parent(genesis_id)
        .with_transactions(vec![tx_fund.clone()])
        .build(&mut rng);

    tf.process_block(block.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(1), vec![block]).await.unwrap();

    // Verify Storage
    let db_tx = local_state.storage().transaction_ro().await.unwrap();

    let expected_txs = BTreeSet::from([tx_fund_id]);

    // Check Spend Address Transactions
    let spend_address = Address::new(&chain_config, spend_dest).unwrap();
    let spend_txs = db_tx
        .get_address_transactions(spend_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(spend_txs, expected_txs);

    // Check Refund Address Transactions
    let refund_address = Address::new(&chain_config, refund_dest).unwrap();
    let refund_txs = db_tx
        .get_address_transactions(refund_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(refund_txs, expected_txs);

    let expected_utxso = BTreeSet::from([
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx_fund_id), 0),
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx_fund_id), 1),
    ]);

    let utxos = db_tx
        .get_address_available_utxos(spend_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .map(|(outpoint, _)| outpoint)
        .collect::<BTreeSet<_>>();
    assert_eq!(utxos, expected_utxso);
    let utxos = db_tx
        .get_address_available_utxos(refund_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .map(|(outpoint, _)| outpoint)
        .collect::<BTreeSet<_>>();
    assert_eq!(utxos, expected_utxso);
    drop(db_tx);

    // ------------------------------------------------------------------------
    // Block 2: Spend HTLC 1 (Using Secret)
    // ------------------------------------------------------------------------
    let input_htlc1 = TxInput::from_utxo(OutPointSourceId::Transaction(tx_fund_id), 0);

    let tx_spend_unsigned = Transaction::new(
        0,
        vec![input_htlc1.clone()],
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(900)),
            Destination::AnyoneCanSpend,
        )],
    )
    .unwrap();

    // Construct Spend Witness
    // 1. Sign the tx
    let utxo1 = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_utxo(UtxoOutPoint::new(
            OutPointSourceId::Transaction(tx_fund_id),
            0,
        ))
        .await
        .unwrap()
        .unwrap();

    let sighash = signature_hash(
        SigHashType::try_from(SigHashType::ALL).unwrap(),
        &tx_spend_unsigned,
        &[SighashInputCommitment::Utxo(Cow::Owned(utxo1.output().clone()))],
        0,
    )
    .unwrap();
    let sig = sign_public_key_spending(&spend_sk, &spend_pk, &sighash, &mut rng).unwrap();

    let auth_spend = AuthorizedHashedTimelockContractSpend::Spend(secret, sig.encode());
    let witness = InputWitness::Standard(StandardInputSignature::new(
        SigHashType::try_from(SigHashType::ALL).unwrap(),
        auth_spend.encode(),
    ));

    let tx_spend = SignedTransaction::new(tx_spend_unsigned, vec![witness]).unwrap();
    let tx_spend_id = tx_spend.transaction().get_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block2 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_spend.clone()])
        .build(&mut rng);

    tf.process_block(block2.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(2), vec![block2]).await.unwrap();

    // ------------------------------------------------------------------------
    // Block 3 & 4: Refund HTLC 2 (Using Timeout)
    // ------------------------------------------------------------------------
    // Refund requires blocks to pass. Timeout is 1 block count.
    // Input created at Block 1.
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block3 = tf.make_block_builder().with_parent(best_block_id).build(&mut rng);
    tf.process_block(block3.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(3), vec![block3]).await.unwrap();

    // Now construct Refund Tx
    let input_htlc2 = TxInput::from_utxo(OutPointSourceId::Transaction(tx_fund_id), 1);

    let tx_refund_unsigned = Transaction::new(
        0,
        vec![input_htlc2],
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(900)),
            Destination::AnyoneCanSpend,
        )],
    )
    .unwrap();

    let utxo2 = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_utxo(UtxoOutPoint::new(
            OutPointSourceId::Transaction(tx_fund_id),
            1,
        ))
        .await
        .unwrap()
        .unwrap();

    let sighash = signature_hash(
        SigHashType::try_from(SigHashType::ALL).unwrap(),
        &tx_refund_unsigned,
        &[SighashInputCommitment::Utxo(Cow::Owned(utxo2.output().clone()))],
        0,
    )
    .unwrap();
    let sig = sign_public_key_spending(&refund_sk, &refund_pk, &sighash, &mut rng).unwrap();

    let auth_refund = AuthorizedHashedTimelockContractSpend::Refund(sig.encode());
    let witness = InputWitness::Standard(StandardInputSignature::new(
        SigHashType::try_from(SigHashType::ALL).unwrap(),
        auth_refund.encode(),
    ));

    let tx_refund = SignedTransaction::new(tx_refund_unsigned, vec![witness]).unwrap();
    let tx_refund_id = tx_refund.transaction().get_id();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());
    let best_block_id = tf.best_block_id();
    let block4 = tf
        .make_block_builder()
        .with_parent(best_block_id)
        .with_transactions(vec![tx_refund.clone()])
        .build(&mut rng);

    tf.process_block(block4.clone(), BlockSource::Local).unwrap();
    local_state.scan_blocks(BlockHeight::new(4), vec![block4]).await.unwrap();

    // ------------------------------------------------------------------------
    // Verify Storage
    // ------------------------------------------------------------------------
    let db_tx = local_state.storage().transaction_ro().await.unwrap();

    let mut expected_spend_address_txs = expected_txs.clone();
    // A. Check Spend Address Transactions
    // Should see Fund Tx (because it's the spend authority in the outputs)
    expected_spend_address_txs.insert(tx_fund_id);
    // Should see Spend Tx (because it spent the input using the key)
    expected_spend_address_txs.insert(tx_spend_id);

    let spend_txs = db_tx
        .get_address_transactions(spend_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(spend_txs, expected_spend_address_txs);
    // Should NOT contain refund tx
    assert!(
        !spend_txs.contains(&tx_refund_id),
        "Spend address has refund tx"
    );

    let mut expected_refund_address_txs = expected_txs.clone();
    // B. Check Refund Address Transactions
    // Should see Fund Tx (because it's the refund authority in the outputs)
    expected_refund_address_txs.insert(tx_fund_id);
    // Should see Refund Tx (because it refunded the input using the key)
    expected_refund_address_txs.insert(tx_refund_id);
    let refund_txs = db_tx
        .get_address_transactions(refund_address.as_str())
        .await
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(refund_txs, expected_refund_address_txs);
    // Should NOT contain spend tx
    assert!(
        !refund_txs.contains(&tx_spend_id),
        "Refund address has spend tx"
    );

    let utxos = db_tx.get_address_available_utxos(spend_address.as_str()).await.unwrap();
    assert!(utxos.is_empty());
    let utxos = db_tx.get_address_available_utxos(refund_address.as_str()).await.unwrap();
    assert!(utxos.is_empty());
}

fn create_command_tx(
    nonce: AccountNonce,
    command: AccountCommand,
    last_tx_id: Id<Transaction>,
    coins_amount: Amount,
) -> SignedTransaction {
    TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(last_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::AccountCommand(nonce, command),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_amount),
            Destination::AnyoneCanSpend,
        ))
        .build()
}
