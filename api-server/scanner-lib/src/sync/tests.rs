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

use crate::blockchain_state::BlockchainState;

use mempool::FeeRate;
use serialization::Encode;

use super::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};

use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{
        ApiServerStorageRead, ApiServerStorageWrite, ApiServerTransactionRw, Transactional,
        UtxoLock,
    },
};

use chainstate::{BlockSource, ChainInfo};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        output_value::OutputValue,
        signature::{
            inputsig::{
                authorize_pubkey_spend::sign_pubkey_spending,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            make_token_id, NftIssuance, RPCIsTokenFrozen, RPCTokenInfo, RPCTokenTotalSupply,
            TokenId,
        },
        CoinUnit, ConsensusUpgrade, DelegationId, Destination, GenBlockId, NetUpgrades,
        OutPointSourceId, PoSChainConfigBuilder, PoolId, SignedTransaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockCount, CoinOrTokenId, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::{seq::IteratorRandom, CryptoRng, Rng},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use logging::log;
use pos_accounting::{make_delegation_id, make_pool_id};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tokio::sync::mpsc;

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
    let delegation_id = make_delegation_id(&UtxoOutPoint::new(
        OutPointSourceId::Transaction(prev_tx_id),
        0,
    ));
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
    let new_pool_id = make_pool_id(&UtxoOutPoint::new(
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
    let transaction = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(prev_tx_id), 0),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(prev_block_hash.into()), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(remaining_coins)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let sighash = signature_hash(
        SigHashType::default(),
        transaction.transaction(),
        &[Some(&coin_tx_out), Some(&from_block_output)],
        1,
    )
    .unwrap();

    let signature = sign_pubkey_spending(&staking_sk, &pk, &sighash).unwrap();

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
        .with_stake_pool(new_pool_id)
        .with_kernel_input(UtxoOutPoint::new(
            OutPointSourceId::Transaction(new_pool_tx_id),
            1,
        ))
        .with_transactions(vec![transaction])
        .build();

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
        .build();

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
    let block = tf.make_block_builder().with_parent(prev_block_hash.into()).build();

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
                &[Some(&lock_for_block_count), Some(&lock_until_height)],
                idx,
            )
            .unwrap();
            let signature = sign_pubkey_spending(&priv_key, &pub_key, &sighash).unwrap();
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
        .build();

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
                &[Some(&lock_for_sec), Some(&lock_until_time)],
                idx,
            )
            .unwrap();
            let signature = sign_pubkey_spending(&priv_key, &pub_key, &sighash).unwrap();
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
        .build();

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

fn create_block(
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
        .with_stake_pool(pool_id)
        .with_transactions(transactions)
        .build();
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
        .build();

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
#[case(test_utils::random::Seed::from_entropy(), 20, 50)]
#[tokio::test]
async fn simulation(
    #[case] seed: Seed,
    #[case] max_blocks: usize,
    #[case] max_tx_per_block: usize,
) {
    logging::init_logging();
    let mut rng = make_seedable_rng(seed);

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (config_builder, genesis_pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staking_pk, vrf_pk,
        );

    let upgrades = vec![(
        BlockHeight::new(0),
        ConsensusUpgrade::PoS {
            initial_difficulty: None,
            config: PoSChainConfigBuilder::new_for_unit_test()
                .staking_pool_spend_maturity_block_count(BlockCount::new(5))
                .build(),
        },
    )];
    let consensus_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");

    let epoch_length = NonZeroU64::new(rng.gen_range(1..10)).unwrap();
    let sealed_epoch_distance_from_tip = rng.gen_range(1..10);
    let chain_config = config_builder
        .consensus_upgrades(consensus_upgrades)
        .max_future_block_time_offset(std::time::Duration::from_secs(1_000_000))
        .epoch_length(epoch_length)
        .sealed_epoch_distance_from_tip(sealed_epoch_distance_from_tip)
        .build();
    let target_time = chain_config.target_block_spacing();
    let genesis_pool_outpoint = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);

    // Initialize original TestFramework
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.clone())
        .with_initial_time_since_genesis(target_time.as_secs())
        .with_staking_pools(BTreeMap::from_iter([(
            genesis_pool_id,
            (
                staking_sk.clone(),
                vrf_sk.clone(),
                genesis_pool_outpoint.clone(),
            ),
        )]))
        .build();

    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        storage
    };
    let mut local_state = BlockchainState::new(Arc::new(chain_config.clone()), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    let num_blocks = rng.gen_range((max_blocks / 2)..max_blocks);

    let mut utxo_outpoints = Vec::new();
    let mut staking_pools: BTreeSet<PoolId> = BTreeSet::new();
    staking_pools.insert(genesis_pool_id);

    let mut delegations = BTreeSet::new();
    let mut token_ids = BTreeSet::new();

    let mut data_per_block_height = BTreeMap::new();
    data_per_block_height.insert(
        BlockHeight::zero(),
        (
            utxo_outpoints.clone(),
            staking_pools.clone(),
            delegations.clone(),
            token_ids.clone(),
        ),
    );

    let mut tf_internal_staking_pools = BTreeMap::new();
    tf_internal_staking_pools.insert(BlockHeight::zero(), tf.staking_pools.clone());

    // Generate a random chain
    for current_height in 0..num_blocks {
        let create_reorg = rng.gen_bool(0.1);
        let height_to_continue_from = if create_reorg {
            rng.gen_range(0..=current_height)
        } else {
            current_height
        };

        tf = if create_reorg {
            let blocks = if height_to_continue_from > 0 {
                tf.chainstate
                    .get_mainchain_blocks(BlockHeight::new(1), height_to_continue_from)
                    .unwrap()
            } else {
                vec![]
            };
            let mut new_tf = TestFramework::builder(&mut rng)
                .with_chain_config(chain_config.clone())
                .with_initial_time_since_genesis(target_time.as_secs())
                .with_staking_pools(BTreeMap::from_iter([(
                    genesis_pool_id,
                    (
                        staking_sk.clone(),
                        vrf_sk.clone(),
                        genesis_pool_outpoint.clone(),
                    ),
                )]))
                .build();
            for block in blocks {
                new_tf.progress_time_seconds_since_epoch(target_time.as_secs());
                new_tf.process_block(block.clone(), BlockSource::Local).unwrap();
            }
            new_tf.staking_pools = tf_internal_staking_pools
                .get(&BlockHeight::new(height_to_continue_from as u64))
                .unwrap()
                .clone();
            new_tf.key_manager = tf.key_manager;

            (utxo_outpoints, staking_pools, delegations, token_ids) = data_per_block_height
                .get(&BlockHeight::new(height_to_continue_from as u64))
                .unwrap()
                .clone();

            new_tf
        } else {
            tf
        };

        let block_height_to_continue_from = BlockHeight::new(height_to_continue_from as u64);
        let mut prev_block_hash = tf
            .chainstate
            .get_block_id_from_height(&block_height_to_continue_from)
            .unwrap()
            .unwrap();

        for block_height_idx in 0..=(current_height - height_to_continue_from) {
            let block_height =
                BlockHeight::new((height_to_continue_from + block_height_idx) as u64);

            let mut block_builder = tf.make_pos_block_builder().with_random_staking_pool(&mut rng);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            let block = block_builder.build();
            for tx in block.transactions() {
                let new_utxos = (0..tx.inputs().len()).map(|output_index| {
                    UtxoOutPoint::new(
                        OutPointSourceId::Transaction(tx.transaction().get_id()),
                        output_index as u32,
                    )
                });
                utxo_outpoints.extend(new_utxos);

                let new_pools = tx.outputs().iter().filter_map(|out| match out {
                    TxOutput::CreateStakePool(pool_id, _) => Some(pool_id),
                    TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::IssueNft(_, _, _) => None,
                });
                staking_pools.extend(new_pools);

                let new_delegations = tx.outputs().iter().filter_map(|out| match out {
                    TxOutput::CreateDelegationId(_, _) => {
                        let input0_outpoint =
                            tx.inputs().iter().find_map(|input| input.utxo_outpoint()).unwrap();
                        Some(make_delegation_id(input0_outpoint))
                    }
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::IssueNft(_, _, _) => None,
                });
                delegations.extend(new_delegations);

                let new_tokens = tx.outputs().iter().filter_map(|out| match out {
                    TxOutput::IssueNft(_, _, _) | TxOutput::IssueFungibleToken(_) => {
                        Some(make_token_id(tx.inputs()).unwrap())
                    }
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _) => None,
                });
                token_ids.extend(new_tokens);
            }

            prev_block_hash = block.get_id().into();
            tf.process_block(block.clone(), BlockSource::Local).unwrap();

            // save current state
            tf_internal_staking_pools.insert(block_height.next_height(), tf.staking_pools.clone());
            data_per_block_height.insert(
                block_height.next_height(),
                (
                    utxo_outpoints.clone(),
                    staking_pools.clone(),
                    delegations.clone(),
                    token_ids.clone(),
                ),
            );

            local_state.scan_blocks(block_height, vec![block]).await.unwrap();
        }

        let block_height = BlockHeight::new(current_height as u64);
        let median_time = tf.chainstate.calculate_median_time_past(&prev_block_hash).unwrap();

        check_utxos(
            &tf,
            &local_state,
            &utxo_outpoints,
            median_time,
            block_height.next_height(),
        )
        .await;

        check_staking_pools(&tf, &local_state, &staking_pools).await;
        check_delegations(&tf, &local_state, &delegations).await;
        check_tokens(&tf, &local_state, &token_ids).await;
    }
}

async fn check_utxos(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    utxos: &Vec<UtxoOutPoint>,
    current_median_time: BlockTimestamp,
    current_block_height: BlockHeight,
) {
    for outpoint in utxos {
        check_utxo(
            tf,
            local_state,
            outpoint.clone(),
            current_median_time,
            current_block_height,
        )
        .await;
    }
}

async fn check_utxo(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    outpoint: UtxoOutPoint,
    current_median_time: BlockTimestamp,
    current_block_height: BlockHeight,
) {
    let c_utxo = tf.chainstate.utxo(&outpoint).unwrap();

    // if this is a locked utxo get the unlock time/height
    let unlock = c_utxo
        .as_ref()
        .and_then(|utxo| utxo.output().timelock().zip(utxo.source().blockchain_height().ok()))
        .map(|(lock, height)| {
            let block_id = tf.block_id(height.into_int());
            let utxo_block_id = block_id.classify(tf.chainstate.get_chain_config());
            let time_of_tx = match utxo_block_id {
                GenBlockId::Block(id) => {
                    tf.chainstate.get_block_header(id).unwrap().unwrap().timestamp()
                }
                GenBlockId::Genesis(_) => {
                    tf.chainstate.get_chain_config().genesis_block().timestamp()
                }
            };
            UtxoLock::from_output_lock(*lock, time_of_tx, height).into_time_and_height()
        });

    let tx = local_state.storage().transaction_ro().await.unwrap();

    // fetch the locked utxo
    let l_utxo = if let Some((unlock_time, unlock_height)) = unlock {
        tx.get_locked_utxos_until_now(
            unlock_height.unwrap_or(current_block_height),
            (
                current_median_time,
                unlock_time.unwrap_or(current_median_time),
            ),
        )
        .await
        .unwrap()
        .into_iter()
        .find_map(|(out, info)| (out == outpoint).then_some(info))
    } else {
        None
    };

    // fetch the unlocked utxo
    let s_utxo = tx.get_utxo(outpoint).await.unwrap();

    match (c_utxo, s_utxo) {
        (Some(c_utxo), Some(s_utxo)) => {
            // if utxo is in chainstate it should not be spent
            assert!(!s_utxo.spent());
            // check outputs are the same
            assert_eq!(c_utxo.output(), s_utxo.output());
        }
        (None, Some(s_utxo)) => {
            // if utxo is not found in chainstate but found in scanner it must be spent
            assert!(s_utxo.spent());
            // and not in locked utxos
            assert_eq!(l_utxo, None);
        }
        (Some(c_utxo), None) => {
            // if utxo is in chainstate but not in unlocked scanner utxos it must be in the locked
            // ones
            if let Some(l_utxo) = l_utxo {
                assert_eq!(c_utxo.output(), &l_utxo.output);
            } else {
                panic!("Utxo in chainstate but not in the scanner state");
            }
        }
        (None, None) => {
            // on reorg utxos will be gone from both chainstate and the scanner
            // same for locked
            assert_eq!(l_utxo, None);
        }
    };
}

async fn check_staking_pools(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    staking_pools: &BTreeSet<PoolId>,
) {
    for pool_id in staking_pools {
        check_pool(tf, local_state, *pool_id).await;
    }
}

async fn check_pool(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    pool_id: PoolId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let scanner_data = tx.get_pool_data(pool_id).await.unwrap().unwrap();

    if let Some(node_data) = tf.chainstate.get_stake_pool_data(pool_id).unwrap() {
        // check staker total balances are the same
        assert_eq!(node_data.staker_balance(), scanner_data.staker_balance());
        // check the pledges are the same
        assert_eq!(node_data.pledge_amount(), scanner_data.pledge_amount());
        assert_eq!(node_data, scanner_data);

        // Compare the delegation shares
        let node_delegations = tf
            .chainstate
            .get_stake_pool_delegations_shares(pool_id)
            .unwrap()
            .unwrap_or_default();

        let scanner_delegations = tx.get_pool_delegations(pool_id).await.unwrap();

        // check all delegations from the node are contained in the scanner
        for (id, share) in &node_delegations {
            let scanner_delegation = scanner_delegations.get(id).unwrap();
            // check the shares are the same
            assert_eq!(share, scanner_delegation.balance());
        }

        // delegations that have not been staked yet are stored in the scanner but not in the node
        for (id, scanner_delegation) in scanner_delegations {
            let share = node_delegations.get(&id).unwrap_or(&Amount::ZERO);
            // check the shares are the same
            assert_eq!(share, scanner_delegation.balance());
        }
    } else {
        // the pool has been decommissioned
        assert_eq!(Amount::ZERO, scanner_data.pledge_amount());
    }
}

async fn check_delegations(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    delegations: &BTreeSet<DelegationId>,
) {
    for delegation_id in delegations {
        check_delegation(tf, local_state, *delegation_id).await
    }
}

async fn check_delegation(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    delegation_id: DelegationId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let scanner_data = tx.get_delegation(delegation_id).await.unwrap().unwrap();

    if let Some(node_data) = tf.chainstate.get_stake_delegation_data(delegation_id).unwrap() {
        assert_eq!(node_data.source_pool(), scanner_data.pool_id());
        assert_eq!(
            node_data.spend_destination(),
            scanner_data.spend_destination()
        );

        // check delegation balances are the same
        let node_delegation_balance = tf
            .chainstate
            .get_stake_delegation_balance(delegation_id)
            .unwrap()
            .unwrap_or(Amount::ZERO);
        assert_eq!(node_delegation_balance, *scanner_data.balance());
    } else {
        // the pool has been decommissioned
        assert_eq!(Amount::ZERO, *scanner_data.balance());
    }
}

async fn check_tokens(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    token_ids: &BTreeSet<TokenId>,
) {
    for token_id in token_ids {
        check_token(tf, local_state, *token_id).await;
    }
}

async fn check_token(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    token_id: TokenId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let node_data = tf.chainstate.get_token_info_for_rpc(token_id).unwrap().unwrap();

    match node_data {
        RPCTokenInfo::FungibleToken(node_data) => {
            let scanner_data = tx.get_fungible_token_issuance(token_id).await.unwrap().unwrap();

            assert_eq!(node_data.authority, scanner_data.authority);
            assert_eq!(
                node_data.token_ticker.into_bytes(),
                scanner_data.token_ticker
            );
            assert_eq!(
                node_data.metadata_uri.into_bytes(),
                scanner_data.metadata_uri
            );
            assert_eq!(
                node_data.number_of_decimals,
                scanner_data.number_of_decimals
            );
            assert_eq!(
                node_data.circulating_supply,
                scanner_data.circulating_supply
            );
            assert_eq!(node_data.is_locked, scanner_data.is_locked);
            assert_eq!(node_data.frozen, RPCIsTokenFrozen::new(scanner_data.frozen));
            assert_eq!(
                node_data.total_supply,
                RPCTokenTotalSupply::from(scanner_data.total_supply)
            );
        }
        RPCTokenInfo::NonFungibleToken(node_data) => {
            let scanner_data = tx.get_nft_token_issuance(token_id).await.unwrap().unwrap();

            match scanner_data {
                NftIssuance::V0(scanner_data) => {
                    assert_eq!(
                        node_data.metadata.name.into_bytes(),
                        scanner_data.metadata.name
                    );
                    assert_eq!(
                        node_data.metadata.description.into_bytes(),
                        scanner_data.metadata.description
                    );
                    assert_eq!(
                        node_data.metadata.ticker.into_bytes(),
                        scanner_data.metadata.ticker
                    );
                    assert_eq!(
                        &node_data.metadata.icon_uri.map(|x| x.into_bytes()),
                        scanner_data.metadata.icon_uri.as_ref()
                    );
                    assert_eq!(
                        &node_data.metadata.additional_metadata_uri.map(|x| x.into_bytes()),
                        scanner_data.metadata.additional_metadata_uri.as_ref()
                    );
                    assert_eq!(
                        &node_data.metadata.media_uri.map(|x| x.into_bytes()),
                        scanner_data.metadata.media_uri.as_ref()
                    );
                    assert_eq!(
                        node_data.metadata.media_hash.into_bytes(),
                        scanner_data.metadata.media_hash
                    );
                    assert_eq!(
                        node_data.metadata.creator.map(|c| c.into_bytes()),
                        scanner_data.metadata.creator.map(|c| c.encode())
                    );
                }
            }
        }
    }
}
