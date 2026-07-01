// Copyright (c) 2024 RBB S.r.l
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

use chainstate::chainstate_interface::ChainstateInterface;
use chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker;
use common::{
    chain::{
        DelegationId, Destination, PoolId, SignedTransaction, Transaction, TxOutput, UtxoOutPoint,
        make_delegation_id, output_value::OutputValue,
    },
    primitives::{Amount, Id, Idable as _},
    time_getter::TimeGetter,
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use mempool_types::{TxOptions, TxStatus, tx_origin::TxOrigin};

use crate::MempoolConfig;

use super::{Error, MemoryUsageEstimator, Mempool, TxEntry};

pub use crate::pool::tx_pool::tests::utils::*;
pub use rstest::rstest;

pub fn setup_with_chainstate(
    chainstate: Box<dyn ChainstateInterface>,
) -> Mempool<StoreMemoryUsageEstimator> {
    setup_with_chainstate_generic(chainstate, create_mempool_config(), Default::default())
}

pub fn setup_with_chainstate_generic(
    chainstate: Box<dyn ChainstateInterface>,
    mempool_config: MempoolConfig,
    clock: TimeGetter,
) -> Mempool<StoreMemoryUsageEstimator> {
    let chain_config = std::sync::Arc::clone(chainstate.get_chain_config());
    let chainstate_handle = start_chainstate(chainstate);
    Mempool::new(
        chain_config,
        mempool_config,
        chainstate_handle,
        clock,
        StoreMemoryUsageEstimator,
    )
    .unwrap()
}

pub fn fetch_status<T>(mempool: &Mempool<T>, tx_id: &Id<Transaction>) -> Option<TxStatus> {
    let in_mempool = mempool.contains_transaction(tx_id);
    let in_orphan_pool = mempool.contains_orphan_transaction(tx_id);
    match (in_mempool, in_orphan_pool) {
        (false, false) => None,
        (false, true) => Some(TxStatus::InOrphanPool),
        (true, false) => Some(TxStatus::InMempool),
        (true, true) => panic!("Transaction {tx_id} both in mempool and orphan pool"),
    }
}

impl<M: MemoryUsageEstimator> Mempool<M> {
    pub fn add_transaction_with_origin(
        &mut self,
        tx: SignedTransaction,
        origin: TxOrigin,
    ) -> Result<TxStatus, Error> {
        let options = TxOptions::default_for(origin);
        let entry = TxEntry::new(tx, self.clock().get_time(), origin, options);
        self.add_transaction(entry)
    }

    pub fn add_transaction_test(&mut self, tx: SignedTransaction) -> Result<TxStatus, Error> {
        let entry = make_test_tx_entry(self.clock(), tx);
        let result = self.add_transaction(entry)?;
        self.process_queue();
        Ok(result)
    }

    pub fn process_queue(&mut self) {
        while self.has_work() {
            self.perform_work_unit();
        }
    }
}

pub fn setup_pool_and_delegation(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    outpoint: UtxoOutPoint,
    pool_size: Amount,
    delegation_size: Amount,
) -> (PoolId, DelegationId, /*change utxo*/ UtxoOutPoint) {
    let coins_amount = tf.coin_amount_from_utxo(&outpoint);

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_staker(rng, pool_size, vrf_pk);

    let pool_id = PoolId::from_utxo(&outpoint);
    let change_amount = (coins_amount - pool_size).unwrap();
    let create_pool_tx = TransactionBuilder::new()
        .add_input(outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let create_pool_tx_id = create_pool_tx.transaction().get_id();
    let change_utxo = UtxoOutPoint::new(create_pool_tx_id.into(), 1);
    tf.make_block_builder()
        .add_transaction(create_pool_tx)
        .build_and_process(rng)
        .unwrap();

    let create_delegation_tx = TransactionBuilder::new()
        .add_input(change_utxo.into(), empty_witness(rng))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_id,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let create_delegation_tx_id = create_delegation_tx.transaction().get_id();
    let change_utxo = UtxoOutPoint::new(create_delegation_tx_id.into(), 1);
    let delegation_id = make_delegation_id(create_delegation_tx.inputs()).unwrap();

    tf.make_block_builder()
        .add_transaction(create_delegation_tx)
        .build_and_process(rng)
        .unwrap();

    let change_amount = (change_amount - delegation_size).unwrap();
    let delegate_staking_tx = TransactionBuilder::new()
        .add_input(change_utxo.into(), empty_witness(rng))
        .add_output(TxOutput::DelegateStaking(delegation_size, delegation_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(change_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();
    let change_utxo = UtxoOutPoint::new(delegate_staking_tx_id.into(), 1);

    tf.make_block_builder()
        .add_transaction(delegate_staking_tx)
        .build_and_process(rng)
        .unwrap();

    (pool_id, delegation_id, change_utxo)
}
