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

use chainstate_test_framework::{TestFramework, TestStore};
use common::chain::config::Builder as ConfigBuilder;
use common::primitives::Amount;
use common::{
    chain::{DelegationId, OrderId, PoolId, UtxoOutPoint},
    primitives::{Id, H256},
};
use orders_accounting::{OrderData, OrdersAccountingView};
use pos_accounting::PoSAccountingView;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tokens_accounting::TokensAccountingView;
use tx_verifier::transaction_verifier::TransactionVerifier;
use utxo::{Utxo, UtxosView};

use super::helpers::in_memory_storage_wrapper::InMemoryStorageWrapper;

struct EmptyUtxosView;

impl UtxosView for EmptyUtxosView {
    type Error = std::convert::Infallible;

    fn utxo(&self, _outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        Ok(None)
    }

    fn has_utxo(&self, _outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn best_block_hash(&self) -> Result<Id<common::chain::GenBlock>, Self::Error> {
        Ok(H256::zero().into())
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

struct EmptyAccountingView;

impl PoSAccountingView for EmptyAccountingView {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, _pool_id: PoolId) -> Result<bool, pos_accounting::Error> {
        Ok(false)
    }

    fn get_pool_balance(&self, _pool_id: PoolId) -> Result<Amount, pos_accounting::Error> {
        Ok(Amount::ZERO)
    }

    fn get_pool_data(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<pos_accounting::PoolData>, pos_accounting::Error> {
        Ok(None)
    }

    fn get_pool_delegations_shares(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<std::collections::BTreeMap<DelegationId, Amount>>, pos_accounting::Error>
    {
        Ok(None)
    }

    fn get_delegation_balance(
        &self,
        _delegation_id: DelegationId,
    ) -> Result<Amount, pos_accounting::Error> {
        Ok(Amount::ZERO)
    }

    fn get_delegation_data(
        &self,
        _delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, pos_accounting::Error> {
        Ok(None)
    }

    fn get_pool_delegation_share(
        &self,
        _pool_id: PoolId,
        _delegation_id: DelegationId,
    ) -> Result<Amount, pos_accounting::Error> {
        Ok(Amount::ZERO)
    }
}

struct EmptyTokensAccountingView;

impl TokensAccountingView for EmptyTokensAccountingView {
    type Error = tokens_accounting::Error;

    fn get_token_data(
        &self,
        _id: &common::chain::tokens::TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        Ok(None)
    }

    fn get_circulating_supply(
        &self,
        _id: &common::chain::tokens::TokenId,
    ) -> Result<Amount, Self::Error> {
        Ok(Amount::ZERO)
    }
}

struct EmptyOrdersAccountingView;

impl OrdersAccountingView for EmptyOrdersAccountingView {
    type Error = orders_accounting::Error;

    fn get_order_data(&self, _id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        Ok(None)
    }

    fn get_ask_balance(&self, _id: &OrderId) -> Result<Amount, Self::Error> {
        Ok(Amount::ZERO)
    }

    fn get_give_balance(&self, _id: &OrderId) -> Result<Amount, Self::Error> {
        Ok(Amount::ZERO)
    }
}

/// This test proves that a transaction verifier with this structure can be moved among threads
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn transfer_tx_verifier_to_thread(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let _tf = TestFramework::builder(&mut rng).with_storage(storage.clone()).build();

        let chain_config = ConfigBuilder::test_chain().build();
        let storage = InMemoryStorageWrapper::new(storage, chain_config.clone());

        let utxos = EmptyUtxosView {};
        let accounting = EmptyAccountingView {};
        let tokens_accounting = EmptyTokensAccountingView {};
        let orders_accounting = EmptyOrdersAccountingView {};

        let verifier = TransactionVerifier::new_generic(
            &storage,
            &chain_config,
            utxos,
            accounting,
            tokens_accounting,
            orders_accounting,
        );

        std::thread::scope(|s| {
            s.spawn(move || verifier.consume());
        });
    });
}
