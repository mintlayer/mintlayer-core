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

use crate::detail::query::locator_tip_distances;

use super::*;
use chainstate_storage::inmemory::Store;
use common::chain::config::Builder as ChainConfigBuilder;
use common::chain::config::ChainType;
use common::chain::Destination;
use common::chain::NetUpgrades;
use common::Uint256;
use static_assertions::*;

assert_impl_all!(ChainstateInterfaceImpl<chainstate_storage::inmemory::Store>: Send);

// TODO: write tests for consensus crate
#[test]
fn process_genesis_block() {
    utils::concurrency::model(|| {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = ChainstateConfig::default();
        let chainstate_storage = Store::new_empty().unwrap();
        let time_getter = TimeGetter::default();
        let genesis_id = chain_config.genesis_block_id();

        let mut chainstate = Chainstate::new_no_genesis(
            Arc::new(chain_config),
            chainstate_config,
            chainstate_storage,
            None,
            time_getter,
        );

        chainstate.process_genesis().unwrap();
        let chainstate_ref = chainstate.make_db_tx_ro();

        // Check the genesis block is properly set up
        assert_eq!(chainstate.query().get_best_block_id().unwrap(), genesis_id);
        let genesis_index = chainstate_ref.get_gen_block_index(&genesis_id).unwrap().unwrap();
        assert_eq!(genesis_index.block_height(), BlockHeight::from(0));
        assert_eq!(genesis_index.block_id(), genesis_id);
        let block_at_0 =
            chainstate_ref.get_block_id_by_height(&BlockHeight::from(0)).unwrap().unwrap();
        assert_eq!(block_at_0, genesis_id);
        assert_eq!(genesis_index.chain_trust(), &Uint256::from_u64(0));
    });
}

#[test]
fn locator_distances() {
    let distances: Vec<i64> = locator_tip_distances().take(7).map(From::from).collect();
    assert_eq!(distances, vec![0, 1, 2, 4, 8, 16, 32]);
}

#[test]
#[should_panic(expected = "Best block ID not initialized")]
fn empty_chainstate_no_genesis() {
    utils::concurrency::model(|| {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = ChainstateConfig::default();
        let chainstate_storage = Store::new_empty().unwrap();
        let time_getter = TimeGetter::default();
        let chainstate = Chainstate::new_no_genesis(
            Arc::new(chain_config),
            chainstate_config,
            chainstate_storage,
            None,
            time_getter,
        );
        // This panics
        let _ = chainstate.query().get_best_block_id();
    })
}
