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

//! Node suitable for wallet testing as a library

#![allow(clippy::unwrap_used)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crypto::{key::PublicKey, vrf::VRFPublicKey};
use hex::FromHex;
use randomness::Rng;

use blockprod::{rpc::BlockProductionRpcServer, test_blockprod_config};
use chainstate::{
    make_chainstate, rpc::ChainstateRpcServer, ChainstateConfig,
    DefaultTransactionVerificationStrategy,
};
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{
            self, regtest::GenesisStakingSettings, regtest_options::ChainConfigOptions, ChainType,
        },
        output_value::OutputValue,
        pos_initial_difficulty,
        stakelock::StakePoolData,
        ChainConfig, ConsensusUpgrade, Destination, Genesis, NetUpgrades, PoSChainConfigBuilder,
        TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, H256},
};
use mempool::{rpc::MempoolRpcServer, MempoolConfig};
use p2p::rpc::P2pRpcServer;
use rpc::rpc_creds::RpcCreds;

pub const RPC_USERNAME: &str = "username";
pub const RPC_PASSWORD: &str = "password";

pub const MNEMONIC: &str = concat!(
    "spawn dove notice resist rigid grass load forum tobacco category motor fantasy ",
    "prison submit rescue pool panic unable enact oven trap lava floor toward",
);

pub const COLD_WALLET_MENEMONIC: &str = concat!(
    "milk idle bicycle taxi pear gold teach left broom pill close alcohol ",
    "mule medal morning shine famous like spare buzz fatigue same drift wall",
);

pub fn decode_hex<T: serialization::DecodeAll>(hex: &str) -> T {
    let bytes = Vec::from_hex(hex).expect("Hex decoding shouldn't fail");
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .expect("Decoding shouldn't fail")
}

fn create_custom_regtest_genesis(rng: &mut impl Rng) -> Genesis {
    // TODO: use coin_decimals instead of a fixed value
    const COIN: Amount = Amount::from_atoms(100_000_000_000);

    let total_amount = (COIN * 100_000_000).expect("must be valid");
    let initial_pool_amount = (COIN * 40_000).expect("must be valid");
    let mint_output_amount = (total_amount - initial_pool_amount).expect("must be valid");

    let genesis_mint_destination = decode_hex::<PublicKey>(
        "00027a9771bbb58170a0df36ed43e56490530f0f2f45b100c42f6f405af3ef21f54e",
    );
    let decommission_pub_key = decode_hex::<PublicKey>(
        // "0002ea30f3bb179c58022dcf2f4fd2c88685695f9532d6a9dd071da8d7ac1fe91a7d",
        "00035ca9a5797bb62e9adaec0911b6c431aefa1fb4628a206cfed1da04c0a55ba364",
    );
    let staker_pub_key = decode_hex::<PublicKey>(
        "0002884adf48b0b32ab3d66e1a8b46576dfacca5dd25b66603650de792de4dd2e483",
    );

    let vrf_pub_key = decode_hex::<VRFPublicKey>(
        "0020b95f66e824fc0df1ff13ba63d6727e013e1ea465cc37c2415a69cc408cf375",
    );

    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(mint_output_amount),
        Destination::PublicKey(genesis_mint_destination),
    );

    let initial_pool = TxOutput::CreateStakePool(
        H256::zero().into(),
        Box::new(StakePoolData::new(
            initial_pool_amount,
            Destination::PublicKey(staker_pub_key),
            vrf_pub_key,
            Destination::PublicKey(decommission_pub_key),
            PerThousand::new(1000).expect("must be valid"),
            Amount::ZERO,
        )),
    );

    // Must be less than the current time, otherwise block production will not work properly
    let genesis_timestamp = rng.gen_range(1685000000..1685030000);

    Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(genesis_timestamp),
        vec![mint_output, initial_pool],
    )
}

pub fn default_chain_config_options() -> ChainConfigOptions {
    ChainConfigOptions {
        chain_magic_bytes: None,
        chain_max_future_block_time_offset: None,
        software_version: None,
        chain_target_block_spacing: None,
        chain_coin_decimals: None,
        chain_emission_schedule: None,
        chain_max_block_header_size: None,
        chain_max_block_size_with_standard_txs: None,
        chain_max_block_size_with_smart_contracts: None,
        chain_initial_difficulty: None,
        chain_pos_netupgrades: None,
        chain_pos_netupgrades_v0_to_v1: None,
        chain_genesis_block_timestamp: None,
        chain_genesis_staking_settings: GenesisStakingSettings::default(),
        chain_chainstate_orders_v1_upgrade_height: None,
    }
}

pub fn create_chain_config(
    rng: &mut impl Rng,
    options: &config::regtest_options::ChainConfigOptions,
) -> ChainConfig {
    let genesis = create_custom_regtest_genesis(rng);
    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(pos_initial_difficulty(ChainType::Regtest).into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("net upgrades");

    config::regtest_options::regtest_chain_config_builder(options)
        .expect("regtest options to be valid")
        .genesis_custom(genesis)
        .consensus_upgrades(net_upgrades)
        .epoch_length(5.try_into().unwrap())
        .build()
}

pub async fn start_node(chain_config: Arc<ChainConfig>) -> (subsystem::Manager, SocketAddr) {
    let p2p_config = p2p::config::P2pConfig {
        bind_addresses: vec!["127.0.0.1:0".parse().unwrap()],

        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: common::primitives::user_agent::mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    };
    let rpc_creds = RpcCreds::basic(RPC_USERNAME, RPC_PASSWORD).unwrap();

    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let mut manager = subsystem::Manager::new("wallet-cli-test-manager");

    let chainstate_config = {
        let mut chainstate_config = ChainstateConfig::new();
        chainstate_config.max_tip_age = Duration::from_secs(60 * 60 * 24 * 365 * 100).into();
        chainstate_config
    };
    let mempool_config = MempoolConfig::new();

    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        chainstate_config,
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();

    let chainstate = manager.add_subsystem("wallet-cli-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        mempool_config,
        chainstate.clone(),
        Default::default(),
    );
    let mempool = manager.add_custom_subsystem("wallet-cli-test-mempool", |hdl| mempool.init(hdl));

    let peerdb_storage = p2p::test_helpers::peerdb_inmemory_store();
    let p2p = p2p::make_p2p(
        true,
        Arc::clone(&chain_config),
        Arc::new(p2p_config),
        chainstate.clone(),
        mempool.clone(),
        Default::default(),
        peerdb_storage,
    )
    .unwrap()
    .add_to_manager("p2p", &mut manager);

    // Block production
    let block_prod = manager.add_subsystem(
        "blockprod",
        blockprod::make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool.clone(),
            p2p.clone(),
            Default::default(),
        )
        .unwrap(),
    );

    let rpc = rpc::Builder::new(http_bind_address, Some(rpc_creds))
        .register(node_lib::rpc::init(
            manager.make_shutdown_trigger(),
            chain_config,
        ))
        .register(block_prod.clone().into_rpc())
        .register(chainstate.clone().into_rpc())
        .register(mempool.clone().into_rpc())
        .register(p2p.clone().into_rpc())
        .build()
        .await
        .unwrap();
    let rpc_http_address = *rpc.http_address();
    manager.add_subsystem("rpc", rpc);

    (manager, rpc_http_address)
}
