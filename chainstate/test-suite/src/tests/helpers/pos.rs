// Copyright (c) 2021-2022 RBB S.r.l
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

use std::{borrow::Cow, num::NonZeroU64};

use chainstate::ChainstateConfig;
use chainstate_test_framework::{
    TestFramework, TransactionBuilder, calculate_new_pos_compact_target,
    create_stake_pool_data_with_all_reward_to_staker, empty_witness,
};
use common::{
    Uint256,
    chain::{
        ChainConfig, CoinUnit, ConsensusUpgrade, Destination, Genesis, NetUpgrades,
        OutPointSourceId, PoSChainConfig, PoSChainConfigBuilder, PoolId, RequiredConsensus,
        TxOutput, UtxoOutPoint,
        block::BlockRewardTransactable,
        config::Builder as ConfigBuilder,
        signature::{
            inputsig::standard_signature::StandardInputSignature,
            sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
        },
        stakelock::StakePoolData,
    },
    primitives::{BlockHeight, Compact, Idable as _},
};
use consensus::ConsensusPoSError;
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::VRFPublicKey,
};
use randomness::CryptoRng;
use utils::const_nz_u64;

// It's important to have short epoch length, so that genesis and the first block can seal
// an epoch with pool, which is required for PoS validation to work.
pub const TEST_EPOCH_LENGTH: NonZeroU64 = const_nz_u64!(2);
pub const TEST_SEALED_EPOCH_DISTANCE: usize = 0;

pub const MIN_DIFFICULTY: Uint256 = Uint256::MAX;

pub fn calculate_new_target(
    tf: &TestFramework,
    block_height: BlockHeight,
) -> Result<Compact, ConsensusPoSError> {
    calculate_new_pos_compact_target(tf, block_height, &tf.best_block_id())
}

pub fn create_custom_genesis_with_stake_pool(
    staker_pk: PublicKey,
    vrf_pk: VRFPublicKey,
) -> Genesis {
    let initial_amount = CoinUnit::from_coins(100_000_000).to_amount_atoms();
    let initial_pool_amount = (initial_amount / 3).unwrap();
    let initial_mint_amount = (initial_amount - initial_pool_amount).unwrap();

    chainstate_test_framework::create_custom_genesis_with_stake_pool(
        staker_pk,
        vrf_pk,
        initial_mint_amount,
        initial_pool_amount,
    )
}

/// The height of the first PoS block in chains built by these helpers: the
/// stake-pool block sits at height 1, so the PoS (seal) blocks live at height 2.
pub const FIRST_POS_BLOCK_HEIGHT: BlockHeight = BlockHeight::new(2);

pub fn consensus_upgrades_with_pos_at_height(height: BlockHeight) -> NetUpgrades<ConsensusUpgrade> {
    NetUpgrades::initialize(vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            height,
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(MIN_DIFFICULTY.into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ])
    .unwrap()
}

pub fn add_block_with_stake_pool(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    stake_pool_data: StakePoolData,
) -> (UtxoOutPoint, PoolId) {
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id = PoolId::from_utxo(&genesis_outpoint);
    let tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .build();
    let tx_id = tx.transaction().get_id();

    tf.make_block_builder().add_transaction(tx).build_and_process(rng).unwrap();

    tf.progress_time_seconds_since_epoch(1);

    (
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0),
        pool_id,
    )
}

/// Create a chain genesis <- block_1, where block_1 has a tx with a StakePool output.
pub fn setup_chain_with_stake_pool(
    rng: &mut impl CryptoRng,
    vrf_pk: VRFPublicKey,
) -> (TestFramework, UtxoOutPoint, PoolId, PrivateKey) {
    setup_chain_with_stake_pool_with_chainstate_config(rng, vrf_pk, ChainstateConfig::default())
}

/// Same as `setup_chain_with_stake_pool`, but with a custom chainstate configuration.
pub fn setup_chain_with_stake_pool_with_chainstate_config(
    rng: &mut impl CryptoRng,
    vrf_pk: VRFPublicKey,
    chainstate_config: ChainstateConfig,
) -> (TestFramework, UtxoOutPoint, PoolId, PrivateKey) {
    let net_upgrades = consensus_upgrades_with_pos_at_height(FIRST_POS_BLOCK_HEIGHT);
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();

    let mut tf = TestFramework::builder(rng)
        .with_chain_config(chain_config)
        .with_chainstate_config(chainstate_config)
        .build();

    let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
        rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk,
    );
    let (stake_pool_outpoint, pool_id) = add_block_with_stake_pool(rng, &mut tf, stake_pool_data);

    (tf, stake_pool_outpoint, pool_id, staking_sk)
}

pub fn produce_kernel_signature(
    rng: &mut impl CryptoRng,
    tf: &TestFramework,
    staking_sk: &PrivateKey,
    reward_outputs: &[TxOutput],
    staking_destination: Destination,
    kernel_outpoint: UtxoOutPoint,
) -> StandardInputSignature {
    let kernel_input_utxo = tf.utxo(&kernel_outpoint).take_output();
    let kernel_inputs = vec![kernel_outpoint.into()];

    let block_reward_tx =
        BlockRewardTransactable::new(Some(kernel_inputs.as_slice()), Some(reward_outputs), None);
    StandardInputSignature::produce_uniparty_signature_for_input(
        staking_sk,
        SigHashType::default(),
        staking_destination,
        &block_reward_tx,
        &[SighashInputCommitment::Utxo(Cow::Borrowed(&kernel_input_utxo))],
        0,
        rng,
    )
    .unwrap()
}

pub fn get_pos_chain_config(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> PoSChainConfig {
    match chain_config.consensus_upgrades().consensus_status(block_height) {
        RequiredConsensus::PoS(status) => status.get_chain_config().clone(),
        status @ (RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus) => {
            panic!("Invalid consensus at height {block_height}: {status:?}")
        }
    }
}
