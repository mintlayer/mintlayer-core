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

use super::helpers::pos::create_custom_genesis_with_stake_pool;

use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{empty_witness, TestFramework, TransactionBuilder};
use common::{
    chain::{
        config::Builder as ConfigBuilder, output_value::OutputValue, stakelock::StakePoolData,
        timelock::OutputTimeLock, AccountNonce, AccountSpending, ConsensusUpgrade, DelegationId,
        Destination, NetUpgrades, OutPointSourceId, PoSChainConfigBuilder, PoolId, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{
        per_thousand::PerThousand, Amount, BlockCount, BlockHeight, CoinOrTokenId, Idable,
    },
    Uint256,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_maturity_setting_follows_netupgrade(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_block_count(BlockCount::new(100))
                    .build(),
            },
        ),
        (
            BlockHeight::new(3),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_block_count(BlockCount::new(50))
                    .build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis = create_custom_genesis_with_stake_pool(staking_pk, vrf_pk.clone());
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let target_block_time = chain_config.target_block_spacing();
    let genesis_pool_id = common::primitives::H256::zero().into();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    //
    // create a pool at height 1
    //

    let genesis_mint_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let pool_id = PoolId::from_utxo(&genesis_mint_outpoint);
    let stake_amount = Amount::from_atoms(40_000_000 * common::chain::CoinUnit::ATOMS_PER_COIN);

    let tx = TransactionBuilder::new()
        .add_input(genesis_mint_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(StakePoolData::new(
                stake_amount,
                Destination::AnyoneCanSpend,
                vrf_pk,
                Destination::AnyoneCanSpend,
                PerThousand::new(0).unwrap(),
                Amount::ZERO,
            )),
        ))
        .build();
    let create_pool_tx_id = tx.transaction().get_id();

    tf.make_pos_block_builder()
        .with_transactions(vec![tx])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    //
    // try decommission pool at height 2 with wrong maturity setting
    //
    let decommission_tx = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(create_pool_tx_id.into(), 0).into(),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(stake_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(50),
        ))
        .build();
    let decommission_tx_id = decommission_tx.transaction().get_id();

    let result = tf
        .make_pos_block_builder()
        .with_transactions(vec![decommission_tx.clone()])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap_err();
    assert_eq!(
        result,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                    CoinOrTokenId::Coin
                ),
                decommission_tx_id.into()
            )
        ))
    );

    //
    // produce some block at height 2 just to move to the next NetUpgrade
    //
    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    //
    // decommission pool again now it should pass
    //
    tf.make_pos_block_builder()
        .with_transactions(vec![decommission_tx])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_maturity_setting_follows_netupgrade(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_block_count(BlockCount::new(100))
                    .build(),
            },
        ),
        (
            BlockHeight::new(3),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test()
                    // decrease maturity setting
                    .staking_pool_spend_maturity_block_count(BlockCount::new(50))
                    .build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis = create_custom_genesis_with_stake_pool(staking_pk, vrf_pk);
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let target_block_time = chain_config.target_block_spacing();
    let genesis_pool_id = common::primitives::H256::zero().into();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    //
    // create delegation
    //

    let genesis_mint_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let amount_to_delegate = Amount::from_atoms(1000);
    let pool_id = common::primitives::H256::zero().into();
    let delegation_id = DelegationId::from_utxo(&genesis_mint_outpoint);

    let tx1 = TransactionBuilder::new()
        .add_input(genesis_mint_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amount_to_delegate),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_id,
        ))
        .build();
    let tx1_id = tx1.transaction().get_id();
    let tx2 = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(tx1_id.into(), 0).into(),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
        .build();

    tf.make_pos_block_builder()
        .with_transactions(vec![tx1, tx2])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    //
    // try spend share at height 2 with wrong maturity setting
    //

    let tx_input_spend_from_delegation = TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, amount_to_delegate),
    );
    let spend_share_tx = TransactionBuilder::new()
        .add_input(tx_input_spend_from_delegation, empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_delegate),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(50),
        ))
        .build();
    let spend_share_tx_id = spend_share_tx.transaction().get_id();

    let result = tf
        .make_pos_block_builder()
        .with_transactions(vec![spend_share_tx.clone()])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap_err();
    assert_eq!(
        result,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                    CoinOrTokenId::Coin
                ),
                spend_share_tx_id.into()
            )
        ))
    );

    //
    // produce some block at height 2 just to move to the next NetUpgrade
    //
    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    //
    // spend share again now it should pass
    //
    tf.make_pos_block_builder()
        .with_transactions(vec![spend_share_tx])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap();
}
