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
        timelock::OutputTimeLock, AccountNonce, AccountOutPoint, AccountSpending, ConsensusUpgrade,
        Destination, NetUpgrades, OutPointSourceId, PoSChainConfig, PoSConsensusVersion, TxInput,
        TxOutput, UpgradeVersion, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Idable},
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
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(1),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    1,
                    100.into(),
                    1.into(),
                    5,
                    PerThousand::new(100).unwrap(),
                    PoSConsensusVersion::CURRENT,
                )
                .unwrap(),
            }),
        ),
        (
            BlockHeight::new(3),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    1,
                    50.into(), // decrease maturity setting
                    1.into(),
                    5,
                    PerThousand::new(100).unwrap(),
                    PoSConsensusVersion::CURRENT,
                )
                .unwrap(),
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis = create_custom_genesis_with_stake_pool(staking_pk, vrf_pk.clone());
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let target_block_time =
        chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.get());

    //
    // create a pool at height 1
    //

    let genesis_mint_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let pool_id = pos_accounting::make_pool_id(&genesis_mint_outpoint);
    let stake_amount = Amount::from_atoms(40_000_000 * common::chain::Mlt::ATOMS_PER_MLT);

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

    tf.make_pos_block_builder(&mut rng)
        .with_transactions(vec![tx])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
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
        .make_pos_block_builder(&mut rng)
        .with_transactions(vec![decommission_tx.clone()])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap_err();
    assert_eq!(
        result,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::IOPolicyError(
                chainstate::IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints,
                decommission_tx_id.into()
            )
        ))
    );

    //
    // produce some block at height 2 just to move to the next netupgrade
    //
    tf.make_pos_block_builder(&mut rng)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap();

    //
    // decommission pool again now it should pass
    //
    tf.make_pos_block_builder(&mut rng)
        .with_transactions(vec![decommission_tx])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process()
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
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(1),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    1,
                    1.into(),
                    100.into(),
                    5,
                    PerThousand::new(100).unwrap(),
                    PoSConsensusVersion::CURRENT,
                )
                .unwrap(),
            }),
        ),
        (
            BlockHeight::new(3),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    1,
                    1.into(),
                    50.into(), // decrease maturity setting
                    5,
                    PerThousand::new(100).unwrap(),
                    PoSConsensusVersion::CURRENT,
                )
                .unwrap(),
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis = create_custom_genesis_with_stake_pool(staking_pk, vrf_pk);
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let target_block_time =
        chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.get());

    //
    // create delegation
    //

    let genesis_mint_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let amount_to_delegate = Amount::from_atoms(1000);
    let pool_id = common::primitives::H256::zero().into();
    let delegation_id = pos_accounting::make_delegation_id(&genesis_mint_outpoint);

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

    tf.make_pos_block_builder(&mut rng)
        .with_transactions(vec![tx1, tx2])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap();

    //
    // try spend share at height 2 with wrong maturity setting
    //

    let tx_input_spend_from_delegation = AccountOutPoint::new(
        AccountNonce::new(0),
        AccountSpending::Delegation(delegation_id, amount_to_delegate),
    );
    let spend_share_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Account(tx_input_spend_from_delegation),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_delegate),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(50),
        ))
        .build();
    let spend_share_tx_id = spend_share_tx.transaction().get_id();

    let result = tf
        .make_pos_block_builder(&mut rng)
        .with_transactions(vec![spend_share_tx.clone()])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap_err();
    assert_eq!(
        result,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::IOPolicyError(
                chainstate::IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints,
                spend_share_tx_id.into()
            )
        ))
    );

    //
    // produce some block at height 2 just to move to the next netupgrade
    //
    tf.make_pos_block_builder(&mut rng)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap();

    //
    // spend share again now it should pass
    //
    tf.make_pos_block_builder(&mut rng)
        .with_transactions(vec![spend_share_tx])
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process()
        .unwrap();
}
