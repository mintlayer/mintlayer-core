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

use super::*;
use common::{
    chain::{
        block::consensus_data::{PoSData, PoWData},
        config::ChainType,
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        Destination, GenBlock, PoolId, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, CoinOrTokenId, Compact, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_block_reward_pow(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet).build();
    let utxo_db =
        utxo::UtxosDBInMemoryImpl::new(Id::<GenBlock>::new(H256::zero()), BTreeMap::new());

    let block_id = Id::<Block>::new(H256::zero());
    let block_height = BlockHeight::new(1);
    let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));
    let subsidy = chain_config.block_subsidy_at_height(&block_height);

    let check = |output_value| {
        let outputs = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(output_value),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(1),
        )];
        let block_reward = BlockRewardTransactable::new(None, Some(&outputs), None);
        check_reward_inputs_outputs_policy(
            &chain_config,
            &utxo_db,
            block_reward,
            block_id,
            block_height,
            &ConsensusData::PoW(Box::new(PoWData::new(Compact(1), 1))),
            fee,
        )
    };

    let expected_output_value = (fee.0 + subsidy).unwrap();

    // invalid case min case
    {
        let invalid_output_value = (expected_output_value + Amount::from_atoms(1)).unwrap();
        let result = check(invalid_output_value);
        assert_eq!(
            result.unwrap_err(),
            ConnectTransactionError::ConstrainedValueAccumulatorError(
                constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                block_id.into()
            )
        );
    }

    // invalid random case
    {
        let invalid_output_value =
            Amount::from_atoms(rng.gen_range((expected_output_value.into_atoms() + 1)..u128::MAX));
        let result = check(invalid_output_value);
        assert_eq!(
            result.unwrap_err(),
            ConnectTransactionError::ConstrainedValueAccumulatorError(
                constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                block_id.into()
            )
        );
    }

    // valid max case
    {
        let result = check(expected_output_value);
        assert_eq!(result, Ok(()));
    }

    // valid random case
    {
        let valid_output_value =
            Amount::from_atoms(rng.gen_range(0..expected_output_value.into_atoms()));
        let result = check(valid_output_value);
        assert_eq!(result, Ok(()));
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_block_reward_pos(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet).build();

    let pool_id = PoolId::new(H256::zero());
    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let pledge_amount = Amount::from_atoms(rng.gen_range(0..100_000));
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let vrf_data = vrf_sk.produce_vrf_data(VRFTranscript::new(b"abc"));
    let stake_pool_data = StakePoolData::new(
        pledge_amount,
        Destination::AnyoneCanSpend,
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(0).unwrap(),
        Amount::ZERO,
    );
    let input_utxo = TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data.clone()));
    let utxo_db = utxo::UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(outpoint.clone(), utxo::Utxo::new_for_mempool(input_utxo))]),
    );

    let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));

    let inputs = vec![outpoint.into()];
    let outputs = vec![TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id)];
    let block_reward = BlockRewardTransactable::new(Some(&inputs), Some(&outputs), None);
    check_reward_inputs_outputs_policy(
        &chain_config,
        &utxo_db,
        block_reward,
        Id::<Block>::new(H256::zero()),
        BlockHeight::new(1),
        &ConsensusData::PoS(Box::new(PoSData::new(
            vec![],
            vec![],
            pool_id,
            vrf_data,
            Compact(1),
        ))),
        fee,
    )
    .unwrap();
}

// Check that if different pool ids are used for inputs and outputs an error is produced.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_block_reward_pos_pool_id_mismatch(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet).build();

    let pool_id_1 = PoolId::new(H256::random_using(&mut rng));
    let pool_id_2 = PoolId::new(H256::random_using(&mut rng));

    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let pledge_amount_1 = Amount::from_atoms(rng.gen_range(0..100_000));
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let vrf_data = vrf_sk.produce_vrf_data(VRFTranscript::new(b"abc"));
    let stake_pool_data_1 = StakePoolData::new(
        pledge_amount_1,
        Destination::AnyoneCanSpend,
        vrf_pk.clone(),
        Destination::AnyoneCanSpend,
        PerThousand::new(0).unwrap(),
        Amount::ZERO,
    );
    let input_utxo = TxOutput::CreateStakePool(pool_id_1, Box::new(stake_pool_data_1.clone()));
    let utxo_db = utxo::UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(outpoint.clone(), utxo::Utxo::new_for_mempool(input_utxo))]),
    );

    let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));

    let inputs = vec![outpoint.into()];
    let outputs = vec![TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id_2)];
    let block_reward = BlockRewardTransactable::new(Some(&inputs), Some(&outputs), None);
    let result = check_reward_inputs_outputs_policy(
        &chain_config,
        &utxo_db,
        block_reward,
        Id::<Block>::new(H256::zero()),
        BlockHeight::new(1),
        &ConsensusData::PoS(Box::new(PoSData::new(
            vec![],
            vec![],
            pool_id_1,
            vrf_data,
            Compact(1),
        ))),
        fee,
    )
    .unwrap_err();

    assert_eq!(
        result,
        ConnectTransactionError::SpendStakeError(SpendStakeError::StakePoolIdMismatch(
            pool_id_1, pool_id_2
        ))
    )
}
