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

use crate::{framework::BlockOutputs, key_manager::KeyManager, TestFramework};
use chainstate::{BlockIndex, GenBlockIndex};
use chainstate_storage::{BlockchainStorageRead, TipStorageTag};
use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockRewardTransactable},
        config::{create_unit_test_config, Builder as ConfigBuilder, ChainType, EpochIndex},
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        Block, ChainConfig, CoinUnit, ConsensusUpgrade, Destination, GenBlock, Genesis,
        NetUpgrades, OutPointSourceId, PoSChainConfig, PoSChainConfigBuilder, PoolId, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Compact, Id, Idable, H256},
    Uint256,
};
use consensus::find_timestamp_for_staking_impl;
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use itertools::Itertools;
use pos_accounting::{PoSAccountingDB, PoSAccountingView};
use randomness::Rng;

pub fn empty_witness(rng: &mut impl Rng) -> InputWitness {
    use randomness::SliceRandom;
    let mut msg: Vec<u8> = (1..100).collect();
    msg.shuffle(rng);
    InputWitness::NoSignature(Some(msg))
}

pub fn anyonecanspend_address() -> Destination {
    Destination::AnyoneCanSpend
}

pub fn get_output_value(output: &TxOutput) -> Option<OutputValue> {
    match output {
        TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
            Some(v.clone())
        }
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DataDeposit(_) => None,
        TxOutput::IssueNft(token_id, _, _) => {
            Some(OutputValue::TokenV1(*token_id, Amount::from_atoms(1)))
        }
    }
}

pub fn create_new_outputs(
    srcid: OutPointSourceId,
    outs: &[TxOutput],
    rng: &mut impl Rng,
) -> Vec<(InputWitness, TxInput, TxOutput)> {
    outs.iter()
        .enumerate()
        .filter_map(move |(index, output)| create_utxo_data(srcid.clone(), index, output, rng))
        .collect()
}

pub fn create_utxo_data(
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut impl Rng,
) -> Option<(InputWitness, TxInput, TxOutput)> {
    match output {
        TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) => {
            let new_output = match v {
                OutputValue::Coin(output_value) => {
                    let spent_value =
                        Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
                    let new_value = (*output_value - spent_value).unwrap();
                    utils::ensure!(new_value >= Amount::from_atoms(1));
                    TxOutput::Transfer(OutputValue::Coin(new_value), anyonecanspend_address())
                }
                OutputValue::TokenV0(_) => return None, // ignore
                OutputValue::TokenV1(token_id, output_value) => {
                    let spent_value =
                        Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
                    let new_value = (*output_value - spent_value).unwrap();
                    utils::ensure!(new_value >= Amount::from_atoms(1));
                    TxOutput::Transfer(
                        OutputValue::TokenV1(*token_id, new_value),
                        anyonecanspend_address(),
                    )
                }
            };

            Some((
                empty_witness(rng),
                TxInput::from_utxo(outsrc, index as u32),
                new_output,
            ))
        }
        TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_) => None,
    }
}

pub fn outputs_from_genesis(genesis: &Genesis) -> BlockOutputs {
    [(
        OutPointSourceId::BlockReward(genesis.get_id().into()),
        genesis.utxos().to_vec(),
    )]
    .into_iter()
    .collect()
}

pub fn outputs_from_block(blk: &Block) -> BlockOutputs {
    std::iter::once((
        OutPointSourceId::BlockReward(blk.get_id().into()),
        blk.block_reward().outputs().to_vec(),
    ))
    .chain(blk.transactions().iter().map(|tx| {
        (
            OutPointSourceId::Transaction(tx.transaction().get_id()),
            tx.transaction().outputs().to_owned(),
        )
    }))
    .collect()
}

pub fn create_chain_config_with_default_staking_pool(
    rng: &mut impl Rng,
    staking_pk: PublicKey,
    vrf_pk: VRFPublicKey,
) -> (ConfigBuilder, PoolId) {
    let stake_amount = create_unit_test_config().min_stake_pool_pledge();
    let mint_amount = Amount::from_atoms(100_000_000 * common::chain::CoinUnit::ATOMS_PER_COIN);

    let genesis_pool_id = PoolId::new(H256::random_using(rng));
    let genesis_stake_pool_data = StakePoolData::new(
        stake_amount,
        Destination::PublicKey(staking_pk.clone()),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );

    let chain_config = create_chain_config_with_staking_pool(
        rng,
        mint_amount,
        genesis_pool_id,
        genesis_stake_pool_data,
    );

    (chain_config, genesis_pool_id)
}

pub fn create_chain_config_with_staking_pool(
    rng: &mut impl Rng,
    mint_amount: Amount,
    pool_id: PoolId,
    pool_data: StakePoolData,
) -> ConfigBuilder {
    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];

    let mint_output =
        TxOutput::Transfer(OutputValue::Coin(mint_amount), Destination::AnyoneCanSpend);

    let pool = TxOutput::CreateStakePool(pool_id, Box::new(pool_data));

    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(rng.gen_range(0..1639975460)),
        vec![mint_output, pool],
    );

    let net_upgrades = NetUpgrades::initialize(upgrades).unwrap();
    ConfigBuilder::new(ChainType::Regtest)
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
}

pub fn produce_kernel_signature(
    tf: &TestFramework,
    staking_sk: &PrivateKey,
    reward_outputs: &[TxOutput],
    staking_destination: Destination,
    kernel_utxo_block_id: Id<GenBlock>,
    kernel_outpoint: UtxoOutPoint,
) -> StandardInputSignature {
    let block_outputs = tf.outputs_from_genblock(kernel_utxo_block_id);
    let utxo = match block_outputs.get(&kernel_outpoint.source_id()) {
        Some(outputs) => outputs[kernel_outpoint.output_index() as usize].clone(),
        None => {
            // if it's not in the block try find output in the utxo set
            tf.chainstate
                .utxo(&kernel_outpoint)
                .expect("ok")
                .expect("some")
                .output()
                .clone()
        }
    };

    let kernel_inputs = vec![kernel_outpoint.into()];

    let block_reward_tx =
        BlockRewardTransactable::new(Some(kernel_inputs.as_slice()), Some(reward_outputs), None);
    StandardInputSignature::produce_uniparty_signature_for_input(
        staking_sk,
        SigHashType::default(),
        staking_destination,
        &block_reward_tx,
        std::iter::once(Some(&utxo)).collect::<Vec<_>>().as_slice(),
        0,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn pos_mine(
    storage: &impl BlockchainStorageRead,
    pos_config: &PoSChainConfig,
    initial_timestamp: BlockTimestamp,
    kernel_outpoint: UtxoOutPoint,
    kernel_witness: InputWitness,
    vrf_sk: &VRFPrivateKey,
    sealed_epoch_randomness: PoSRandomness,
    pool_id: PoolId,
    final_supply: CoinUnit,
    epoch_index: EpochIndex,
    compact_target: Compact,
) -> Option<(PoSData, BlockTimestamp)> {
    let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&storage);

    let pool_balance = pos_db.get_pool_balance(pool_id).unwrap().unwrap();
    let pledge_amount = pos_db.get_pool_data(pool_id).unwrap().unwrap().staker_balance().unwrap();

    find_timestamp_for_staking_impl(
        final_supply,
        pos_config,
        &compact_target.try_into().unwrap(),
        initial_timestamp,
        initial_timestamp.add_int_seconds(1000).unwrap(),
        &sealed_epoch_randomness,
        epoch_index,
        pledge_amount,
        pool_balance,
        vrf_sk,
    )
    .unwrap()
    .map(|(timestamp, vrf_data)| {
        let pos_data = PoSData::new(
            vec![kernel_outpoint.clone().into()],
            vec![kernel_witness.clone()],
            pool_id,
            vrf_data,
            compact_target,
        );

        (pos_data, timestamp)
    })
}

#[allow(unused)]
pub fn assert_block_index_identical_to(bi1: &BlockIndex, bi2: &BlockIndex) {
    assert!(
        bi1.is_identical_to(bi2),
        "{bi1:?} should be identical to {bi2:?}"
    );
}

pub fn assert_gen_block_index_identical_to(bi1: &GenBlockIndex, bi2: &GenBlockIndex) {
    assert!(
        bi1.is_identical_to(bi2),
        "{bi1:?} should be identical to {bi2:?}"
    );
}

pub fn assert_block_index_opt_identical_to(bi1: Option<&BlockIndex>, bi2: Option<&BlockIndex>) {
    let identical = match (bi1, bi2) {
        (Some(bi1), Some(bi2)) => bi1.is_identical_to(bi2),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    assert!(identical, "{bi1:?} should be identical to {bi2:?}");
}

pub fn assert_gen_block_index_opt_identical_to(
    bi1: Option<&GenBlockIndex>,
    bi2: Option<&GenBlockIndex>,
) {
    let identical = match (bi1, bi2) {
        (Some(bi1), Some(bi2)) => bi1.is_identical_to(bi2),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    assert!(identical, "{bi1:?} should be identical to {bi2:?}");
}

pub fn sign_witnesses(
    key_manager: &KeyManager,
    chain_config: &ChainConfig,
    tx: &common::chain::Transaction,
    input_utxos: Vec<(Option<TxOutput>, Destination)>,
) -> Vec<InputWitness> {
    let input_utxos_refs = input_utxos.iter().map(|(utxo, _)| utxo.as_ref()).collect_vec();
    let witnesses = input_utxos
        .iter()
        .enumerate()
        .map(|(idx, (_, dest))| {
            key_manager
                .get_signature(dest, chain_config, tx, &input_utxos_refs, idx)
                .unwrap()
        })
        .collect();
    witnesses
}
