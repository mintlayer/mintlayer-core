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

use std::num::NonZeroU64;

use crate::{framework::BlockOutputs, TestChainstate, TestFramework};
use chainstate::chainstate_interface::ChainstateInterface;
use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockRewardTransactable},
        config::{create_unit_test_config, Builder as ConfigBuilder, ChainType, EpochIndex},
        create_unittest_pos_config,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        tokens::{TokenData, TokenTransfer},
        Block, ChainConfig, ConsensusUpgrade, Destination, GenBlock, Genesis, NetUpgrades,
        OutPointSourceId, PoolId, RequiredConsensus, TxInput, TxOutput, UpgradeVersion,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Compact, Id, Idable, H256},
    Uint256,
};
use crypto::{
    key::{PrivateKey, PublicKey},
    random::{CryptoRng, Rng},
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use test_utils::nft_utils::*;

pub fn empty_witness(rng: &mut impl Rng) -> InputWitness {
    use crypto::random::SliceRandom;
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
        | TxOutput::DelegateStaking(_, _) => None,
    }
}

pub fn create_new_outputs(
    chainstate: &TestChainstate,
    srcid: OutPointSourceId,
    outs: &[TxOutput],
    rng: &mut impl Rng,
) -> Vec<(InputWitness, TxInput, TxOutput)> {
    outs.iter()
        .enumerate()
        .filter_map(move |(index, output)| {
            create_utxo_data(chainstate, srcid.clone(), index, output, rng)
        })
        .collect()
}

pub fn create_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut impl Rng,
) -> Option<(InputWitness, TxInput, TxOutput)> {
    let new_output = match get_output_value(output)? {
        OutputValue::Coin(output_value) => {
            let spent_value = Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
            let new_value = (output_value - spent_value).unwrap();
            utils::ensure!(new_value >= Amount::from_atoms(1));
            TxOutput::Transfer(OutputValue::Coin(new_value), anyonecanspend_address())
        }
        OutputValue::Token(token_data) => match &*token_data {
            TokenData::TokenTransfer(_transfer) => {
                TxOutput::Transfer(OutputValue::Token(token_data), anyonecanspend_address())
            }
            TokenData::TokenIssuance(issuance) => {
                new_token_transfer_output(chainstate, &outsrc, issuance.amount_to_issue)
            }
            TokenData::NftIssuance(_issuance) => {
                new_token_transfer_output(chainstate, &outsrc, Amount::from_atoms(1))
            }
        },
    };

    Some((
        empty_witness(rng),
        TxInput::from_utxo(outsrc, index as u32),
        new_output,
    ))
}

/// Given an output as in input creates multiple new random outputs.
pub fn create_multiple_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut (impl Rng + CryptoRng),
) -> Option<(InputWitness, TxInput, Vec<TxOutput>)> {
    let num_outputs = rng.gen_range(1..10);
    let new_outputs = match get_output_value(output)? {
        OutputValue::Coin(output_value) => {
            let switch = rng.gen_range(0..3);
            if switch == 0 {
                // issue nft
                let min_tx_fee = chainstate.get_chain_config().token_min_issuance_fee();
                if output_value >= min_tx_fee {
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    vec![
                        TxOutput::Transfer(
                            random_nft_issuance(chainstate.get_chain_config().clone(), rng).into(),
                            Destination::AnyoneCanSpend,
                        ),
                        TxOutput::Burn(OutputValue::Coin(min_tx_fee)),
                    ]
                } else {
                    return None;
                }
            } else if switch == 1 {
                // issue token
                let min_tx_fee = chainstate.get_chain_config().token_min_issuance_fee();
                if output_value >= min_tx_fee {
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    vec![
                        TxOutput::Transfer(
                            random_token_issuance(chainstate.get_chain_config().clone(), rng)
                                .into(),
                            Destination::AnyoneCanSpend,
                        ),
                        TxOutput::Burn(OutputValue::Coin(min_tx_fee)),
                    ]
                } else {
                    return None;
                }
            } else {
                // spend the coin with multiple outputs
                (0..num_outputs)
                    .map(|_| {
                        let new_value = Amount::from_atoms(output_value.into_atoms() / num_outputs);
                        debug_assert!(new_value >= Amount::from_atoms(1));
                        TxOutput::Transfer(OutputValue::Coin(new_value), anyonecanspend_address())
                    })
                    .collect()
            }
        }
        OutputValue::Token(token_data) => match &*token_data {
            TokenData::TokenTransfer(transfer) => {
                if rng.gen::<bool>() {
                    // burn transferred tokens
                    let amount_to_burn = if transfer.amount.into_atoms() > 1 {
                        Amount::from_atoms(rng.gen_range(1..transfer.amount.into_atoms()))
                    } else {
                        transfer.amount
                    };
                    vec![TxOutput::Burn(
                        TokenTransfer {
                            token_id: transfer.token_id,
                            amount: amount_to_burn,
                        }
                        .into(),
                    )]
                } else {
                    // transfer tokens again
                    if transfer.amount.into_atoms() >= num_outputs {
                        // transfer with multiple outputs
                        (0..num_outputs)
                            .map(|_| {
                                let amount =
                                    Amount::from_atoms(transfer.amount.into_atoms() / num_outputs);
                                TxOutput::Transfer(
                                    TokenTransfer {
                                        token_id: transfer.token_id,
                                        amount,
                                    }
                                    .into(),
                                    anyonecanspend_address(),
                                )
                            })
                            .collect()
                    } else {
                        // transfer with a single output
                        vec![TxOutput::Transfer(
                            OutputValue::Token(token_data),
                            anyonecanspend_address(),
                        )]
                    }
                }
            }
            TokenData::TokenIssuance(issuance) => {
                if rng.gen::<bool>() {
                    vec![new_token_burn_output(
                        chainstate,
                        &outsrc,
                        Amount::from_atoms(rng.gen_range(1..issuance.amount_to_issue.into_atoms())),
                    )]
                } else {
                    vec![new_token_transfer_output(chainstate, &outsrc, issuance.amount_to_issue)]
                }
            }
            TokenData::NftIssuance(_issuance) => {
                if rng.gen::<bool>() {
                    vec![new_token_burn_output(chainstate, &outsrc, Amount::from_atoms(1))]
                } else {
                    vec![new_token_transfer_output(chainstate, &outsrc, Amount::from_atoms(1))]
                }
            }
        },
    };

    Some((
        empty_witness(rng),
        TxInput::from_utxo(outsrc, index as u32),
        new_outputs,
    ))
}

fn new_token_transfer_output(
    chainstate: &TestChainstate,
    outsrc: &OutPointSourceId,
    amount: Amount,
) -> TxOutput {
    TxOutput::Transfer(
        TokenTransfer {
            token_id: match outsrc {
                OutPointSourceId::Transaction(prev_tx) => {
                    chainstate.get_token_id_from_issuance_tx(prev_tx).expect("ok").expect("some")
                }
                OutPointSourceId::BlockReward(_) => {
                    panic!("cannot issue token in block reward")
                }
            },
            amount,
        }
        .into(),
        anyonecanspend_address(),
    )
}

fn new_token_burn_output(
    chainstate: &TestChainstate,
    outsrc: &OutPointSourceId,
    amount_to_burn: Amount,
) -> TxOutput {
    TxOutput::Burn(
        TokenTransfer {
            token_id: match outsrc {
                OutPointSourceId::Transaction(prev_tx) => {
                    chainstate.get_token_id_from_issuance_tx(prev_tx).expect("ok").expect("some")
                }
                OutPointSourceId::BlockReward(_) => {
                    panic!("cannot issue token in block reward")
                }
            },
            amount: amount_to_burn,
        }
        .into(),
    )
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

pub fn get_target_block_time(chain_config: &ChainConfig, block_height: BlockHeight) -> NonZeroU64 {
    match chain_config.net_upgrade().consensus_status(block_height) {
        RequiredConsensus::PoS(status) => status.get_chain_config().target_block_time(),
        RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
            unimplemented!()
        }
    }
}

pub fn create_chain_config_with_default_staking_pool(
    rng: &mut impl Rng,
    staking_pk: PublicKey,
    vrf_pk: VRFPublicKey,
) -> (ConfigBuilder, PoolId) {
    let stake_amount = create_unit_test_config().min_stake_pool_pledge();
    let mint_amount = Amount::from_atoms(100_000_000 * common::chain::Mlt::ATOMS_PER_MLT);

    let genesis_pool_id = PoolId::new(H256::random_using(rng));
    let genesis_stake_pool_data = StakePoolData::new(
        stake_amount,
        Destination::PublicKey(staking_pk.clone()),
        vrf_pk,
        Destination::PublicKey(staking_pk),
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );

    let chain_config = create_chain_config_with_staking_pool(
        mint_amount,
        genesis_pool_id,
        genesis_stake_pool_data,
    );

    (chain_config, genesis_pool_id)
}

pub fn create_chain_config_with_staking_pool(
    mint_amount: Amount,
    pool_id: PoolId,
    pool_data: StakePoolData,
) -> ConfigBuilder {
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(1),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: create_unittest_pos_config(),
            }),
        ),
    ];

    let mint_output =
        TxOutput::Transfer(OutputValue::Coin(mint_amount), Destination::AnyoneCanSpend);

    let pool = TxOutput::CreateStakePool(pool_id, Box::new(pool_data));

    let genesis_time = common::time_getter::TimeGetter::default().get_time();
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_duration_since_epoch(genesis_time),
        vec![mint_output, pool],
    );

    let net_upgrades = NetUpgrades::initialize(upgrades).unwrap();
    ConfigBuilder::new(ChainType::Regtest)
        .net_upgrades(net_upgrades)
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
    let utxo = &block_outputs.get(&kernel_outpoint.source_id()).unwrap()
        [kernel_outpoint.output_index() as usize];

    let kernel_inputs = vec![kernel_outpoint.into()];

    let block_reward_tx =
        BlockRewardTransactable::new(Some(kernel_inputs.as_slice()), Some(reward_outputs), None);
    StandardInputSignature::produce_uniparty_signature_for_input(
        staking_sk,
        SigHashType::default(),
        staking_destination,
        &block_reward_tx,
        std::iter::once(Some(utxo)).collect::<Vec<_>>().as_slice(),
        0,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn pos_mine(
    initial_timestamp: BlockTimestamp,
    kernel_outpoint: UtxoOutPoint,
    kernel_witness: InputWitness,
    vrf_sk: &VRFPrivateKey,
    sealed_epoch_randomness: PoSRandomness,
    pool_id: PoolId,
    pool_balance: Amount,
    epoch_index: EpochIndex,
    target: Compact,
) -> Option<(PoSData, BlockTimestamp)> {
    let mut timestamp = initial_timestamp;
    // FIXME: pass pledge amount as parameter
    let pledge_amount = Amount::from_atoms(1);

    for _ in 0..1000 {
        let transcript = chainstate_types::vrf_tools::construct_transcript(
            epoch_index,
            &sealed_epoch_randomness.value(),
            timestamp,
        );
        let vrf_data = vrf_sk.produce_vrf_data(transcript.into());

        let pos_data = PoSData::new(
            vec![kernel_outpoint.clone().into()],
            vec![kernel_witness.clone()],
            pool_id,
            vrf_data,
            target,
        );

        let vrf_pk = VRFPublicKey::from_private_key(vrf_sk);
        if consensus::check_pos_hash(
            epoch_index,
            &sealed_epoch_randomness,
            &pos_data,
            &vrf_pk,
            timestamp,
            pledge_amount,
            pool_balance,
        )
        .is_ok()
        {
            return Some((pos_data, timestamp));
        }

        timestamp = timestamp.add_int_seconds(1).unwrap();
    }
    None
}
