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

use common::chain::{block::BlockRewardTransactable, signature::Signable, Transaction, TxOutput};
use consensus::ConsensusPoSError;
use utils::ensure;

use super::error::{ConnectTransactionError, SpendStakeError};

/// Not all `TxOutput` combinations can be used in a block reward.
pub fn check_reward_inputs_outputs_purposes(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    match reward.inputs() {
        Some(inputs) => {
            let inputs_utxos = inputs
                .iter()
                .map(|input| {
                    utxo_view
                        .utxo(input.outpoint())
                        .map_err(|_| utxo::Error::ViewRead)?
                        .map(|u| u.output().clone())
                        .ok_or(ConnectTransactionError::MissingOutputOrSpent)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // the rule for single input/output boils down to that the pair should satisfy:
            // `CreateStakePool` | `ProduceBlockFromStake` -> `ProduceBlockFromStake`
            match inputs_utxos.as_slice() {
                // no inputs
                [] => Err(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::ConsensusPoSError(ConsensusPoSError::NoKernel),
                )),
                // single input
                [intput_utxo] => match intput_utxo {
                    TxOutput::Transfer(..)
                    | TxOutput::LockThenTransfer(..)
                    | TxOutput::Burn(..)
                    | TxOutput::DecommissionPool(..)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::SpendShareFromDelegation(..) => {
                        Err(ConnectTransactionError::InvalidInputTypeInReward)
                    }
                    TxOutput::CreateStakePool(..) | TxOutput::ProduceBlockFromStake(..) => {
                        let outputs =
                            reward.outputs().ok_or(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            ))?;
                        match outputs {
                            [] => Err(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            )),
                            [output] => match output {
                                TxOutput::Transfer(..)
                                | TxOutput::LockThenTransfer(..)
                                | TxOutput::Burn(..)
                                | TxOutput::CreateStakePool(..)
                                | TxOutput::DecommissionPool(..)
                                | TxOutput::CreateDelegationId(..)
                                | TxOutput::DelegateStaking(..)
                                | TxOutput::SpendShareFromDelegation(..) => {
                                    Err(ConnectTransactionError::InvalidOutputTypeInReward)
                                }
                                TxOutput::ProduceBlockFromStake(..) => Ok(()),
                            },
                            _ => Err(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::MultipleBlockRewardOutputs,
                            )),
                        }
                    }
                },
                // multiple inputs
                _ => Err(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::ConsensusPoSError(ConsensusPoSError::MultipleKernels),
                )),
            }
        }
        None => {
            // if no kernel input is present it's allowed to have multiple `LockThenTransfer` outputs
            let all_lock_then_transfer = reward
                .outputs()
                .ok_or(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::NoBlockRewardOutputs,
                ))?
                .iter()
                .all(|output| match output {
                    TxOutput::LockThenTransfer(..) => true,
                    TxOutput::Transfer(..)
                    | TxOutput::Burn(..)
                    | TxOutput::CreateStakePool(..)
                    | TxOutput::ProduceBlockFromStake(..)
                    | TxOutput::DecommissionPool(..)
                    | TxOutput::CreateDelegationId(..)
                    | TxOutput::DelegateStaking(..)
                    | TxOutput::SpendShareFromDelegation(..) => false,
                });
            ensure!(
                all_lock_then_transfer,
                ConnectTransactionError::InvalidOutputTypeInReward
            );
            Ok(())
        }
    }
}

/// Not all `TxOutput` combinations can be used in a transaction.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let inputs_utxos = tx
        .inputs()
        .iter()
        .map(|input| {
            utxo_view
                .utxo(input.outpoint())
                .map_err(|_| utxo::Error::ViewRead)?
                .map(|u| u.output().clone())
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
        })
        .collect::<Result<Vec<_>, _>>()?;

    match inputs_utxos.as_slice() {
        // no inputs
        [] => return Err(ConnectTransactionError::MissingTxInputs),
        // single input
        [input_utxo] => match tx.outputs() {
            // no outputs
            [] => { /* do nothing, it's ok to burn outputs in this way */ }
            // single output
            [output] => {
                ensure!(
                    is_valid_one_to_one_combination(input_utxo, output),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
            // multiple outputs
            _ => {
                is_valid_one_to_any_combination_for_tx(input_utxo, tx.outputs())?;
            }
        },
        // multiple inputs
        _ => {
            is_valid_any_to_any_combination_for_tx(inputs_utxos.as_slice(), tx.outputs())?;
        }
    };

    Ok(())
}

#[allow(clippy::unnested_or_patterns)]
fn is_valid_one_to_one_combination(input_utxo: &TxOutput, output: &TxOutput) -> bool {
    match (input_utxo, output) {
        | (TxOutput::Transfer(..), TxOutput::Transfer(..))
        | (TxOutput::Transfer(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::Transfer(..), TxOutput::Burn(..))
        | (TxOutput::Transfer(..), TxOutput::CreateStakePool(..))
        | (TxOutput::Transfer(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::Transfer(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::Transfer(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::Transfer(..), TxOutput::DecommissionPool(..))
        | (TxOutput::Transfer(..), TxOutput::SpendShareFromDelegation(..)) => false,
        | (TxOutput::LockThenTransfer(..), TxOutput::Transfer(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::Burn(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::CreateStakePool(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::LockThenTransfer(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::SpendShareFromDelegation(..))
        | (TxOutput::LockThenTransfer(..), TxOutput::DecommissionPool(..)) => false,
        | (TxOutput::Burn(..), _) => false,
        | (TxOutput::CreateStakePool(..), TxOutput::Transfer(..))
        | (TxOutput::CreateStakePool(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::CreateStakePool(..), TxOutput::Burn(..))
        | (TxOutput::CreateStakePool(..), TxOutput::CreateStakePool(..))
        | (TxOutput::CreateStakePool(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::CreateStakePool(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::CreateStakePool(..), TxOutput::DelegateStaking(..))
        | (TxOutput::CreateStakePool(..), TxOutput::SpendShareFromDelegation(..)) => false,
        | (TxOutput::CreateStakePool(..), TxOutput::DecommissionPool(..)) => true,
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::Transfer(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::Burn(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::CreateStakePool(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::SpendShareFromDelegation(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::DelegateStaking(..)) => false,
        | (TxOutput::ProduceBlockFromStake(..), TxOutput::DecommissionPool(..)) => true,
        | (TxOutput::DecommissionPool(..), TxOutput::Transfer(..))
        | (TxOutput::DecommissionPool(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::DecommissionPool(..), TxOutput::Burn(..))
        | (TxOutput::DecommissionPool(..), TxOutput::CreateStakePool(..))
        | (TxOutput::DecommissionPool(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::DecommissionPool(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::DecommissionPool(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::DecommissionPool(..), TxOutput::SpendShareFromDelegation(..))
        | (TxOutput::DecommissionPool(..), TxOutput::DecommissionPool(..)) => false,
        | (TxOutput::CreateDelegationId(..), _) => false,
        | (TxOutput::DelegateStaking(..), TxOutput::Transfer(..))
        | (TxOutput::DelegateStaking(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::DelegateStaking(..), TxOutput::Burn(..))
        | (TxOutput::DelegateStaking(..), TxOutput::CreateStakePool(..))
        | (TxOutput::DelegateStaking(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::DelegateStaking(..), TxOutput::DecommissionPool(..))
        | (TxOutput::DelegateStaking(..), TxOutput::CreateDelegationId(..)) => false,
        | (TxOutput::DelegateStaking(..), TxOutput::DelegateStaking(..))
        | (TxOutput::DelegateStaking(..), TxOutput::SpendShareFromDelegation(..)) => true,
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::Transfer(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::LockThenTransfer(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::Burn(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::CreateStakePool(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::CreateDelegationId(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::DelegateStaking(..)) => true,
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::ProduceBlockFromStake(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::DecommissionPool(..))
        | (TxOutput::SpendShareFromDelegation(..), TxOutput::SpendShareFromDelegation(..)) => false,
    }
}

fn is_valid_one_to_any_combination_for_tx(
    input_utxo: &TxOutput,
    outputs: &[TxOutput],
) -> Result<(), ConnectTransactionError> {
    if !is_delegation_spending(input_utxo, outputs) {
        let valid_inputs = are_inputs_valid_for_tx(std::slice::from_ref(input_utxo));
        ensure!(valid_inputs, ConnectTransactionError::InvalidInputTypeInTx);
        let valid_outputs = are_outputs_valid_for_tx(outputs);
        ensure!(
            valid_outputs,
            ConnectTransactionError::InvalidOutputTypeInTx
        );
    }
    Ok(())
}

// single DelegateStaking input; zero or one DelegateStakingOutput + any number of SpendShareFromDelegation
fn is_delegation_spending(input_utxo: &TxOutput, outputs: &[TxOutput]) -> bool {
    let delegation_input = match input_utxo {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::DecommissionPool(_, _, _, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::SpendShareFromDelegation(_, _, _, _) => false,
        TxOutput::DelegateStaking(_, _, _) => true,
    };

    let delegation_outputs_count = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::DecommissionPool(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::SpendShareFromDelegation(..) => false,
            TxOutput::DelegateStaking(..) => true,
        })
        .count();

    let spend_share_outputs_count = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::DecommissionPool(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..) => false,
            TxOutput::SpendShareFromDelegation(..) => true,
        })
        .count();

    delegation_input
        && delegation_outputs_count < 2
        && spend_share_outputs_count == outputs.len() - delegation_outputs_count
}

fn is_valid_any_to_any_combination_for_tx(
    inputs_utxos: &[TxOutput],
    outputs: &[TxOutput],
) -> Result<(), ConnectTransactionError> {
    let valid_inputs = are_inputs_valid_for_tx(inputs_utxos);
    ensure!(valid_inputs, ConnectTransactionError::InvalidInputTypeInTx);
    let valid_outputs = are_outputs_valid_for_tx(outputs);
    ensure!(
        valid_outputs,
        ConnectTransactionError::InvalidOutputTypeInTx
    );
    Ok(())
}

fn are_inputs_valid_for_tx(inputs_utxos: &[TxOutput]) -> bool {
    inputs_utxos.iter().all(|input_utxo| match input_utxo {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::DecommissionPool(..)
        | TxOutput::SpendShareFromDelegation(..) => true,
        TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => false,
    })
}

fn are_outputs_valid_for_tx(outputs: &[TxOutput]) -> bool {
    let valid_outputs_types = outputs.iter().all(|output| match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..) => true,
        TxOutput::ProduceBlockFromStake(..)
        | TxOutput::DecommissionPool(..)
        | TxOutput::SpendShareFromDelegation(..) => false,
    });

    let is_stake_pool_unique = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::DecommissionPool(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..)
            | TxOutput::SpendShareFromDelegation(..) => false,
            TxOutput::CreateStakePool(..) => true,
        })
        .count()
        < 2;

    let is_create_delegation_unique = outputs
        .iter()
        .filter(|output| match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::DecommissionPool(..)
            | TxOutput::DelegateStaking(..)
            | TxOutput::SpendShareFromDelegation(..) => false,
            TxOutput::CreateDelegationId(..) => true,
        })
        .count()
        < 2;

    valid_outputs_types && is_stake_pool_unique && is_create_delegation_unique
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use common::{
        chain::{
            block::{
                consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward, ConsensusData,
            },
            stakelock::StakePoolData,
            timelock::OutputTimeLock,
            tokens::OutputValue,
            Block, DelegationId, Destination, GenBlock, OutPoint, OutPointSourceId, PoolId,
            TxInput,
        },
        primitives::{per_thousand::PerThousand, Amount, Compact, Id, H256},
    };
    use crypto::{
        random::{seq::IteratorRandom, Rng},
        vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
    };
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};
    use utxo::{Utxo, UtxosDBInMemoryImpl};

    use super::*;

    fn transfer() -> TxOutput {
        TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)
    }

    fn burn() -> TxOutput {
        TxOutput::Burn(OutputValue::Coin(Amount::ZERO))
    }

    fn lock_then_transfer() -> TxOutput {
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::ZERO),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(1),
        )
    }

    fn stake_pool() -> TxOutput {
        let (_, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        TxOutput::CreateStakePool(Box::new(StakePoolData::new(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            vrf_pub_key,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        )))
    }

    fn produce_block() -> TxOutput {
        TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
    }

    fn decommission_pool() -> TxOutput {
        TxOutput::DecommissionPool(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            PoolId::new(H256::zero()),
            OutputTimeLock::ForBlockCount(1),
        )
    }

    fn create_delegation() -> TxOutput {
        TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
    }

    fn delegate_staking() -> TxOutput {
        TxOutput::DelegateStaking(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            DelegationId::new(H256::zero()),
        )
    }

    fn spend_share() -> TxOutput {
        TxOutput::SpendShareFromDelegation(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            DelegationId::new(H256::zero()),
            OutputTimeLock::ForBlockCount(1),
        )
    }

    fn get_random_outputs_combination(
        rng: &mut impl Rng,
        source: &[TxOutput],
        result_len: usize,
    ) -> Vec<TxOutput> {
        source
            .iter()
            .combinations_with_replacement(result_len)
            .choose(rng)
            .unwrap()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    }

    fn make_block(kernels: Vec<TxInput>, reward_outputs: Vec<TxOutput>) -> Block {
        let (sk, _) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(TranscriptAssembler::new(b"abc").finalize().into());
        Block::new(
            vec![],
            Id::<GenBlock>::new(H256::zero()),
            BlockTimestamp::from_int_seconds(0),
            ConsensusData::PoS(Box::new(PoSData::new(
                kernels,
                vec![],
                PoolId::new(H256::zero()),
                vrf_data,
                Compact(1),
            ))),
            BlockReward::new(reward_outputs),
        )
        .unwrap()
    }

    fn make_block_no_kernel(reward_outputs: Vec<TxOutput>) -> Block {
        Block::new(
            vec![],
            Id::<GenBlock>::new(H256::zero()),
            BlockTimestamp::from_int_seconds(0),
            ConsensusData::None,
            BlockReward::new(reward_outputs),
        )
        .unwrap()
    }

    fn setup(
        rng: &mut impl Rng,
        input_utxos: Vec<TxOutput>,
        outputs: Vec<TxOutput>,
    ) -> (UtxosDBInMemoryImpl, Transaction) {
        let utxos = input_utxos
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                (
                    OutPoint::new(
                        OutPointSourceId::Transaction(Id::new(H256::random_using(rng))),
                        i as u32,
                    ),
                    Utxo::new_for_mempool(output),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let inputs: Vec<TxInput> = utxos.keys().map(|outpoint| outpoint.clone().into()).collect();

        (
            UtxosDBInMemoryImpl::new(Id::<GenBlock>::new(H256::zero()), utxos),
            Transaction::new(0, inputs, outputs, 0).unwrap(),
        )
    }

    fn setup_with_random_combinations(
        rng: &mut impl Rng,
        origin_input_utxos: &[TxOutput],
        number_of_inputs: usize,
        origin_outputs: &[TxOutput],
        number_of_outputs: usize,
        extra_output: Option<TxOutput>,
    ) -> (UtxosDBInMemoryImpl, Transaction) {
        let input_utxos = get_random_outputs_combination(rng, origin_input_utxos, number_of_inputs);

        let outputs = match extra_output {
            Some(extra) => get_random_outputs_combination(rng, origin_outputs, number_of_outputs)
                .into_iter()
                .chain(std::iter::once(extra))
                .collect(),
            None => get_random_outputs_combination(rng, origin_outputs, number_of_outputs),
        };

        setup(rng, input_utxos, outputs)
    }

    #[rstest]
    #[rustfmt::skip]
    #[case(transfer(), transfer(),           Ok(()))]
    #[case(transfer(), burn(),               Ok(()))]
    #[case(transfer(), lock_then_transfer(), Ok(()))]
    #[case(transfer(), stake_pool(),         Ok(()))]
    #[case(transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(transfer(), create_delegation(),  Ok(()))]
    #[case(transfer(), delegate_staking(),   Ok(()))]
    #[case(transfer(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(burn(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(lock_then_transfer(), transfer(),           Ok(()))]
    #[case(lock_then_transfer(), burn(),               Ok(()))]
    #[case(lock_then_transfer(), lock_then_transfer(), Ok(()))]
    #[case(lock_then_transfer(), stake_pool(),         Ok(()))]
    #[case(lock_then_transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(lock_then_transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(lock_then_transfer(), create_delegation(),  Ok(()))]
    #[case(lock_then_transfer(), delegate_staking(),   Ok(()))]
    #[case(lock_then_transfer(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(stake_pool(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), decommission_pool(),  Ok(()))]
    #[case(stake_pool(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(produce_block(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), decommission_pool(),  Ok(()))]
    #[case(produce_block(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(decommission_pool(), transfer(),           Ok(()))]
    #[case(decommission_pool(), burn(),               Ok(()))]
    #[case(decommission_pool(), lock_then_transfer(), Ok(()))]
    #[case(decommission_pool(), stake_pool(),         Ok(()))]
    #[case(decommission_pool(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(decommission_pool(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(decommission_pool(), create_delegation(),  Ok(()))]
    #[case(decommission_pool(), delegate_staking(),   Ok(()))]
    #[case(decommission_pool(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(create_delegation(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(create_delegation(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(delegate_staking(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(delegate_staking(), delegate_staking(),   Ok(()))]
    #[case(delegate_staking(), spend_share(),        Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(spend_share(), transfer(),           Ok(()))]
    #[case(spend_share(), burn(),               Ok(()))]
    #[case(spend_share(), lock_then_transfer(), Ok(()))]
    #[case(spend_share(), stake_pool(),         Ok(()))]
    #[case(spend_share(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(spend_share(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(spend_share(), create_delegation(),  Ok(()))]
    #[case(spend_share(), delegate_staking(),   Ok(()))]
    #[case(spend_share(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    fn tx_one_to_one(
        #[case] input_utxo: TxOutput,
        #[case] output: TxOutput,
        #[case] result: Result<(), ConnectTransactionError>,
    ) {
        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);

        let utxo_db = UtxosDBInMemoryImpl::new(
            Id::<GenBlock>::new(H256::zero()), 
            BTreeMap::from_iter([(
                outpoint.clone(),
                Utxo::new_for_mempool(input_utxo),
            )]),
        );

        let tx = Transaction::new(0, vec![outpoint.into()], vec![output],).unwrap();
        assert_eq!(result, check_tx_inputs_outputs_purposes(&tx, &utxo_db));
    }

    // TODO: tests for 1:N, N:1 and N:M combinations need better coverage

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_one_to_many(#[case] seed: Seed) {
        let check = |inputs_utxos: &[TxOutput], outputs: &[TxOutput], expected_result| {
            let mut rng = make_seedable_rng(seed);
            let number_of_outputs = rng.gen_range(2..10);

            let extra_output = if rng.gen::<bool>() {
                None
            } else if rng.gen::<bool>() {
                Some(stake_pool())
            } else {
                Some(create_delegation())
            };

            let (utxo_db, tx) = setup_with_random_combinations(
                &mut rng,
                inputs_utxos,
                1,
                outputs,
                number_of_outputs,
                extra_output,
            );
            assert_eq!(
                check_tx_inputs_outputs_purposes(&tx, &utxo_db),
                expected_result
            );
        };

        // valid cases
        {
            let valid_inputs =
                [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
            let valid_outputs = [lock_then_transfer(), transfer(), burn()];
            check(&valid_inputs, &valid_outputs, Ok(()));
        }

        // invalid input
        let invalid_inputs =
            [stake_pool(), burn(), produce_block(), create_delegation(), delegate_staking()];
        let valid_outputs = [lock_then_transfer(), transfer(), burn()];
        check(
            &invalid_inputs,
            &valid_outputs,
            Err(ConnectTransactionError::InvalidInputTypeInTx),
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_spend_delegation(#[case] seed: Seed) {
        let inputs = [delegate_staking()];
        let outputs = [spend_share()];

        let mut rng = make_seedable_rng(seed);
        let number_of_outputs = rng.gen_range(2..10);

        let extra_output = if rng.gen::<bool>() {
            Some(delegate_staking())
        } else {
            None
        };

        let (utxo_db, tx) = setup_with_random_combinations(
            &mut rng,
            &inputs,
            1,
            &outputs,
            number_of_outputs,
            extra_output,
        );
        assert_eq!(check_tx_inputs_outputs_purposes(&tx, &utxo_db), Ok(()));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_one_to_any_invalid_outputs(#[case] seed: Seed) {
        let source_inputs = [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
        let source_valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
        let source_invalid_outputs = [produce_block(), decommission_pool()];

        let mut rng = make_seedable_rng(seed);
        let inputs = get_random_outputs_combination(&mut rng, &source_inputs, 1);

        let number_of_valid_outputs = rng.gen_range(0..10);
        let number_of_invalid_outputs = rng.gen_range(1..10);
        let outputs = get_random_outputs_combination(
            &mut rng,
            &source_valid_outputs,
            number_of_valid_outputs,
        )
        .into_iter()
        .chain(get_random_outputs_combination(
            &mut rng,
            &source_invalid_outputs,
            number_of_invalid_outputs,
        ))
        .collect();

        let (utxo_db, tx) = setup(&mut rng, inputs, outputs);
        let result = check_tx_inputs_outputs_purposes(&tx, &utxo_db).unwrap_err();
        assert_eq!(result, ConnectTransactionError::InvalidOutputTypeInTx);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_one_to_any_stake_multiple_pools(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let source_inputs = [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
        let source_valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
        let source_invalid_outputs = [stake_pool()];

        let inputs = get_random_outputs_combination(&mut rng, &source_inputs, 1);

        let number_of_valid_outputs = rng.gen_range(0..10);
        let number_of_invalid_outputs = rng.gen_range(2..10);
        let outputs = get_random_outputs_combination(
            &mut rng,
            &source_valid_outputs,
            number_of_valid_outputs,
        )
        .into_iter()
        .chain(
            get_random_outputs_combination(
                &mut rng,
                &source_invalid_outputs,
                number_of_invalid_outputs,
            )
            .into_iter(),
        )
        .collect();

        let (utxo_db, tx) = setup(&mut rng, inputs, outputs);

        let result = check_tx_inputs_outputs_purposes(&tx, &utxo_db).unwrap_err();
        assert_eq!(result, ConnectTransactionError::InvalidOutputTypeInTx);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_one_to_any_create_multiple_delegations(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let source_inputs = [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
        let source_valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
        let source_invalid_outputs = [create_delegation()];

        let inputs = get_random_outputs_combination(&mut rng, &source_inputs, 1);

        let number_of_valid_outputs = rng.gen_range(0..10);
        let number_of_invalid_outputs = rng.gen_range(2..10);
        let outputs = get_random_outputs_combination(
            &mut rng,
            &source_valid_outputs,
            number_of_valid_outputs,
        )
        .into_iter()
        .chain(
            get_random_outputs_combination(
                &mut rng,
                &source_invalid_outputs,
                number_of_invalid_outputs,
            )
            .into_iter(),
        )
        .collect();

        let (utxo_db, tx) = setup(&mut rng, inputs, outputs);

        let result = check_tx_inputs_outputs_purposes(&tx, &utxo_db).unwrap_err();
        assert_eq!(result, ConnectTransactionError::InvalidOutputTypeInTx);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_many_to_one(#[case] seed: Seed) {
        let check = |inputs_utxos: &[TxOutput], source_outputs: &[TxOutput], expected_result| {
            let mut rng = make_seedable_rng(seed);
            let number_of_inputs = rng.gen_range(2..10);
            let (utxo_db, tx) = setup_with_random_combinations(
                &mut rng,
                inputs_utxos,
                number_of_inputs,
                source_outputs,
                1,
                None,
            );
            assert_eq!(
                check_tx_inputs_outputs_purposes(&tx, &utxo_db),
                expected_result
            );
        };

        // valid cases
        let valid_inputs = [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
        let valid_outputs = [
            lock_then_transfer(),
            transfer(),
            burn(),
            stake_pool(),
            create_delegation(),
            delegate_staking(),
        ];
        check(&valid_inputs, &valid_outputs, Ok(()));

        // invalid outputs
        let invalid_outputs = [produce_block(), decommission_pool()];
        check(
            &valid_inputs,
            &invalid_outputs,
            Err(ConnectTransactionError::InvalidOutputTypeInTx),
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_many_to_many(#[case] seed: Seed) {
        let check = |source_inputs: &[TxOutput], source_outputs: &[TxOutput], expected_result| {
            let mut rng = make_seedable_rng(seed);
            let number_of_inputs = rng.gen_range(2..10);
            let number_of_outputs = rng.gen_range(2..10);

            let (utxo_db, tx) = setup_with_random_combinations(
                &mut rng,
                source_inputs,
                number_of_inputs,
                source_outputs,
                number_of_outputs,
                None,
            );
            assert_eq!(
                check_tx_inputs_outputs_purposes(&tx, &utxo_db),
                expected_result
            );
        };

        // valid cases
        let valid_inputs = [lock_then_transfer(), transfer(), decommission_pool(), spend_share()];
        let valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
        check(&valid_inputs, &valid_outputs, Ok(()));

        // invalid cases
        let invalid_inputs = [burn(), stake_pool(), produce_block(), create_delegation()];
        let invalid_outputs =
            [stake_pool(), produce_block(), decommission_pool(), create_delegation()];
        check(
            &invalid_inputs,
            &valid_outputs,
            Err(ConnectTransactionError::InvalidInputTypeInTx),
        );
        check(
            &valid_inputs,
            &invalid_outputs,
            Err(ConnectTransactionError::InvalidOutputTypeInTx),
        );
    }

    #[rstest]
    #[rustfmt::skip]
    #[case(transfer(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(transfer(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(burn(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(burn(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(lock_then_transfer(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(lock_then_transfer(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(stake_pool(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), produce_block(),      Ok(()))]
    #[case(stake_pool(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(produce_block(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), produce_block(),      Ok(()))]
    #[case(produce_block(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), create_delegation(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), delegate_staking(),   Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), spend_share(),        Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(decommission_pool(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(decommission_pool(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(create_delegation(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(create_delegation(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(delegate_staking(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(delegate_staking(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(spend_share(), transfer(),           Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), burn(),               Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), lock_then_transfer(), Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), stake_pool(),         Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), produce_block(),      Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), decommission_pool(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), create_delegation(),  Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), delegate_staking(),   Err(ConnectTransactionError::InvalidInputTypeInReward))]
    #[case(spend_share(), spend_share(),        Err(ConnectTransactionError::InvalidInputTypeInReward))]
    fn reward_one_to_one(
        #[case] input_utxo: TxOutput,
        #[case] output: TxOutput,
        #[case] result: Result<(), ConnectTransactionError>,
    ) {
        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let utxo_db = UtxosDBInMemoryImpl::new(
            Id::<GenBlock>::new(H256::zero()), 
            BTreeMap::from_iter([(
                outpoint.clone(),
                Utxo::new_for_mempool(input_utxo),
            )]),
        );

        let block = make_block(vec![outpoint.into()], vec![output]);

        assert_eq!(result, check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &utxo_db));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn reward_one_to_none(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let valid_kernels = [stake_pool(), produce_block()];

        let input = get_random_outputs_combination(&mut rng, &valid_kernels, 1)
            .into_iter()
            .next()
            .unwrap();
        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);

        let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
        let utxo_db = UtxosDBInMemoryImpl::new(
            best_block_id,
            BTreeMap::from_iter([(outpoint.clone(), Utxo::new_for_mempool(input))]),
        );

        let block = make_block(vec![outpoint.into()], vec![]);

        let res =
            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &utxo_db)
                .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::SpendStakeError(SpendStakeError::NoBlockRewardOutputs)
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn reward_none_to_any(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
        let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, BTreeMap::new());

        {
            // valid cases
            let valid_purposes = [lock_then_transfer()];

            let number_of_outputs = rng.gen_range(1..10);
            let outputs =
                get_random_outputs_combination(&mut rng, &valid_purposes, number_of_outputs);
            let block = make_block_no_kernel(outputs);

            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &utxo_db)
                .unwrap();
        }

        {
            // invalid cases
            let invalid_purposes = [
                transfer(),
                burn(),
                stake_pool(),
                produce_block(),
                decommission_pool(),
                create_delegation(),
                delegate_staking(),
                spend_share(),
            ];

            let number_of_outputs = rng.gen_range(1..10);
            let outputs =
                get_random_outputs_combination(&mut rng, &invalid_purposes, number_of_outputs);
            let block = make_block_no_kernel(outputs);

            let res =
                check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &utxo_db)
                    .unwrap_err();
            assert_eq!(res, ConnectTransactionError::InvalidOutputTypeInReward);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn reward_many_to_none(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let all_purposes = [
            lock_then_transfer(),
            transfer(),
            burn(),
            stake_pool(),
            produce_block(),
            decommission_pool(),
            create_delegation(),
            delegate_staking(),
            spend_share(),
        ];

        let number_of_outputs = rng.gen_range(2..10);
        let kernel_outputs =
            get_random_outputs_combination(&mut rng, &all_purposes, number_of_outputs)
                .into_iter()
                .enumerate()
                .map(|(i, output)| {
                    (
                        OutPoint::new(
                            OutPointSourceId::BlockReward(Id::new(H256::zero())),
                            i as u32,
                        ),
                        Utxo::new_for_mempool(output),
                    )
                })
                .collect::<BTreeMap<_, _>>();

        let inputs: Vec<TxInput> = kernel_outputs.keys().map(|k| k.clone().into()).collect();
        let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
        let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, kernel_outputs);

        let block = make_block(inputs, vec![]);

        let res =
            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &utxo_db)
                .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::SpendStakeError(SpendStakeError::ConsensusPoSError(
                ConsensusPoSError::MultipleKernels
            ))
        );
    }
}
