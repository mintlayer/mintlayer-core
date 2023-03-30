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

pub fn check_reward_inputs_outputs_purposes(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    match reward.inputs() {
        Some(inputs) => {
            let inputs = inputs
                .iter()
                .map(|input| {
                    utxo_view
                        .utxo(input.outpoint())
                        .map_err(|_| utxo::Error::ViewRead)?
                        .map(|u| u.output().clone())
                        .ok_or(ConnectTransactionError::MissingOutputOrSpent)
                })
                .collect::<Result<Vec<_>, _>>()?;

            match inputs.as_slice() {
                // no inputs
                [] => Err(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::ConsensusPoSError(ConsensusPoSError::NoKernel),
                )),
                // single input
                [input] => match input {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::Burn(_)
                    | TxOutput::DecommissionPool(_, _, _, _) => {
                        Err(ConnectTransactionError::InvalidOutputTypeInReward)
                    }
                    TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
                        let outputs =
                            reward.outputs().ok_or(ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            ))?;
                        ensure!(
                            outputs.len() != 0,
                            ConnectTransactionError::SpendStakeError(
                                SpendStakeError::NoBlockRewardOutputs,
                            )
                        );
                        ensure!(
                            outputs.len() == 1,
                            ConnectTransactionError::SpendStakeError(
                                SpendStakeError::MultipleBlockRewardOutputs,
                            )
                        );
                        match outputs.first().expect("nonempty") {
                            TxOutput::Transfer(_, _)
                            | TxOutput::LockThenTransfer(_, _, _)
                            | TxOutput::Burn(_)
                            | TxOutput::StakePool(_) => {
                                Err(ConnectTransactionError::InvalidOutputTypeInReward)
                            }
                            TxOutput::ProduceBlockFromStake(_, _, _)
                            | TxOutput::DecommissionPool(_, _, _, _) => Ok(()),
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
            let all_lock_then_transfer = reward
                .outputs()
                .ok_or(ConnectTransactionError::SpendStakeError(
                    SpendStakeError::NoBlockRewardOutputs,
                ))?
                .iter()
                .all(|output| match output {
                    TxOutput::LockThenTransfer(_, _, _) => true,
                    TxOutput::Transfer(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::StakePool(_)
                    | TxOutput::ProduceBlockFromStake(_, _, _)
                    | TxOutput::DecommissionPool(_, _, _, _) => false,
                });
            ensure!(
                all_lock_then_transfer,
                ConnectTransactionError::InvalidOutputTypeInReward
            );
            Ok(())
        }
    }
}

#[rustfmt::skip]
#[allow(clippy::unnested_or_patterns)]
pub fn is_valid_one_to_one_combination(input: &TxOutput, output: &TxOutput) -> bool {
    match (input, output){
        (TxOutput::Transfer(_, _), TxOutput::Transfer(_, _)) |
        (TxOutput::Transfer(_, _), TxOutput::LockThenTransfer(_, _, _)) |
        (TxOutput::Transfer(_, _), TxOutput::Burn(_)) |
        (TxOutput::Transfer(_, _), TxOutput::StakePool(_)) => true,
        (TxOutput::Transfer(_, _), TxOutput::ProduceBlockFromStake(_, _, _)) |
        (TxOutput::Transfer(_, _), TxOutput::DecommissionPool(_, _, _, _)) => false,
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::Transfer(_, _)) |
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::LockThenTransfer(_, _, _)) |
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::Burn(_)) |
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::StakePool(_)) => true,
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::ProduceBlockFromStake(_, _, _)) |
        (TxOutput::LockThenTransfer(_, _, _), TxOutput::DecommissionPool(_, _, _, _)) => false,
        (TxOutput::Burn(_), _) => false,
        (TxOutput::StakePool(_), TxOutput::Transfer(_, _)) |
        (TxOutput::StakePool(_), TxOutput::LockThenTransfer(_, _, _)) |
        (TxOutput::StakePool(_), TxOutput::Burn(_)) |
        (TxOutput::StakePool(_), TxOutput::StakePool(_)) |
        (TxOutput::StakePool(_), TxOutput::ProduceBlockFromStake(_, _, _)) => false,
        (TxOutput::StakePool(_), TxOutput::DecommissionPool(_, _, _, _)) => true,
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::Transfer(_, _)) |
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::LockThenTransfer(_, _, _)) |
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::Burn(_)) |
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::StakePool(_)) |
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::ProduceBlockFromStake(_, _, _)) => false,
        (TxOutput::ProduceBlockFromStake(_, _, _), TxOutput::DecommissionPool(_, _, _, _)) => true,
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::Transfer(_, _)) |
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::LockThenTransfer(_, _, _)) |
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::Burn(_)) |
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::StakePool(_)) => true,
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::ProduceBlockFromStake(_, _, _)) |
        (TxOutput::DecommissionPool(_, _, _, _), TxOutput::DecommissionPool(_, _, _, _)) => false,
    }
}

pub fn is_valid_many_to_one_combination(inputs: &[TxOutput], output: &TxOutput) -> bool {
    let valid_inputs = inputs.iter().all(|input| match input {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::DecommissionPool(_, _, _, _) => true,
        TxOutput::Burn(_) | TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
            false
        }
    });

    let valid_output = match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::StakePool(_) => true,
        TxOutput::ProduceBlockFromStake(_, _, _) | TxOutput::DecommissionPool(_, _, _, _) => false,
    };

    valid_inputs && valid_output
}

pub fn is_valid_one_to_many_combination(input: &TxOutput, outputs: &[TxOutput]) -> bool {
    let valid_input = match input {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::DecommissionPool(_, _, _, _) => true,
        TxOutput::Burn(_) | TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
            false
        }
    };

    let valid_outputs = outputs.iter().all(|output| match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::StakePool(_) => true,
        TxOutput::ProduceBlockFromStake(_, _, _) | TxOutput::DecommissionPool(_, _, _, _) => false,
    });

    valid_input && valid_outputs
}

pub fn is_valid_many_to_many_combination(inputs: &[TxOutput], outputs: &[TxOutput]) -> bool {
    let valid_inputs = inputs.iter().all(|input| match input {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::DecommissionPool(_, _, _, _) => true,
        TxOutput::Burn(_) | TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
            false
        }
    });

    let valid_outputs = outputs.iter().all(|output| match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::StakePool(_) => true,
        TxOutput::ProduceBlockFromStake(_, _, _) | TxOutput::DecommissionPool(_, _, _, _) => false,
    });

    valid_inputs && valid_outputs
}

/// Not all `OutputPurposes` combinations can be used in a transaction.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let inputs = tx
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

    match inputs.as_slice() {
        // no inputs
        [] => return Err(ConnectTransactionError::MissingTxInputs),
        // single input
        [input] => match tx.outputs() {
            // no inputs
            [] => { /* do nothing */ }
            // single input
            [output] => {
                ensure!(
                    is_valid_one_to_one_combination(input, output),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
            // multiple inputs
            _ => {
                ensure!(
                    is_valid_one_to_many_combination(input, tx.outputs()),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
        },
        // multiple inputs
        _ => match tx.outputs() {
            // no inputs
            [] => { /* do nothing */ }
            // single input
            [output] => {
                ensure!(
                    is_valid_many_to_one_combination(inputs.as_slice(), output),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
            // multiple inputs
            _ => {
                ensure!(
                    is_valid_many_to_many_combination(inputs.as_slice(), tx.outputs()),
                    ConnectTransactionError::InvalidOutputTypeInTx
                );
            }
        },
    };

    Ok(())
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
            Block, Destination, GenBlock, OutPoint, OutPointSourceId, PoolId, TxInput,
        },
        primitives::{Amount, Compact, Id, H256},
    };
    use crypto::{
        random::Rng,
        vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
    };
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};
    use utxo::Utxo;

    use super::*;

    mockall::mock! {
        pub UtxoView{}

        impl utxo::UtxosView for UtxoView {
            type Error = utxo::Error;

            fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, utxo::Error>;
            fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool, utxo::Error>;
            fn best_block_hash(&self) -> Result<Id<GenBlock>, utxo::Error>;
            fn estimated_size(&self) -> Option<usize>;
        }
    }

    pub fn transfer() -> TxOutput {
        TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)
    }

    pub fn burn() -> TxOutput {
        TxOutput::Burn(OutputValue::Coin(Amount::ZERO))
    }

    pub fn lock_then_transfer() -> TxOutput {
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::ZERO),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(1),
        )
    }

    pub fn stake_pool() -> TxOutput {
        let (_, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        TxOutput::StakePool(Box::new(StakePoolData::new(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            vrf_pub_key,
            Destination::AnyoneCanSpend,
            0,
            Amount::ZERO,
        )))
    }

    pub fn produce_block() -> TxOutput {
        TxOutput::ProduceBlockFromStake(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            PoolId::new(H256::zero()),
        )
    }

    pub fn decommission_pool() -> TxOutput {
        TxOutput::DecommissionPool(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            PoolId::new(H256::zero()),
            OutputTimeLock::ForBlockCount(1),
        )
    }

    fn get_random_outputs(
        rng: &mut impl Rng,
        source: &[TxOutput],
        result_len: usize,
    ) -> Vec<TxOutput> {
        let all_combinations =
            source.iter().combinations_with_replacement(result_len).collect::<Vec<_>>();
        let all_combinations_len = all_combinations.len();

        all_combinations
            .into_iter()
            .nth(rng.gen_range(0..all_combinations_len))
            .unwrap()
            .into_iter()
            .map(|output| output.clone())
            .collect::<Vec<_>>()
    }

    #[rstest]
    #[rustfmt::skip]
    #[case(transfer(), transfer(),           Ok(()))]
    #[case(transfer(), burn(),               Ok(()))]
    #[case(transfer(), lock_then_transfer(), Ok(()))]
    #[case(transfer(), stake_pool(),         Ok(()))]
    #[case(transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(burn(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(burn(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(lock_then_transfer(), transfer(),           Ok(()))]
    #[case(lock_then_transfer(), burn(),               Ok(()))]
    #[case(lock_then_transfer(), lock_then_transfer(), Ok(()))]
    #[case(lock_then_transfer(), stake_pool(),         Ok(()))]
    #[case(lock_then_transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(lock_then_transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(stake_pool(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(stake_pool(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(produce_block(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(produce_block(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(decommission_pool(), transfer(),           Ok(()))]
    #[case(decommission_pool(), burn(),               Ok(()))]
    #[case(decommission_pool(), lock_then_transfer(), Ok(()))]
    #[case(decommission_pool(), stake_pool(),         Ok(()))]
    #[case(decommission_pool(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    #[case(decommission_pool(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInTx))]
    fn tx_one_to_one(
        #[case] input: TxOutput,
        #[case] output: TxOutput,
        #[case] result: Result<(), ConnectTransactionError>,
    ) {
        match input {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::DecommissionPool(_, _, _, _)
            | TxOutput::Burn(_)
            | TxOutput::StakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _, _) => {
                /* this is a compile guard: after adding new arm don't forget to reconsider the test */
            },
        };

        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let mut mocked_view = MockUtxoView::new();
        mocked_view
            .expect_utxo()
            .return_once(move |_| Ok(Some(Utxo::new_for_mempool(input, false))));

        let tx = Transaction::new(0, vec![outpoint.into()], vec![output], 0).unwrap();
        assert_eq!(result, check_tx_inputs_outputs_purposes(&tx, &mocked_view));
    }

    // FIXME: more tests

    //#[rstest]
    //#[trace]
    //#[case(Seed::from_entropy())]
    //fn tx_one_to_many(#[case] seed: Seed) {
    //    let mut rng = make_seedable_rng(seed);
    //    let every_purpose = [
    //        transfer(),
    //        lock_then_transfer(),
    //        burn(),
    //        stake_pool(),
    //        produce_block(),
    //        decommission_pool(),
    //    ];

    //    let t = every_purpose
    //        .iter()
    //        .combinations_with_replacement(rng.gen_range(1..10))
    //        .collect::<Vec<_>>();
    //    let outputs = t
    //        .get(rng.gen_range(0..t.len()))
    //        .unwrap()
    //        .iter()
    //        .map(|purpose| TxOutput::new(OutputValue::Coin(Amount::ZERO), **purpose));

    //    let input = TxOutput::new(OutputValue::Coin(Amount::ZERO), in_purpose);
    //    let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    //    let mut mocked_view = MockUtxoView::new();
    //    mocked_view
    //        .expect_utxo()
    //        .return_once(move |_| Some(Utxo::new_for_mempool(input, false)));

    //    let tx = Transaction::new(0, vec![outpoint.into()], vec![output], 0).unwrap();
    //    assert_eq!(result, check_tx_inputs_outputs_purposes(&tx, &mocked_view));
    //}

    // FIXME: tx_many_to_one, tx_one_to_many, tx_mane_to_many

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

    #[rstest]
    #[rustfmt::skip]
    #[case(transfer(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(transfer(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(transfer(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(transfer(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(burn(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(burn(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(burn(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(burn(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(burn(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(burn(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(lock_then_transfer(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(lock_then_transfer(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(lock_then_transfer(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(lock_then_transfer(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(lock_then_transfer(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(lock_then_transfer(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(stake_pool(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(stake_pool(), produce_block(),      Ok(()))]
    #[case(stake_pool(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(produce_block(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(produce_block(), produce_block(),      Ok(()))]
    #[case(produce_block(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(decommission_pool(), transfer(),           Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(decommission_pool(), burn(),               Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(decommission_pool(), lock_then_transfer(), Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(decommission_pool(), stake_pool(),         Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(decommission_pool(), produce_block(),      Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    #[case(decommission_pool(), decommission_pool(),  Err(ConnectTransactionError::InvalidOutputTypeInReward))]
    fn reward_one_to_one(
        #[case] input: TxOutput,
        #[case] output: TxOutput,
        #[case] result: Result<(), ConnectTransactionError>,
    ) {
        match input {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::DecommissionPool(_, _, _, _)
            | TxOutput::Burn(_)
            | TxOutput::StakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _, _) => {
                /* this is a compile guard: after adding new arm don't forget to reconsider the test */
            },
        };

        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let mut mocked_view = MockUtxoView::new();
        mocked_view
            .expect_utxo()
            .return_once(move |_| Some(Utxo::new_for_mempool(input, false)));

        let block = make_block(vec![outpoint.into()], vec![output]);

        assert_eq!(result, check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &mocked_view));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn reward_one_to_none(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let valid_kernels = [stake_pool(), produce_block()];

        let input = get_random_outputs(&mut rng, &valid_kernels, 1).into_iter().next().unwrap();
        let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);

        let mut mocked_view = MockUtxoView::new();
        mocked_view
            .expect_utxo()
            .return_once(move |_| Some(Utxo::new_for_mempool(input, false)));

        let block = make_block(vec![outpoint.into()], vec![]);

        let res =
            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &mocked_view)
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

        {
            // valid cases
            let valid_purposes = [lock_then_transfer()];

            let number_of_outputs = rng.gen_range(1..10);
            let outputs = get_random_outputs(&mut rng, &valid_purposes, number_of_outputs);

            let mocked_view = MockUtxoView::new();
            let block = make_block_no_kernel(outputs);

            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &mocked_view)
                .unwrap();
        }

        {
            // invalid cases
            let invalid_purposes =
                [transfer(), burn(), stake_pool(), produce_block(), decommission_pool()];

            let number_of_outputs = rng.gen_range(1..10);
            let outputs = get_random_outputs(&mut rng, &invalid_purposes, number_of_outputs);

            let mocked_view = MockUtxoView::new();
            let block = make_block_no_kernel(outputs);

            let res = check_reward_inputs_outputs_purposes(
                &block.block_reward_transactable(),
                &mocked_view,
            )
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
        ];

        let number_of_outputs = rng.gen_range(2..10);
        let kernel_outputs = get_random_outputs(&mut rng, &all_purposes, number_of_outputs)
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                (
                    OutPoint::new(
                        OutPointSourceId::BlockReward(Id::new(H256::zero())),
                        i as u32,
                    ),
                    output,
                )
            })
            .collect::<BTreeMap<_, _>>();

        let inputs: Vec<TxInput> = kernel_outputs.iter().map(|(k, _)| k.clone().into()).collect();

        let mut mocked_view = MockUtxoView::new();
        mocked_view.expect_utxo().returning(move |outpoint| {
            kernel_outputs.get(outpoint).map(|v| Utxo::new_for_mempool(v.clone(), false))
        });

        let block = make_block(inputs, vec![]);

        let res =
            check_reward_inputs_outputs_purposes(&block.block_reward_transactable(), &mocked_view)
                .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::SpendStakeError(SpendStakeError::ConsensusPoSError(
                ConsensusPoSError::MultipleKernels
            ))
        );
    }
}
