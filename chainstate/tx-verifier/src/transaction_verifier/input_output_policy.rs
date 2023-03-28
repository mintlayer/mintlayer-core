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

use common::chain::{block::BlockRewardTransactable, Transaction, TxOutput};

use super::error::ConnectTransactionError;

pub fn check_reward_inputs_outputs_purposes(
    _reward: &BlockRewardTransactable,
    _utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    // FIXME: rules for block reward
    Ok(())
}

/// Not all `OutputPurposes` can be used in a transaction.
/// For example spending `ProduceBlockFromStake` and `StakePool` in a tx is not supported
/// at the moment and considered invalid.
pub fn check_tx_inputs_outputs_purposes(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    check_inputs_can_be_used_in_tx(tx, utxo_view)?;
    check_outputs_can_be_used_in_tx(tx)?;
    Ok(())
}

/// Indicates whether an output purpose can be used in a tx as an input
fn is_valid_input_for_tx(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::DecommissionPool(_, _, _, _) => true,
        TxOutput::Burn(_) | TxOutput::StakePool(_) | TxOutput::ProduceBlockFromStake(_, _, _) => {
            false
        }
    }
}

/// Indicates whether an output purpose can be used in a tx as an output
fn is_valid_output_for_tx(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::StakePool(_)
        | TxOutput::DecommissionPool(_, _, _, _) => true,
        TxOutput::ProduceBlockFromStake(_, _, _) => false,
    }
}

fn check_inputs_can_be_used_in_tx(
    tx: &Transaction,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    let can_be_spent = tx
        .inputs()
        .iter()
        .map(|input| {
            utxo_view
                .utxo(input.outpoint())
                .map_err(|_| utxo::Error::ViewRead)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
        })
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .all(|utxo| is_valid_input_for_tx(utxo.output()));

    utils::ensure!(
        can_be_spent,
        ConnectTransactionError::AttemptToSpendInvalidOutputType
    );
    Ok(())
}

fn check_outputs_can_be_used_in_tx(tx: &Transaction) -> Result<(), ConnectTransactionError> {
    let are_outputs_valid = tx.outputs().iter().all(is_valid_output_for_tx);

    utils::ensure!(
        are_outputs_valid,
        ConnectTransactionError::AttemptToUseInvalidOutputInTx
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::{
        chain::{
            stakelock::StakePoolData, timelock::OutputTimeLock, tokens::OutputValue, Destination,
            GenBlock, OutPoint, OutPointSourceId, PoolId,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
    use rstest::rstest;
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

    #[rstest]
    #[rustfmt::skip]
    #[case(transfer(), transfer(),           Ok(()))]
    #[case(transfer(), burn(),               Ok(()))]
    #[case(transfer(), lock_then_transfer(), Ok(()))]
    #[case(transfer(), stake_pool(),         Ok(()))]
    #[case(transfer(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(transfer(), decommission_pool(),  Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(burn(), transfer(),           Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(burn(), burn(),               Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(burn(), lock_then_transfer(), Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(burn(), stake_pool(),         Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(burn(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(burn(), decommission_pool(),  Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(lock_then_transfer(), transfer(),           Ok(()))]
    #[case(lock_then_transfer(), burn(),               Ok(()))]
    #[case(lock_then_transfer(), lock_then_transfer(), Ok(()))]
    #[case(lock_then_transfer(), stake_pool(),         Ok(()))]
    #[case(lock_then_transfer(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(lock_then_transfer(), decommission_pool(),  Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(stake_pool(), transfer(),           Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(stake_pool(), burn(),               Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(stake_pool(), lock_then_transfer(), Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(stake_pool(), stake_pool(),         Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(stake_pool(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(stake_pool(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(produce_block(), transfer(),           Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(produce_block(), burn(),               Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(produce_block(), lock_then_transfer(), Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(produce_block(), stake_pool(),         Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(produce_block(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(produce_block(), decommission_pool(),  Ok(()))]
    /*-----------------------------------------------------------------------------------------------*/
    #[case(decommission_pool(), transfer(),           Ok(()))]
    #[case(decommission_pool(), burn(),               Ok(()))]
    #[case(decommission_pool(), lock_then_transfer(), Ok(()))]
    #[case(decommission_pool(), stake_pool(),         Ok(()))]
    #[case(decommission_pool(), produce_block(),      Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
    #[case(decommission_pool(), decommission_pool(),  Err(ConnectTransactionError::AttemptToSpendInvalidOutputType))]
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

    // FIXME: tx_many_to_one, tx_one_to_many, tx_mane_to_many
}
