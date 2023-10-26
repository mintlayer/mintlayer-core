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

use std::collections::BTreeMap;

use common::{
    amount_sum,
    chain::{
        block::{BlockRewardTransactable, ConsensusData},
        output_value::OutputValue,
        signature::Signable,
        tokens::{
            get_token_supply_change_count, get_tokens_issuance_count, make_token_id, TokenData,
            TokenId, TokenIssuanceVersion,
        },
        AccountOp, Block, ChainConfig, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use fallible_iterator::FallibleIterator;
use pos_accounting::PoSAccountingView;
use utils::ensure;
use utxo::UtxosView;

use super::{
    amounts_map::AmountsMap,
    error::{ConnectTransactionError, TokensError},
    token_issuance_cache::CoinOrTokenId,
    Fee, IOPolicyError, Subsidy,
};

fn get_total_fee(
    inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
) -> Result<Fee, ConnectTransactionError> {
    // TODO: fees should support tokens as well in the future
    let outputs_total = *outputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::ZERO);
    let inputs_total = *inputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::ZERO);
    (inputs_total - outputs_total)
        .map(Fee)
        .ok_or(ConnectTransactionError::TxFeeTotalCalcFailed(
            inputs_total,
            outputs_total,
        ))
}

fn check_transferred_amount(
    inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
) -> Result<(), ConnectTransactionError> {
    for (coin_or_token_id, outputs_total) in outputs_total_map {
        // Does coin or token exist in inputs?
        let inputs_total = inputs_total_map.get(coin_or_token_id).unwrap_or(&Amount::ZERO);

        // Do the outputs exceed inputs?
        if outputs_total > inputs_total {
            return Err(ConnectTransactionError::AttemptToPrintMoney(
                *inputs_total,
                *outputs_total,
            ));
        }
    }
    Ok(())
}

pub fn check_transferred_amounts_and_get_fee<U, P, IssuanceTokenIdGetterFunc>(
    chain_config: &ChainConfig,
    utxo_view: &U,
    pos_accounting_view: &P,
    tx: &Transaction,
    current_height: BlockHeight,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<Fee, ConnectTransactionError>
where
    U: UtxosView,
    P: PoSAccountingView,
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let mut inputs_total_map = calculate_total_inputs(
        utxo_view,
        pos_accounting_view,
        tx.inputs(),
        tx.get_id().into(),
        issuance_token_id_getter,
    )?;

    let latest_token_version = chain_config
        .chainstate_upgrades()
        .version_at_height(current_height)
        .1
        .token_issuance_version();

    match latest_token_version {
        TokenIssuanceVersion::V0 => {
            check_issuance_fee_burn_v0(chain_config, tx)?;
        }
        TokenIssuanceVersion::V1 => {
            // For V1 all operations that require coins to be burned (token issuance, token supply change, data deposit)
            // create an accumulated fee that is deducted from the input coins.
            let total_required_burn = calculate_required_fee_burn(chain_config, tx)?;
            match inputs_total_map.get_mut(&CoinOrTokenId::Coin) {
                Some(total_input_coins) => {
                    *total_input_coins = (*total_input_coins - total_required_burn).ok_or(
                        ConnectTransactionError::InsufficientCoinsFee(
                            *total_input_coins,
                            total_required_burn,
                        ),
                    )?;
                }
                None => {
                    ensure!(
                        total_required_burn == Amount::ZERO,
                        ConnectTransactionError::InsufficientCoinsFee(
                            Amount::ZERO,
                            total_required_burn
                        )
                    );
                }
            };
        }
    }

    let outputs_total_map = calculate_total_outputs(pos_accounting_view, tx.outputs(), None)?;

    check_transferred_amount(&inputs_total_map, &outputs_total_map)?;
    let total_fee = get_total_fee(&inputs_total_map, &outputs_total_map)?;

    Ok(total_fee)
}

fn calculate_total_inputs<U, P, IssuanceTokenIdGetterFunc>(
    utxo_view: &U,
    pos_accounting_view: &P,
    inputs: &[TxInput],
    inputs_source: OutPointSourceId,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError>
where
    U: UtxosView,
    P: PoSAccountingView,
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let iter = inputs.iter().map(|input| match input {
        TxInput::Utxo(outpoint) => {
            let utxo = utxo_view.utxo(outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                ConnectTransactionError::MissingOutputOrSpent(outpoint.clone()),
            )?;

            let output_value = match utxo.output() {
                TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) => v.clone(),
                TxOutput::CreateStakePool(_, data) => OutputValue::Coin(data.value()),
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    let pledge_amount = pos_accounting_view
                        .get_pool_data(*pool_id)
                        .map_err(|_| pos_accounting::Error::ViewFail)?
                        .ok_or(ConnectTransactionError::PoolOwnerBalanceNotFound(*pool_id))?
                        .pledge_amount();
                    OutputValue::Coin(pledge_amount)
                }
                TxOutput::Burn(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => {
                    return Err(ConnectTransactionError::IOPolicyError(
                        IOPolicyError::InvalidInputTypeInTx,
                        inputs_source.clone(),
                    ))
                }
                TxOutput::IssueNft(token_id, _, _) => {
                    OutputValue::TokenV1(*token_id, Amount::from_atoms(1))
                }
                TxOutput::IssueFungibleToken(_) => {
                    return Err(ConnectTransactionError::IOPolicyError(
                        IOPolicyError::InvalidInputTypeInTx,
                        inputs_source.clone(),
                    ))
                }
            };

            amount_from_outpoint(
                outpoint.source_id(),
                &output_value,
                &issuance_token_id_getter,
            )
        }
        TxInput::Account(account_input) => match account_input.account() {
            AccountOp::SpendDelegationBalance(delegation_id, withdraw_amount) => {
                let total_balance = pos_accounting_view
                    .get_delegation_balance(*delegation_id)
                    .map_err(|_| pos_accounting::Error::ViewFail)?
                    .ok_or(ConnectTransactionError::DelegationBalanceNotFound(
                        *delegation_id,
                    ))?;
                ensure!(
                    total_balance >= *withdraw_amount,
                    ConnectTransactionError::AttemptToPrintMoney(total_balance, *withdraw_amount)
                );
                Ok((CoinOrTokenId::Coin, *withdraw_amount))
            }
            AccountOp::MintTokens(token_id, amount) => {
                Ok((CoinOrTokenId::TokenId(*token_id), *amount))
            }
            AccountOp::UnmintTokens(token_id)
            | AccountOp::LockTokenSupply(token_id)
            | AccountOp::FreezeToken(token_id, _)
            | AccountOp::UnfreezeToken(token_id)
            | AccountOp::ChangeAuthority(token_id, _) => {
                Ok((CoinOrTokenId::TokenId(*token_id), Amount::ZERO))
            }
        },
    });

    let iter = fallible_iterator::convert(iter);

    let amounts_map = AmountsMap::from_fallible_iter(iter)?;

    Ok(amounts_map.take())
}

fn calculate_total_outputs<P: PoSAccountingView>(
    pos_accounting_view: &P,
    outputs: &[TxOutput],
    include_issuance: Option<&Transaction>,
) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError> {
    let iter = outputs.iter().map(|output| {
        let output_value = match output {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                v.clone()
            }
            TxOutput::CreateStakePool(_, data) => OutputValue::Coin(data.value()),
            TxOutput::ProduceBlockFromStake(_, pool_id) => {
                let pledge_amount = pos_accounting_view
                    .get_pool_data(*pool_id)
                    .map_err(|_| pos_accounting::Error::ViewFail)?
                    .ok_or(ConnectTransactionError::PoolOwnerBalanceNotFound(*pool_id))?
                    .pledge_amount();
                OutputValue::Coin(pledge_amount)
            }
            TxOutput::CreateDelegationId(_, _) => OutputValue::Coin(Amount::ZERO),
            TxOutput::DelegateStaking(v, _) => OutputValue::Coin(*v),
            // IssueFungibleToken cannot be spent so the output value is 0
            TxOutput::IssueFungibleToken(_) => OutputValue::Coin(Amount::ZERO),
            // when in tx output IssueNft has 0 output value because it is created there
            TxOutput::IssueNft(_, _, _) => OutputValue::Coin(Amount::ZERO),
            TxOutput::DataDeposit(_) => OutputValue::Coin(Amount::ZERO),
        };
        get_output_token_id_and_amount(&output_value, include_issuance)
    });
    let iter = fallible_iterator::convert(iter).filter_map(Ok).map_err(Into::into);

    let result = AmountsMap::from_fallible_iter(iter)?;
    Ok(result.take())
}

fn get_output_token_id_and_amount(
    output_value: &OutputValue,
    include_issuance: Option<&Transaction>,
) -> Result<Option<(CoinOrTokenId, Amount)>, ConnectTransactionError> {
    Ok(match output_value {
        OutputValue::Coin(amount) => Some((CoinOrTokenId::Coin, *amount)),
        OutputValue::TokenV0(token_data) => match &**token_data {
            TokenData::TokenTransfer(transfer) => {
                Some((CoinOrTokenId::TokenId(transfer.token_id), transfer.amount))
            }
            TokenData::TokenIssuance(issuance) => match include_issuance {
                Some(tx) => {
                    let token_id =
                        make_token_id(tx.inputs()).ok_or(TokensError::TokenIdCantBeCalculated)?;
                    Some((CoinOrTokenId::TokenId(token_id), issuance.amount_to_issue))
                }
                None => None,
            },
            TokenData::NftIssuance(_) => match include_issuance {
                Some(tx) => {
                    let token_id =
                        make_token_id(tx.inputs()).ok_or(TokensError::TokenIdCantBeCalculated)?;
                    Some((CoinOrTokenId::TokenId(token_id), Amount::from_atoms(1)))
                }
                None => None,
            },
        },
        OutputValue::TokenV1(id, amount) => Some((CoinOrTokenId::TokenId(*id), *amount)),
    })
}

fn get_input_token_id_and_amount<IssuanceTokenIdGetterFunc>(
    output_value: &OutputValue,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc: Fn() -> Result<Option<TokenId>, ConnectTransactionError>,
{
    match output_value {
        OutputValue::Coin(amount) => Ok((CoinOrTokenId::Coin, *amount)),
        OutputValue::TokenV0(token_data) => match &**token_data {
            TokenData::TokenTransfer(transfer) => {
                Ok((CoinOrTokenId::TokenId(transfer.token_id), transfer.amount))
            }
            TokenData::TokenIssuance(issuance) => issuance_token_id_getter()?
                .map(|token_id| (CoinOrTokenId::TokenId(token_id), issuance.amount_to_issue))
                .ok_or(ConnectTransactionError::TokensError(
                    TokensError::TokenIdCantBeCalculated,
                )),
            TokenData::NftIssuance(_) => issuance_token_id_getter()?
                // TODO: Find more appropriate way to check NFTs when we add multi-token feature
                .map(|token_id| (CoinOrTokenId::TokenId(token_id), Amount::from_atoms(1)))
                .ok_or(ConnectTransactionError::TokensError(
                    TokensError::TokenIdCantBeCalculated,
                )),
        },
        OutputValue::TokenV1(id, amount) => Ok((CoinOrTokenId::TokenId(*id), *amount)),
    }
}

fn amount_from_outpoint<IssuanceTokenIdGetterFunc>(
    tx_id: OutPointSourceId,
    output_value: &OutputValue,
    issuance_token_id_getter: &IssuanceTokenIdGetterFunc,
) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    match tx_id {
        OutPointSourceId::Transaction(tx_id) => {
            let issuance_token_id_getter =
                || -> Result<Option<TokenId>, ConnectTransactionError> {
                    issuance_token_id_getter(&tx_id)
                };
            get_input_token_id_and_amount(output_value, issuance_token_id_getter)
        }
        OutPointSourceId::BlockReward(_) => {
            get_input_token_id_and_amount(output_value, || Ok(None))
        }
    }
}

pub fn check_transferred_amount_in_reward<U: UtxosView, P: PoSAccountingView>(
    utxo_view: &U,
    pos_accounting_view: &P,
    block_reward_transactable: &BlockRewardTransactable,
    block_id: Id<Block>,
    consensus_data: &ConsensusData,
    total_fees: Fee,
    block_subsidy_at_height: Subsidy,
) -> Result<(), ConnectTransactionError> {
    let inputs = block_reward_transactable.inputs();
    let outputs = block_reward_transactable.outputs();

    let inputs_total = inputs.map_or_else(
        || Ok::<Amount, ConnectTransactionError>(Amount::ZERO),
        |ins| {
            calculate_total_inputs(utxo_view, pos_accounting_view, ins, block_id.into(), |_| {
                Ok(None)
            })
            .map(|total| total.get(&CoinOrTokenId::Coin).cloned().unwrap_or(Amount::ZERO))
        },
    )?;
    let outputs_total = outputs.map_or_else(
        || Ok::<Amount, ConnectTransactionError>(Amount::ZERO),
        |outputs| {
            let has_token_issuance = get_tokens_issuance_count(outputs) > 0;
            ensure!(
                !has_token_issuance,
                ConnectTransactionError::TokensError(TokensError::TokensInBlockReward)
            );

            calculate_total_outputs(pos_accounting_view, outputs, None)
                .map(|total| total.get(&CoinOrTokenId::Coin).cloned().unwrap_or(Amount::ZERO))
        },
    )?;

    match consensus_data {
        ConsensusData::None | ConsensusData::PoW(_) => {
            let max_allowed_outputs_total =
                amount_sum!(inputs_total, block_subsidy_at_height.0, total_fees.0)
                    .ok_or_else(|| ConnectTransactionError::RewardAdditionError(block_id))?;
            ensure!(
                outputs_total <= max_allowed_outputs_total,
                ConnectTransactionError::AttemptToPrintMoney(
                    max_allowed_outputs_total,
                    outputs_total
                )
            );
        }
        ConsensusData::PoS(_) => {
            ensure!(
                outputs_total == inputs_total,
                ConnectTransactionError::BlockRewardInputOutputMismatch(
                    inputs_total,
                    outputs_total
                )
            );
        }
    };

    Ok(())
}

pub fn calculate_tokens_burned_in_outputs(
    tx: &Transaction,
    token_id: &TokenId,
) -> Result<Amount, ConnectTransactionError> {
    tx.outputs()
        .iter()
        .filter_map(|output| match output {
            TxOutput::Burn(output_value) => match output_value {
                OutputValue::Coin(_) | OutputValue::TokenV0(_) => None,
                OutputValue::TokenV1(id, amount) => (id == token_id).then_some(*amount),
            },
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => None,
        })
        .sum::<Option<Amount>>()
        .ok_or(ConnectTransactionError::BurnAmountSumError(tx.get_id()))
}

fn calculate_required_fee_burn(
    chain_config: &ChainConfig,
    tx: &Transaction,
) -> Result<Amount, ConnectTransactionError> {
    // Check if the fee is enough for issuance and all supply change
    let issuance_count = get_tokens_issuance_count(tx.outputs()) as u128;
    let supply_change_count = get_token_supply_change_count(tx.inputs()) as u128;
    let data_deposit_count = tx
        .outputs()
        .iter()
        .filter(|&output| match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _) => false,
            TxOutput::DataDeposit(_) => true,
        })
        .count() as u128;

    let token_freeze_count = tx
        .inputs()
        .iter()
        .filter(|&input| match input {
            TxInput::Utxo(_) => false,
            TxInput::Account(account) => match account.account() {
                AccountOp::SpendDelegationBalance(_, _)
                | AccountOp::MintTokens(_, _)
                | AccountOp::UnmintTokens(_)
                | AccountOp::LockTokenSupply(_)
                | AccountOp::ChangeAuthority(_, _) => false,
                AccountOp::FreezeToken(_, _) | AccountOp::UnfreezeToken(_) => true,
            },
        })
        .count() as u128;

    // FIXME: authority change?
    let required_fee = (chain_config.token_min_supply_change_fee() * supply_change_count)
        .and_then(|fee| fee + (chain_config.token_min_issuance_fee() * issuance_count)?)
        .and_then(|fee| fee + (chain_config.token_min_freeze_fee() * token_freeze_count)?)
        .and_then(|fee| fee + (chain_config.data_deposit_min_fee() * data_deposit_count)?)
        .ok_or(ConnectTransactionError::TotalFeeRequiredOverflow)?;

    Ok(required_fee)
}

fn check_issuance_fee_burn_v0(
    chain_config: &ChainConfig,
    tx: &Transaction,
) -> Result<(), ConnectTransactionError> {
    // Check if the fee is enough for issuance
    let issuance_count = get_tokens_issuance_count(tx.outputs());
    if issuance_count > 0 {
        let total_burned = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Burn(v) => v.coin_amount(),
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::DelegateStaking(_, _) => None,
            })
            .sum::<Option<Amount>>()
            .ok_or_else(|| ConnectTransactionError::BurnAmountSumError(tx.get_id()))?;

        if total_burned < chain_config.token_min_issuance_fee() {
            return Err(ConnectTransactionError::TokensError(
                TokensError::InsufficientTokenFees(tx.get_id()),
            ));
        }
    }

    Ok(())
}
// TODO: add more tests

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        chain::{
            block::consensus_data::{PoSData, PoWData},
            config::ChainType,
            stakelock::StakePoolData,
            timelock::OutputTimeLock,
            AccountNonce, AccountOutPoint, DelegationId, Destination, GenBlock, PoolId,
            UtxoOutPoint,
        },
        primitives::{per_thousand::PerThousand, Compact, H256},
    };
    use crypto::{
        random::Rng,
        vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
    };
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_block_reward_pow(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let input_amount = Amount::from_atoms(rng.gen_range(0..100_000));
        let input_utxo =
            TxOutput::Transfer(OutputValue::Coin(input_amount), Destination::AnyoneCanSpend);
        let utxo_db = utxo::UtxosDBInMemoryImpl::new(
            Id::<GenBlock>::new(H256::zero()),
            BTreeMap::from_iter([(outpoint.clone(), utxo::Utxo::new_for_mempool(input_utxo))]),
        );
        let pos_accounting_store = pos_accounting::InMemoryPoSAccounting::new();
        let pos_accounting_db = pos_accounting::PoSAccountingDB::new(&pos_accounting_store);

        let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));
        let subsidy = Subsidy(Amount::from_atoms(rng.gen_range(0..100_000)));
        let total_input_value = ((input_amount + fee.0).unwrap() + subsidy.0).unwrap();

        let check = |output_value| {
            let inputs = vec![outpoint.clone().into()];
            let outputs = vec![TxOutput::LockThenTransfer(
                OutputValue::Coin(output_value),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            )];
            let block_reward = BlockRewardTransactable::new(Some(&inputs), Some(&outputs), None);
            check_transferred_amount_in_reward(
                &utxo_db,
                &pos_accounting_db,
                &block_reward,
                Id::<Block>::new(H256::zero()),
                &ConsensusData::PoW(Box::new(PoWData::new(Compact(1), 1))),
                fee,
                subsidy,
            )
        };

        // invalid case min case
        {
            let invalid_output_value = Amount::from_atoms(total_input_value.into_atoms() + 1);
            let result = check(invalid_output_value);
            assert_eq!(
                result,
                Err(ConnectTransactionError::AttemptToPrintMoney(
                    total_input_value,
                    invalid_output_value
                ))
            );
        }

        // invalid random case
        {
            let invalid_output_value =
                Amount::from_atoms(rng.gen_range((total_input_value.into_atoms() + 1)..u128::MAX));
            let result = check(invalid_output_value);
            assert_eq!(
                result,
                Err(ConnectTransactionError::AttemptToPrintMoney(
                    total_input_value,
                    invalid_output_value
                ))
            );
        }

        // valid max case
        {
            let result = check(total_input_value);
            assert_eq!(result, Ok(()));
        }

        // valid random case
        {
            let valid_output_value =
                Amount::from_atoms(rng.gen_range(0..total_input_value.into_atoms()));
            let result = check(valid_output_value);
            assert_eq!(result, Ok(()));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_block_reward_pos(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let pool_id = PoolId::new(H256::zero());
        let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let pledge_amount = Amount::from_atoms(rng.gen_range(0..100_000));
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = vrf_sk.produce_vrf_data(TranscriptAssembler::new(b"abc").finalize().into());
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
        let pos_accounting_store = pos_accounting::InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, stake_pool_data.into())]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let pos_accounting_db = pos_accounting::PoSAccountingDB::new(&pos_accounting_store);

        let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));
        let subsidy = Subsidy(Amount::from_atoms(rng.gen_range(0..100_000)));

        let inputs = vec![outpoint.into()];
        let outputs = vec![TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id)];
        let block_reward = BlockRewardTransactable::new(Some(&inputs), Some(&outputs), None);
        check_transferred_amount_in_reward(
            &utxo_db,
            &pos_accounting_db,
            &block_reward,
            Id::<Block>::new(H256::zero()),
            &ConsensusData::PoS(Box::new(PoSData::new(
                vec![],
                vec![],
                pool_id,
                vrf_data,
                Compact(1),
            ))),
            fee,
            subsidy,
        )
        .unwrap();
    }

    // Create 2 pools with different balances.
    // For block reward total inputs and total outputs must be equal.
    // Check that if different balances are used for inputs and outputs an error is produced.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_block_reward_pos_amount_mismatch(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let pool_id_1 = PoolId::new(H256::random_using(&mut rng));
        let pool_id_2 = PoolId::new(H256::random_using(&mut rng));

        let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
        let pledge_amount_1 = Amount::from_atoms(rng.gen_range(0..100_000));
        let pledge_amount_2 = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = vrf_sk.produce_vrf_data(TranscriptAssembler::new(b"abc").finalize().into());
        let stake_pool_data_1 = StakePoolData::new(
            pledge_amount_1,
            Destination::AnyoneCanSpend,
            vrf_pk.clone(),
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        );
        let stake_pool_data_2 = StakePoolData::new(
            pledge_amount_2,
            Destination::AnyoneCanSpend,
            vrf_pk,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        );
        let input_utxo = TxOutput::CreateStakePool(pool_id_1, Box::new(stake_pool_data_1.clone()));
        let utxo_db = utxo::UtxosDBInMemoryImpl::new(
            Id::<GenBlock>::new(H256::zero()),
            BTreeMap::from_iter([(outpoint.clone(), utxo::Utxo::new_for_mempool(input_utxo))]),
        );
        let pos_accounting_store = pos_accounting::InMemoryPoSAccounting::from_values(
            BTreeMap::from([
                (pool_id_1, stake_pool_data_1.into()),
                (pool_id_2, stake_pool_data_2.into()),
            ]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let pos_accounting_db = pos_accounting::PoSAccountingDB::new(&pos_accounting_store);

        let fee = Fee(Amount::from_atoms(rng.gen_range(0..100_000)));
        let subsidy = Subsidy(Amount::from_atoms(rng.gen_range(0..100_000)));

        let inputs = vec![outpoint.into()];
        let outputs = vec![TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id_2)];
        let block_reward = BlockRewardTransactable::new(Some(&inputs), Some(&outputs), None);
        let result = check_transferred_amount_in_reward(
            &utxo_db,
            &pos_accounting_db,
            &block_reward,
            Id::<Block>::new(H256::zero()),
            &ConsensusData::PoS(Box::new(PoSData::new(
                vec![],
                vec![],
                pool_id_1,
                vrf_data,
                Compact(1),
            ))),
            fee,
            subsidy,
        )
        .unwrap_err();
        assert_eq!(
            result,
            ConnectTransactionError::BlockRewardInputOutputMismatch(
                pledge_amount_1,
                pledge_amount_2
            )
        )
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_tx_spend_from_delegation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet).build();

        let utxo_db =
            utxo::UtxosDBInMemoryImpl::new(Id::<GenBlock>::new(H256::zero()), BTreeMap::new());

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_amount = Amount::from_atoms(rng.gen_range(1..100_000));
        let overspend_amount = Amount::from_atoms(delegated_amount.into_atoms() + 1);
        let withdraw_amount = Amount::from_atoms(rng.gen_range(1..=delegated_amount.into_atoms()));

        let pos_accounting_store = pos_accounting::InMemoryPoSAccounting::from_values(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([(delegation_id, delegated_amount)]),
            BTreeMap::new(),
        );
        let pos_accounting_db = pos_accounting::PoSAccountingDB::new(&pos_accounting_store);

        // try overspend balance
        {
            let input = TxInput::Account(AccountOutPoint::new(
                AccountNonce::new(0),
                AccountOp::SpendDelegationBalance(delegation_id, overspend_amount),
            ));

            let output = TxOutput::Transfer(
                OutputValue::Coin(overspend_amount),
                Destination::AnyoneCanSpend,
            );
            let tx = Transaction::new(0, vec![input], vec![output]).unwrap();

            let res = check_transferred_amounts_and_get_fee(
                &chain_config,
                &utxo_db,
                &pos_accounting_db,
                &tx,
                BlockHeight::new(0),
                |_id| Ok(None),
            )
            .unwrap_err();
            assert_eq!(
                res,
                ConnectTransactionError::AttemptToPrintMoney(delegated_amount, overspend_amount)
            );
        }

        // try overspend input
        {
            let input = TxInput::Account(AccountOutPoint::new(
                AccountNonce::new(0),
                AccountOp::SpendDelegationBalance(delegation_id, withdraw_amount),
            ));

            let output = TxOutput::Transfer(
                OutputValue::Coin(overspend_amount),
                Destination::AnyoneCanSpend,
            );
            let tx = Transaction::new(0, vec![input], vec![output]).unwrap();

            let res = check_transferred_amounts_and_get_fee(
                &chain_config,
                &utxo_db,
                &pos_accounting_db,
                &tx,
                BlockHeight::new(0),
                |_id| Ok(None),
            )
            .unwrap_err();
            assert_eq!(
                res,
                ConnectTransactionError::AttemptToPrintMoney(withdraw_amount, overspend_amount)
            );
        }

        let input = TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(0),
            AccountOp::SpendDelegationBalance(delegation_id, withdraw_amount),
        ));
        let output = TxOutput::Transfer(
            OutputValue::Coin(withdraw_amount),
            Destination::AnyoneCanSpend,
        );
        let tx = Transaction::new(0, vec![input], vec![output]).unwrap();

        check_transferred_amounts_and_get_fee(
            &chain_config,
            &utxo_db,
            &pos_accounting_db,
            &tx,
            BlockHeight::new(0),
            |_id| Ok(None),
        )
        .unwrap();
    }
}
