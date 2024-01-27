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

use std::{collections::BTreeMap, vec};

use crate::TestChainstate;

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{
        output_value::OutputValue,
        stakelock::StakePoolData,
        tokens::{
            make_token_id, IsTokenUnfreezable, NftIssuance, TokenId, TokenIssuance,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountType, DelegationId, Destination, PoolId, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight},
};
use crypto::{
    random::{CryptoRng, Rng},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use itertools::Itertools;
use pos_accounting::{
    make_pool_id, DelegationData, InMemoryPoSAccounting, PoSAccountingDB, PoSAccountingDelta,
    PoSAccountingDeltaData, PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
    PoolData,
};
use test_utils::nft_utils::*;
use tokens_accounting::{
    InMemoryTokensAccounting, TokensAccountingCache, TokensAccountingDB, TokensAccountingDeltaData,
    TokensAccountingOperations, TokensAccountingView,
};
use utxo::Utxo;

fn get_random_pool_data<'a>(
    rng: &mut impl Rng,
    storage: &'a InMemoryPoSAccounting,
) -> Option<(&'a PoolId, &'a PoolData)> {
    let all_pool_data = storage.all_pool_data();
    (!all_pool_data.is_empty())
        .then(|| all_pool_data.iter().nth(rng.gen_range(0..all_pool_data.len())).unwrap())
}

fn get_random_delegation_data<'a>(
    rng: &mut impl Rng,
    storage: &'a InMemoryPoSAccounting,
) -> Option<(&'a DelegationId, &'a DelegationData)> {
    let all_delegation_data = storage.all_delegation_data();
    (!all_delegation_data.is_empty()).then(|| {
        all_delegation_data
            .iter()
            .nth(rng.gen_range(0..all_delegation_data.len()))
            .unwrap()
    })
}

pub struct RandomTxMaker<'a> {
    chainstate: &'a TestChainstate,
    utxo_set: &'a BTreeMap<UtxoOutPoint, Utxo>,
    tokens_store: &'a InMemoryTokensAccounting,
    pos_accounting_store: &'a InMemoryPoSAccounting,

    account_nonce_getter: Box<dyn Fn(AccountType) -> Option<AccountNonce> + 'a>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,

    // Transaction is composed of multiple inputs and outputs
    // but pools, delegations and tokens can be created only using input0 so following flags are required
    token_can_be_issued: Option<TokenId>,
    stake_pool_can_be_created: Option<PoolId>,
    delegation_can_be_created: Option<UtxoOutPoint>,

    account_command_used: bool,

    // There can be only one Unmint operation per transaction.
    // But it's unknown in advance which token burn would be utilized by unmint operation
    // so we have to collect all burns for all tokens just in case.
    unmint_for: Option<TokenId>,
    total_tokens_burned: BTreeMap<TokenId, Amount>,
}

impl<'a> RandomTxMaker<'a> {
    pub fn new(
        chainstate: &'a TestChainstate,
        utxo_set: &'a BTreeMap<UtxoOutPoint, Utxo>,
        tokens_store: &'a InMemoryTokensAccounting,
        pos_accounting_store: &'a InMemoryPoSAccounting,
        account_nonce_getter: Box<dyn Fn(AccountType) -> Option<AccountNonce> + 'a>,
    ) -> Self {
        Self {
            chainstate,
            utxo_set,
            tokens_store,
            pos_accounting_store,
            account_nonce_getter,
            account_nonce_tracker: BTreeMap::new(),
            token_can_be_issued: None,
            stake_pool_can_be_created: None,
            delegation_can_be_created: None,
            account_command_used: false,
            unmint_for: None,
            total_tokens_burned: BTreeMap::new(),
        }
    }

    // FIXME: return pos delta
    pub fn make(
        mut self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (
        Transaction,
        TokensAccountingDeltaData,
        PoSAccountingDeltaData,
    ) {
        // TODO: ideally all inputs/outputs should be shuffled but it would mess up with token issuance
        // because ids are build from input0

        let tokens_db = TokensAccountingDB::new(self.tokens_store);
        let mut tokens_cache = TokensAccountingCache::new(&tokens_db);

        let pos_db = PoSAccountingDB::new(self.pos_accounting_store);
        let mut pos_delta = PoSAccountingDelta::new(&pos_db);

        // Select random number of utxos to spend
        let inputs_with_utxos = self.select_utxos(rng);

        // Spend selected utxos
        let (mut inputs, mut outputs) =
            self.create_utxo_spending(rng, &mut tokens_cache, &mut pos_delta, inputs_with_utxos);

        // Select random number of token accounts to spend from
        let account_inputs = self.select_accounts(rng);

        // Spending from a token account requires paying fee. Find sufficient utxo per account input.
        let fee = self.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
        let fee_inputs = self
            .utxo_set
            .iter()
            .filter(|(outpoint, utxo)| {
                let input: TxInput = (**outpoint).clone().into();
                !inputs.iter().contains(&input)
                    && super::get_output_value(utxo.output())
                        .map_or(false, |v| v.coin_amount().unwrap_or(Amount::ZERO) >= fee)
            })
            .map(|(outpoint, _)| outpoint.clone().into())
            .take(inputs.len())
            .collect::<Vec<TxInput>>();

        // If enough utxos to pay fees
        if fee_inputs.len() == account_inputs.len() {
            let (account_inputs, account_outputs) =
                self.create_account_spending(rng, &mut tokens_cache, &account_inputs, fee_inputs);

            inputs.extend(account_inputs);
            outputs.extend(account_outputs);
        };

        (
            Transaction::new(0, inputs, outputs).unwrap(),
            tokens_cache.consume(),
            pos_delta.consume(),
        )
    }

    fn select_utxos(&self, rng: &mut impl Rng) -> Vec<(UtxoOutPoint, TxOutput)> {
        // TODO: it take several items from the beginning of the collection assuming that outpoints
        // are ids thus the order changes with new insertions. But more sophisticated random selection can be implemented here
        let number_of_inputs = rng.gen_range(1..5);
        self.utxo_set
            .iter()
            .take(number_of_inputs)
            .map(|(outpoint, utxo)| (outpoint.clone(), utxo.output().clone()))
            .collect()
    }

    fn select_accounts(&self, rng: &mut impl Rng) -> Vec<TokenId> {
        // TODO: it take several items from the beginning of the collection assuming that outpoints
        // are ids thus the order changes with new insertions. But more sophisticated random selection can be implemented here
        let number_of_inputs = rng.gen_range(1..5);
        self.tokens_store
            .tokens_data()
            .iter()
            .take(number_of_inputs)
            .map(|(token_id, _)| *token_id)
            .collect()
    }

    fn get_next_nonce(&mut self, account: AccountType) -> AccountNonce {
        *self
            .account_nonce_tracker
            .entry(account)
            .and_modify(|nonce| {
                *nonce = nonce.increment().unwrap();
            })
            .or_insert_with(|| {
                (self.account_nonce_getter)(account)
                    .map_or(AccountNonce::new(0), |nonce| nonce.increment().unwrap())
            })
    }

    fn create_account_spending(
        mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        inputs: &[TokenId],
        fee_inputs: Vec<TxInput>,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        assert_eq!(inputs.len(), fee_inputs.len());

        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for (i, token_id) in inputs.iter().copied().enumerate() {
            if self.account_command_used {
                break;
            }

            let token_data = tokens_cache.get_token_data(&token_id).unwrap();
            if let Some(token_data) = token_data {
                let tokens_accounting::TokenData::FungibleToken(token_data) = token_data;

                if token_data.is_frozen() {
                    if token_data.can_be_unfrozen() {
                        // Unfreeze
                        let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                        let account_input = TxInput::AccountCommand(
                            new_nonce,
                            AccountCommand::UnfreezeToken(token_id),
                        );

                        let inputs = vec![account_input, fee_inputs[i].clone()];
                        result_inputs.extend(inputs);

                        let _ = tokens_cache.unfreeze_token(token_id).unwrap();

                        self.account_command_used = true;
                    }
                } else if rng.gen_bool(0.1) {
                    if token_data.can_be_frozen() {
                        // Freeze
                        let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                        let unfreezable = if rng.gen::<bool>() {
                            IsTokenUnfreezable::Yes
                        } else {
                            IsTokenUnfreezable::No
                        };
                        let account_input = TxInput::AccountCommand(
                            new_nonce,
                            AccountCommand::FreezeToken(token_id, unfreezable),
                        );

                        let inputs = vec![account_input, fee_inputs[i].clone()];
                        result_inputs.extend(inputs);

                        let _ = tokens_cache.freeze_token(token_id, unfreezable).unwrap();

                        self.account_command_used = true;
                    }
                } else if rng.gen_bool(0.1) {
                    // Change token authority
                    // TODO: use real keys that are changing
                    let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                    let account_input = TxInput::AccountCommand(
                        new_nonce,
                        AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
                    );

                    let inputs = vec![account_input, fee_inputs[i].clone()];
                    result_inputs.extend(inputs);

                    let _ = tokens_cache
                        .change_authority(token_id, Destination::AnyoneCanSpend)
                        .unwrap();

                    self.account_command_used = true;
                } else if !token_data.is_locked() {
                    if rng.gen_bool(0.9) {
                        let circulating_supply = tokens_cache
                            .get_circulating_supply(&token_id)
                            .unwrap()
                            .unwrap_or(Amount::ZERO);

                        // mint
                        let supply_limit = match token_data.total_supply() {
                            TokenTotalSupply::Fixed(v) => *v,
                            TokenTotalSupply::Lockable | TokenTotalSupply::Unlimited => {
                                Amount::from_atoms(i128::MAX as u128)
                            }
                        };
                        let supply_left = (supply_limit - circulating_supply).unwrap();
                        let to_mint =
                            Amount::from_atoms(rng.gen_range(1..supply_left.into_atoms()));

                        let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                        let account_input = TxInput::AccountCommand(
                            new_nonce,
                            AccountCommand::MintTokens(token_id, to_mint),
                        );
                        result_inputs.extend(vec![account_input, fee_inputs[i].clone()]);

                        let outputs = vec![TxOutput::Transfer(
                            OutputValue::TokenV1(token_id, to_mint),
                            Destination::AnyoneCanSpend,
                        )];
                        result_outputs.extend(outputs);

                        let _ = tokens_cache.mint_tokens(token_id, to_mint).unwrap();

                        self.account_command_used = true;
                    } else {
                        let is_locked =
                            match tokens_cache.get_token_data(&token_id).unwrap().unwrap() {
                                tokens_accounting::TokenData::FungibleToken(data) => {
                                    data.is_locked()
                                }
                            };

                        if !is_locked {
                            let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                            let account_input = TxInput::AccountCommand(
                                new_nonce,
                                AccountCommand::LockTokenSupply(token_id),
                            );
                            result_inputs.extend(vec![account_input, fee_inputs[i].clone()]);

                            let _ = tokens_cache.lock_circulating_supply(token_id).unwrap();

                            self.account_command_used = true;
                        }
                    }
                }
            }
        }

        (result_inputs, result_outputs)
    }

    /// Given an output as in input creates multiple new random outputs.
    fn create_utxo_spending(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
        inputs: Vec<(UtxoOutPoint, TxOutput)>,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();
        let mut fee_input_to_change_supply: Option<TxInput> = None;

        for (i, (outpoint, input_utxo)) in inputs.iter().enumerate() {
            if i == 0 {
                self.token_can_be_issued = Some(make_token_id(&[outpoint.clone().into()]).unwrap());
                self.stake_pool_can_be_created = Some(make_pool_id(&outpoint));
                self.delegation_can_be_created = Some(outpoint.clone());
            }

            match input_utxo {
                TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) => {
                    match v {
                        OutputValue::Coin(coins) => {
                            // save output for potential unmint fee
                            if *coins
                                >= self
                                    .chainstate
                                    .get_chain_config()
                                    .token_supply_change_fee(BlockHeight::zero())
                                && fee_input_to_change_supply.is_none()
                                && inputs.len() > 1
                            {
                                fee_input_to_change_supply = Some(TxInput::Utxo(outpoint.clone()));
                            } else {
                                let new_outputs =
                                    self.spend_coins(rng, *coins, pos_accounting_cache);
                                result_inputs.push(TxInput::Utxo(outpoint.clone()));
                                result_outputs.extend(new_outputs);
                            }
                        }
                        OutputValue::TokenV0(_) => {
                            unimplemented!("deprecated tokens version")
                        }
                        OutputValue::TokenV1(token_id, amount) => {
                            let token_data = tokens_cache.get_token_data(&token_id).unwrap();
                            if let Some(token_data) = token_data {
                                let tokens_accounting::TokenData::FungibleToken(token_data) =
                                    token_data;
                                if token_data.is_frozen() {
                                    continue;
                                }
                            }

                            let (new_inputs, new_outputs) = self.spend_tokens_v1(
                                rng,
                                tokens_cache,
                                *token_id,
                                *amount,
                                &mut fee_input_to_change_supply,
                            );
                            result_inputs.push(TxInput::Utxo(outpoint.clone()));
                            result_inputs.extend(new_inputs);
                            result_outputs.extend(new_outputs);
                        }
                    };
                }
                TxOutput::CreateStakePool(pool_id, _) => {
                    if rng.gen_bool(0.1) {
                        let staker_balance = pos_accounting_cache
                            .get_pool_data(*pool_id)
                            .unwrap()
                            .unwrap()
                            .staker_balance()
                            .unwrap();
                        let _ = pos_accounting_cache.decommission_pool(*pool_id).unwrap();

                        result_inputs.push(TxInput::Utxo(outpoint.clone()));
                        result_outputs.push(TxOutput::LockThenTransfer(
                            OutputValue::Coin(staker_balance),
                            Destination::AnyoneCanSpend,
                            common::chain::timelock::OutputTimeLock::ForBlockCount(1),
                        ));
                    }
                }
                TxOutput::IssueNft(token_id, _, _) => {
                    let (new_inputs, new_outputs) = self.spend_tokens_v1(
                        rng,
                        tokens_cache,
                        *token_id,
                        Amount::from_atoms(1),
                        &mut fee_input_to_change_supply,
                    );
                    result_inputs.push(TxInput::Utxo(outpoint.clone()));
                    result_inputs.extend(new_inputs);
                    result_outputs.extend(new_outputs);
                }
                TxOutput::ProduceBlockFromStake(_, _) => unimplemented!(),
                TxOutput::Burn(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::DataDeposit(_) => unreachable!(),
            }
        }

        if let Some(token_id) = self.unmint_for {
            // it's possible that unmint command was used but no tokens were actually burned
            if let Some(total_burned) = self.total_tokens_burned.get(&token_id) {
                let _ = tokens_cache.unmint_tokens(token_id, *total_burned).unwrap();
            }
        }

        (result_inputs, result_outputs)
    }

    fn spend_coins(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        coins: Amount,
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
    ) -> Vec<TxOutput> {
        let num_outputs = rng.gen_range(1..5);
        let switch = rng.gen_range(0..3);
        if switch == 0 && self.token_can_be_issued.is_some() {
            // issue token v1
            let min_tx_fee = self.chainstate.get_chain_config().fungible_token_issuance_fee();
            if coins >= min_tx_fee {
                self.token_can_be_issued = None;
                let change = (coins - min_tx_fee).unwrap();
                // Coin output is created intentionally besides issuance output in order to not waste utxo
                // (e.g. single genesis output on issuance)
                vec![
                    TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                        random_token_issuance_v1(self.chainstate.get_chain_config(), rng),
                    ))),
                    TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
                ]
            } else {
                Vec::new()
            }
        } else if switch == 1 && self.token_can_be_issued.is_some() {
            // issue nft v1
            let min_tx_fee =
                self.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
            if coins >= min_tx_fee {
                let token_id = self.token_can_be_issued.unwrap();
                self.token_can_be_issued = None;
                let change = (coins - min_tx_fee).unwrap();
                // Coin output is created intentionally besides issuance output in order to not waste utxo
                // (e.g. single genesis output on issuance)
                vec![
                    TxOutput::IssueNft(
                        token_id,
                        Box::new(NftIssuance::V0(random_nft_issuance(
                            self.chainstate.get_chain_config(),
                            rng,
                        ))),
                        Destination::AnyoneCanSpend,
                    ),
                    TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
                ]
            } else {
                Vec::new()
            }
        } else {
            // transfer coins
            let mut new_outputs = (0..num_outputs)
                .map(|_| {
                    let new_value = Amount::from_atoms(coins.into_atoms() / num_outputs);
                    debug_assert!(new_value >= Amount::from_atoms(1));

                    if new_value >= self.chainstate.get_chain_config().min_stake_pool_pledge()
                        && self.stake_pool_can_be_created.is_some()
                    {
                        // If enough coins for pledge - create a pool
                        let pool_id = self.stake_pool_can_be_created.unwrap();
                        self.stake_pool_can_be_created = None;
                        let pool_data = StakePoolData::new(
                            new_value,
                            Destination::AnyoneCanSpend,
                            VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel).1,
                            Destination::AnyoneCanSpend,
                            PerThousand::new_from_rng(rng),
                            Amount::from_atoms(rng.gen_range(0..1000)),
                        );
                        let _ = pos_accounting_cache
                            .create_pool(pool_id, pool_data.clone().into())
                            .unwrap();
                        TxOutput::CreateStakePool(pool_id, Box::new(pool_data))
                    } else {
                        if rng.gen_bool(0.3) {
                            // Send coins to random delegation
                            if let Some((delegation_id, _)) =
                                get_random_delegation_data(rng, self.pos_accounting_store)
                            {
                                let _ = pos_accounting_cache
                                    .delegate_staking(*delegation_id, new_value)
                                    .unwrap();
                                return TxOutput::DelegateStaking(new_value, *delegation_id);
                            }
                        }

                        TxOutput::Transfer(
                            OutputValue::Coin(new_value),
                            Destination::AnyoneCanSpend,
                        )
                    }
                })
                .collect::<Vec<_>>();

            // Occasionally create new delegation id

            if rng.gen_bool(0.3) && self.delegation_can_be_created.is_some() {
                if let Some((pool_id, _)) = get_random_pool_data(rng, &self.pos_accounting_store) {
                    let input0_outpoint = self.delegation_can_be_created.clone().unwrap();
                    self.delegation_can_be_created = None;
                    let _ = pos_accounting_cache
                        .create_delegation_id(
                            *pool_id,
                            Destination::AnyoneCanSpend,
                            &input0_outpoint,
                        )
                        .unwrap();
                    new_outputs.push(TxOutput::CreateDelegationId(
                        Destination::AnyoneCanSpend,
                        *pool_id,
                    ));
                }
            }
            new_outputs
        }
    }

    fn spend_tokens_v1(
        &mut self,
        rng: &mut impl Rng,
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        token_id: TokenId,
        amount: Amount,
        fee_input: &mut Option<TxInput>,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        let atoms_vec = test_utils::split_value(rng, amount.into_atoms());
        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for atoms in atoms_vec {
            if rng.gen::<bool>() {
                // transfer
                result_outputs.push(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(atoms)),
                    Destination::AnyoneCanSpend,
                ));
            } else if rng.gen_bool(0.9) && !self.account_command_used {
                // unmint
                let token_data = tokens_cache.get_token_data(&token_id).unwrap();

                // check token_data as well because it can be an nft
                if let (Some(fee_tx_input), Some(token_data)) = (&fee_input, token_data) {
                    let tokens_accounting::TokenData::FungibleToken(token_data) = token_data;
                    if !token_data.is_locked() && !token_data.is_frozen() {
                        let to_unmint = Amount::from_atoms(atoms);

                        let circulating_supply =
                            tokens_cache.get_circulating_supply(&token_id).unwrap();
                        assert!(circulating_supply.unwrap() >= to_unmint);

                        let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                        let account_input = TxInput::AccountCommand(
                            new_nonce,
                            AccountCommand::UnmintTokens(token_id),
                        );
                        result_inputs.extend(vec![account_input, fee_tx_input.clone()]);

                        let outputs =
                            vec![TxOutput::Burn(OutputValue::TokenV1(token_id, to_unmint))];
                        result_outputs.extend(outputs);

                        self.unmint_for = Some(token_id);
                        self.account_command_used = true;
                    }
                    *fee_input = None;
                }
            } else {
                // burn
                let to_burn = Amount::from_atoms(atoms);
                result_outputs.push(TxOutput::Burn(OutputValue::TokenV1(token_id, to_burn)));

                self.total_tokens_burned
                    .entry(token_id)
                    .and_modify(|total| {
                        *total = (*total + to_burn).unwrap();
                    })
                    .or_insert(to_burn);
            }
        }

        (result_inputs, result_outputs)
    }
}
