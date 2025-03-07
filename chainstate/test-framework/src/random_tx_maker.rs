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

use std::collections::BTreeMap;

use crate::{
    key_manager::KeyManager,
    utils::{output_value_amount, output_value_with_amount},
    TestChainstate,
};

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{
        htlc::{HashedTimelockContract, HtlcSecretHash},
        make_order_id,
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            make_token_id, IsTokenUnfreezable, NftIssuance, TokenId, TokenIssuance,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, AccountType, DelegationId,
        Destination, GenBlockId, OrderAccountCommand, OrderData, OrderId, OrdersVersion,
        OutPointSourceId, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, CoinOrTokenId, Id, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use orders_accounting::{
    InMemoryOrdersAccounting, OrdersAccountingCache, OrdersAccountingDB, OrdersAccountingDeltaData,
    OrdersAccountingOperations, OrdersAccountingView,
};
use pos_accounting::{
    make_pool_id, DelegationData, InMemoryPoSAccounting, PoSAccountingDB, PoSAccountingDelta,
    PoSAccountingDeltaData, PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
    PoolData,
};
use randomness::{seq::IteratorRandom, CryptoRng, Rng, SliceRandom};
use test_utils::{nft_utils::*, random_ascii_alphanumeric_string};
use tokens_accounting::{
    InMemoryTokensAccounting, TokensAccountingCache, TokensAccountingDB, TokensAccountingDeltaData,
    TokensAccountingOperations, TokensAccountingView,
};
use utxo::UtxosDBInMemoryImpl;

// TODO: currently this returns random pool from store but only if it exists in delta. This gives None more often.
//       There should be a way to return random result after delta is accounted.
//       Same applies for delegation.
fn get_random_pool_data<'a>(
    rng: &mut impl Rng,
    storage: &'a InMemoryPoSAccounting,
    tip_view: &impl PoSAccountingView,
) -> Option<(&'a PoolId, &'a PoolData)> {
    storage
        .all_pool_data()
        .iter()
        .choose(rng)
        .and_then(|(id, data)| tip_view.pool_exists(*id).unwrap().then_some((id, data)))
}

fn get_random_delegation_data<'a>(
    rng: &mut impl Rng,
    storage: &'a InMemoryPoSAccounting,
    tip_view: &impl PoSAccountingView,
) -> Option<(&'a DelegationId, &'a DelegationData)> {
    storage.all_delegation_data().iter().choose(rng).and_then(|(id, data)| {
        tip_view.get_delegation_data(*id).unwrap().is_some().then_some((id, data))
    })
}

fn get_random_token<'a>(
    rng: &mut impl Rng,
    storage: &'a InMemoryTokensAccounting,
    tip_view: &'a impl TokensAccountingView,
) -> Option<(TokenId, Amount)> {
    storage
        .tokens_data()
        .iter()
        .choose(rng)
        .and_then(|(token_id, _)| {
            tip_view
                .get_token_data(token_id)
                .unwrap()
                .is_some_and(|data| match data {
                    tokens_accounting::TokenData::FungibleToken(data) => !data.is_frozen(),
                })
                .then_some(*token_id)
        })
        .map(|token_id| {
            (
                token_id,
                tip_view.get_circulating_supply(&token_id).unwrap(),
            )
        })
}

fn get_random_order_to_fill<'a>(
    storage: &'a InMemoryOrdersAccounting,
    tip_view: &'a impl OrdersAccountingView,
    value: &OutputValue,
) -> Option<OrderId> {
    storage
        .orders_data()
        .iter()
        .filter(|(id, _)| tip_view.get_order_data(id).unwrap().is_some())
        .find_map(|(order_id, data)| {
            let same_currency = CoinOrTokenId::from_output_value(data.ask())
                == CoinOrTokenId::from_output_value(value);
            let ask_balance = tip_view.get_ask_balance(order_id).unwrap();
            let order_not_overbid = ask_balance >= output_value_amount(value);
            ((ask_balance > Amount::ZERO) && same_currency && order_not_overbid)
                .then_some(*order_id)
        })
}

fn get_random_timelock(
    rng: &mut impl Rng,
    chainstate: &impl ChainstateInterface,
) -> OutputTimeLock {
    const MAX_LOCK_FOR_NUM_BLOCKS: u64 = 5;
    let target_block_spacing_sec = chainstate.get_chain_config().target_block_spacing().as_secs();
    match rng.gen_range(0..4) {
        0 => OutputTimeLock::ForBlockCount(rng.gen_range(0..=MAX_LOCK_FOR_NUM_BLOCKS)),
        1 => OutputTimeLock::UntilHeight(
            chainstate
                .get_best_block_height()
                .unwrap()
                .checked_add(rng.gen_range(0..=MAX_LOCK_FOR_NUM_BLOCKS))
                .unwrap(),
        ),
        2 => OutputTimeLock::ForSeconds(
            target_block_spacing_sec * rng.gen_range(0..=MAX_LOCK_FOR_NUM_BLOCKS)
                + rng.gen_range(0..=target_block_spacing_sec),
        ),
        3 => OutputTimeLock::UntilTime(
            chainstate
                .get_best_block_index()
                .unwrap()
                .block_timestamp()
                .add_int_seconds(
                    target_block_spacing_sec * rng.gen_range(0..=MAX_LOCK_FOR_NUM_BLOCKS)
                        + rng.gen_range(0..=target_block_spacing_sec),
                )
                .unwrap(),
        ),
        _ => unreachable!(),
    }
}

pub trait StakingPoolsObserver {
    fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
    );
    fn on_pool_decommissioned(&mut self, pool_id: PoolId);
    fn on_pool_used_for_staking(&mut self, pool_id: PoolId, outpoint: UtxoOutPoint);
}

pub struct RandomTxMaker<'a> {
    chainstate: &'a TestChainstate,
    utxo_set: &'a UtxosDBInMemoryImpl,
    tokens_store: &'a InMemoryTokensAccounting,
    pos_accounting_store: &'a InMemoryPoSAccounting,
    orders_store: &'a InMemoryOrdersAccounting,

    // Pool used for staking cannot be spent
    staking_pool: Option<PoolId>,

    account_nonce_getter: Box<dyn Fn(AccountType) -> Option<AccountNonce> + 'a>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,

    // Transaction is composed of multiple inputs and outputs
    // but pools, delegations and tokens can be created only once per transaction
    token_can_be_issued: bool,
    order_can_be_created: bool,
    stake_pool_can_be_created: bool,
    delegation_can_be_created: bool,

    account_command_used: bool,

    // There can be only one Unmint operation per transaction.
    // But it's unknown in advance which token burn would be utilized by unmint operation
    // so we have to collect all burns for all tokens just in case.
    unmint_for: Option<TokenId>,
    total_tokens_burned: BTreeMap<TokenId, Amount>,

    fee_input: Option<(TxInput, Amount)>,
}

impl<'a> RandomTxMaker<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chainstate: &'a TestChainstate,
        utxo_set: &'a UtxosDBInMemoryImpl,
        tokens_store: &'a InMemoryTokensAccounting,
        pos_accounting_store: &'a InMemoryPoSAccounting,
        orders_store: &'a InMemoryOrdersAccounting,
        staking_pool: Option<PoolId>,
        account_nonce_getter: Box<dyn Fn(AccountType) -> Option<AccountNonce> + 'a>,
    ) -> Self {
        Self {
            chainstate,
            utxo_set,
            tokens_store,
            pos_accounting_store,
            orders_store,
            staking_pool,
            account_nonce_getter,
            account_nonce_tracker: BTreeMap::new(),
            token_can_be_issued: true,
            order_can_be_created: true,
            stake_pool_can_be_created: true,
            delegation_can_be_created: true,
            account_command_used: false,
            unmint_for: None,
            total_tokens_burned: BTreeMap::new(),
            fee_input: None,
        }
    }

    pub fn make(
        mut self,
        rng: &mut (impl Rng + CryptoRng),
        staking_pools_observer: &mut impl StakingPoolsObserver,
        key_manager: &mut KeyManager,
    ) -> (
        Transaction,
        TokensAccountingDeltaData,
        PoSAccountingDeltaData,
        OrdersAccountingDeltaData,
    ) {
        let tokens_db = TokensAccountingDB::new(self.tokens_store);
        let mut tokens_cache = TokensAccountingCache::new(&tokens_db);

        let pos_db = PoSAccountingDB::new(self.pos_accounting_store);
        let mut pos_delta = PoSAccountingDelta::new(&pos_db);

        let orders_db = OrdersAccountingDB::new(self.orders_store);
        let mut orders_cache = OrdersAccountingCache::new(&orders_db);

        // Select random number of accounts to spend from
        let account_inputs = self.select_accounts(rng);

        // Spend from accounts first then from utxo because account commands affect the state (like freezing tokens)
        let (account_inputs, account_outputs) = self.create_account_spending(
            rng,
            &mut tokens_cache,
            &pos_db,
            &mut pos_delta,
            &mut orders_cache,
            &account_inputs,
            key_manager,
        );

        // Select random number of utxos to spend
        let inputs_with_utxos = {
            let mut inputs_with_utxos = self.select_utxos(rng);

            // Spending from a token account requires paying fee. Find sufficient utxo and put it aside.
            if inputs_with_utxos.len() > 1 {
                let fee = std::cmp::max(
                    self.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero()),
                    self.chainstate
                        .get_chain_config()
                        .token_change_authority_fee(BlockHeight::zero()),
                );
                let fee_input_position = inputs_with_utxos.iter().position(|(_, input_utxo)| {
                    super::get_output_value(input_utxo)
                        .is_some_and(|v| v.coin_amount().unwrap_or(Amount::ZERO) >= fee)
                });

                if let Some(index) = fee_input_position {
                    self.fee_input = Some(inputs_with_utxos.remove(index)).map(|v| {
                        (
                            v.0,
                            super::get_output_value(&v.1).unwrap().coin_amount().unwrap(),
                        )
                    })
                }
            }

            inputs_with_utxos
        };

        // Spend selected utxos
        let (inputs, mut outputs) = self.create_utxo_spending(
            rng,
            staking_pools_observer,
            &mut tokens_cache,
            &mut pos_delta,
            &mut orders_cache,
            key_manager,
            inputs_with_utxos,
        );

        let mut inputs: Vec<_> = inputs.into_iter().chain(account_inputs).collect();

        outputs.extend(account_outputs);

        if !inputs.is_empty() {
            // keep first element intact so that it's always a UtxoOutpoint for ids calculation
            inputs[1..].shuffle(rng);
        }
        outputs.shuffle(rng);

        // now that the inputs are in place calculate the ids and replace dummy values
        let (outputs, new_staking_pools) = Self::tx_outputs_post_process(
            rng,
            &mut pos_delta,
            &mut tokens_cache,
            &mut orders_cache,
            &inputs,
            outputs,
        );

        let tx = Transaction::new(0, inputs, outputs).unwrap();
        let tx_id = tx.get_id();

        // after tx id is calculated kernel inputs for new pools can be propagated
        tx.outputs().iter().enumerate().for_each(|(i, output)| match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => { /* do nothing */ }
            TxOutput::CreateStakePool(pool_id, _) => {
                let (staker_sk, vrf_sk) = new_staking_pools.get(pool_id).unwrap();
                staking_pools_observer.on_pool_created(
                    *pool_id,
                    staker_sk.clone(),
                    vrf_sk.clone(),
                    UtxoOutPoint::new(tx_id.into(), i as u32),
                );
            }
        });

        (
            tx,
            tokens_cache.consume(),
            pos_delta.consume(),
            orders_cache.consume(),
        )
    }

    fn select_utxos(&self, rng: &mut impl Rng) -> Vec<(TxInput, TxOutput)> {
        let number_of_inputs = rng.gen_range(1..5);
        self.utxo_set
            .utxos()
            .iter()
            .choose_multiple(rng, number_of_inputs)
            .iter()
            .filter_map(|(outpoint, utxo)| {
                let input = TxInput::Utxo((*outpoint).clone());
                let input_utxo = utxo.output().clone();
                match input_utxo {
                    TxOutput::LockThenTransfer(_, _, timelock) => {
                        self.check_timelock(&input, &timelock)
                    }
                    TxOutput::Htlc(_, ref htlc) => {
                        self.check_timelock(&input, &htlc.refund_timelock)
                    }
                    TxOutput::Transfer(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::CreateOrder(_) => true,
                }
                .then_some((input, input_utxo))
            })
            .collect()
    }

    fn select_accounts(&self, rng: &mut impl Rng) -> Vec<AccountType> {
        let number_of_inputs = rng.gen_range(1..5);

        let tokens = self
            .tokens_store
            .tokens_data()
            .iter()
            .choose_multiple(rng, number_of_inputs)
            .iter()
            .map(|(token_id, _)| AccountType::Token(**token_id))
            .collect::<Vec<_>>();

        let orders = self
            .orders_store
            .orders_data()
            .iter()
            .choose_multiple(rng, number_of_inputs)
            .iter()
            .map(|(id, _)| AccountType::Order(**id))
            .collect::<Vec<_>>();

        let mut result = self
            .pos_accounting_store
            .all_delegation_balances()
            .iter()
            .choose_multiple(rng, number_of_inputs)
            .iter()
            .map(|(id, _)| AccountType::Delegation(**id))
            .collect::<Vec<_>>();

        result.extend_from_slice(&tokens);
        result.extend_from_slice(&orders);
        result.shuffle(rng);

        result
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

    // This function accepts 2 PoS accounting views:
    //     - latest state including modifications from current tx
    //     - state before current tx.
    // It's important because spending from delegation accounts must be based on balance that
    // does not include top-ups made in current transaction.
    #[allow(clippy::too_many_arguments)]
    fn create_account_spending(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        pos_accounting_before_tx: &impl PoSAccountingView,
        pos_accounting_latest: &mut (impl PoSAccountingView
                  + PoSAccountingOperations<PoSAccountingUndo>),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        accounts: &[AccountType],
        key_manager: &mut KeyManager,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for account_type in accounts.iter().copied() {
            match account_type {
                AccountType::Delegation(delegation_id) => {
                    let balance =
                        pos_accounting_before_tx.get_delegation_balance(delegation_id).unwrap();
                    if balance > Amount::ZERO {
                        let to_spend = Amount::from_atoms(rng.gen_range(1..=balance.into_atoms()));
                        let new_nonce = self.get_next_nonce(AccountType::Delegation(delegation_id));

                        result_inputs.push(TxInput::Account(AccountOutPoint::new(
                            new_nonce,
                            AccountSpending::DelegationBalance(delegation_id, to_spend),
                        )));

                        let lock_period = self
                            .chainstate
                            .get_chain_config()
                            .staking_pool_spend_maturity_block_count(
                                self.chainstate.get_best_block_height().unwrap(),
                            );
                        result_outputs.push(TxOutput::LockThenTransfer(
                            OutputValue::Coin(to_spend),
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                            OutputTimeLock::ForBlockCount(lock_period.to_int()),
                        ));

                        let _ = pos_accounting_latest
                            .spend_share_from_delegation_id(delegation_id, to_spend)
                            .unwrap();
                    }
                }
                AccountType::Token(token_id) => {
                    let (inputs, outputs) = self.create_token_account_spending(
                        rng,
                        tokens_cache,
                        token_id,
                        key_manager,
                    );

                    result_inputs.extend(inputs);
                    result_outputs.extend(outputs);
                }
                AccountType::Order(order_id) => {
                    let switch = rng.gen_range(0..3);

                    if !self.account_command_used && switch != 0 {
                        // conclude an order
                        let order_data = orders_cache.get_order_data(&order_id).unwrap().unwrap();
                        if !is_frozen_token(order_data.ask(), tokens_cache)
                            && !is_frozen_token(order_data.give(), tokens_cache)
                        {
                            let available_give_balance =
                                orders_cache.get_give_balance(&order_id).unwrap();
                            let give_output =
                                output_value_with_amount(order_data.give(), available_give_balance);

                            let current_ask_balance =
                                orders_cache.get_ask_balance(&order_id).unwrap();
                            let filled_amount = (output_value_amount(order_data.ask())
                                - current_ask_balance)
                                .unwrap();
                            let filled_output =
                                output_value_with_amount(order_data.ask(), filled_amount);

                            result_inputs.push(TxInput::OrderAccountCommand(
                                OrderAccountCommand::ConcludeOrder(order_id),
                            ));

                            let _ = orders_cache.conclude_order(order_id).unwrap();
                            self.account_command_used = true;

                            result_outputs.extend(vec![
                                TxOutput::Transfer(
                                    give_output,
                                    key_manager
                                        .new_destination(self.chainstate.get_chain_config(), rng),
                                ),
                                TxOutput::Transfer(
                                    filled_output,
                                    key_manager
                                        .new_destination(self.chainstate.get_chain_config(), rng),
                                ),
                            ]);
                        }
                    } else if !self.account_command_used
                        && !is_frozen_order(&orders_cache, order_id)
                    {
                        // freeze an order
                        result_inputs.push(TxInput::OrderAccountCommand(
                            OrderAccountCommand::FreezeOrder(order_id),
                        ));

                        let _ = orders_cache.freeze_order(order_id).unwrap();
                        self.account_command_used = true;
                    }
                }
            }
        }

        (result_inputs, result_outputs)
    }

    fn create_token_account_spending(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        token_id: TokenId,
        key_manager: &mut KeyManager,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        if self.account_command_used || self.fee_input.is_none() {
            return (Vec::new(), Vec::new());
        }

        let (fee_input, fee_available_amount) = self.fee_input.clone().unwrap();

        let token_data = tokens_cache.get_token_data(&token_id).unwrap().unwrap();
        let tokens_accounting::TokenData::FungibleToken(token_data) = token_data;

        if token_data.is_frozen() {
            if token_data.can_be_unfrozen() {
                // Unfreeze
                let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                let account_input =
                    TxInput::AccountCommand(new_nonce, AccountCommand::UnfreezeToken(token_id));

                let _ = tokens_cache.unfreeze_token(token_id).unwrap();
                self.account_command_used = true;
                self.fee_input = None;

                let required_fee =
                    self.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
                let fee_change_output = TxOutput::Transfer(
                    OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                    Destination::AnyoneCanSpend,
                );

                (vec![account_input, fee_input], vec![fee_change_output])
            } else {
                (Vec::new(), Vec::new())
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

                let _ = tokens_cache.freeze_token(token_id, unfreezable).unwrap();
                self.account_command_used = true;
                self.fee_input = None;

                let required_fee =
                    self.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
                let fee_change_output = TxOutput::Transfer(
                    OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                    Destination::AnyoneCanSpend,
                );

                (vec![account_input, fee_input], vec![fee_change_output])
            } else {
                (Vec::new(), Vec::new())
            }
        } else if rng.gen_bool(0.1) {
            // Change token authority
            let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
            let new_authority =
                key_manager.new_destination(self.chainstate.get_chain_config(), rng);
            let account_input = TxInput::AccountCommand(
                new_nonce,
                AccountCommand::ChangeTokenAuthority(token_id, new_authority.clone()),
            );

            let _ = tokens_cache.change_authority(token_id, new_authority).unwrap();
            self.account_command_used = true;
            self.fee_input = None;

            let required_fee = self
                .chainstate
                .get_chain_config()
                .token_change_authority_fee(BlockHeight::zero());
            let fee_change_output = TxOutput::Transfer(
                OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                Destination::AnyoneCanSpend,
            );

            (vec![account_input, fee_input], vec![fee_change_output])
        } else if rng.gen_bool(0.1) {
            // Change token metadata uri
            let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
            let max_len = self.chainstate.get_chain_config().token_max_uri_len();
            let new_metadata_uri =
                random_ascii_alphanumeric_string(rng, 1..=max_len).as_bytes().to_vec();
            let account_input = TxInput::AccountCommand(
                new_nonce,
                AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri.clone()),
            );

            let _ = tokens_cache.change_metadata_uri(token_id, new_metadata_uri).unwrap();
            self.account_command_used = true;
            self.fee_input = None;

            let required_fee = self.chainstate.get_chain_config().token_change_metadata_uri_fee();
            let fee_change_output = TxOutput::Transfer(
                OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                Destination::AnyoneCanSpend,
            );

            (vec![account_input, fee_input], vec![fee_change_output])
        } else if !token_data.is_locked() {
            if rng.gen_bool(0.9) {
                let circulating_supply = tokens_cache.get_circulating_supply(&token_id).unwrap();

                // mint
                let supply_limit = match token_data.total_supply() {
                    TokenTotalSupply::Fixed(v) => *v,
                    TokenTotalSupply::Lockable | TokenTotalSupply::Unlimited => {
                        Amount::from_atoms(i128::MAX as u128)
                    }
                };

                let supply_left = (supply_limit - circulating_supply).unwrap();
                if supply_left == Amount::ZERO {
                    return (Vec::new(), Vec::new());
                }

                let mint_limit = std::cmp::min(100_000, supply_left.into_atoms());
                let to_mint = Amount::from_atoms(rng.gen_range(1..=mint_limit));

                let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                let account_input = TxInput::AccountCommand(
                    new_nonce,
                    AccountCommand::MintTokens(token_id, to_mint),
                );

                let required_fee =
                    self.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
                let fee_change_output = TxOutput::Transfer(
                    OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                    Destination::AnyoneCanSpend,
                );

                let outputs = vec![
                    TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, to_mint),
                        key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                    ),
                    fee_change_output,
                ];

                let _ = tokens_cache.mint_tokens(token_id, to_mint).unwrap();
                self.account_command_used = true;
                self.fee_input = None;

                (vec![account_input, fee_input], outputs)
            } else {
                let can_be_locked = match tokens_cache.get_token_data(&token_id).unwrap().unwrap() {
                    tokens_accounting::TokenData::FungibleToken(data) => {
                        !data.is_locked() && data.try_lock().is_ok()
                    }
                };

                if can_be_locked {
                    let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                    let account_input = TxInput::AccountCommand(
                        new_nonce,
                        AccountCommand::LockTokenSupply(token_id),
                    );

                    let _ = tokens_cache.lock_circulating_supply(token_id).unwrap();
                    self.account_command_used = true;
                    self.fee_input = None;

                    let required_fee = self
                        .chainstate
                        .get_chain_config()
                        .token_supply_change_fee(BlockHeight::zero());
                    let fee_change_output = TxOutput::Transfer(
                        OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                        Destination::AnyoneCanSpend,
                    );

                    (vec![account_input, fee_input], vec![fee_change_output])
                } else {
                    (Vec::new(), Vec::new())
                }
            }
        } else {
            (Vec::new(), Vec::new())
        }
    }

    /// Given an output as in input creates multiple new random outputs.
    #[allow(clippy::too_many_arguments)]
    fn create_utxo_spending(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        staking_pools_observer: &mut impl StakingPoolsObserver,
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        key_manager: &mut KeyManager,
        inputs: Vec<(TxInput, TxOutput)>,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for (input, input_utxo) in inputs.into_iter() {
            let (new_inputs, new_outputs) = match &input_utxo {
                TxOutput::Transfer(v, _) => self.spend_output_value(
                    rng,
                    tokens_cache,
                    pos_accounting_cache,
                    orders_cache,
                    input,
                    v,
                    key_manager,
                ),
                TxOutput::LockThenTransfer(v, _, timelock) => {
                    let timelock_passed = self.check_timelock(&input, timelock);

                    if timelock_passed {
                        self.spend_output_value(
                            rng,
                            tokens_cache,
                            pos_accounting_cache,
                            orders_cache,
                            input,
                            v,
                            key_manager,
                        )
                    } else {
                        (Vec::new(), Vec::new())
                    }
                }
                TxOutput::CreateStakePool(pool_id, _)
                | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    if self.staking_pool.is_none_or(|id| id != *pool_id) && rng.gen_bool(0.1) {
                        let staker_balance = pos_accounting_cache
                            .get_pool_data(*pool_id)
                            .unwrap()
                            .unwrap()
                            .staker_balance()
                            .unwrap();
                        let _ = pos_accounting_cache.decommission_pool(*pool_id).unwrap();
                        staking_pools_observer.on_pool_decommissioned(*pool_id);

                        let lock_period = self
                            .chainstate
                            .get_chain_config()
                            .staking_pool_spend_maturity_block_count(
                                self.chainstate.get_best_block_height().unwrap(),
                            );
                        (
                            vec![input],
                            vec![TxOutput::LockThenTransfer(
                                OutputValue::Coin(staker_balance),
                                key_manager
                                    .new_destination(self.chainstate.get_chain_config(), rng),
                                OutputTimeLock::ForBlockCount(lock_period.to_int()),
                            )],
                        )
                    } else {
                        (Vec::new(), Vec::new())
                    }
                }
                TxOutput::IssueNft(token_id, _, _) => {
                    let (mut new_inputs, new_outputs) = self.spend_tokens_v1(
                        rng,
                        tokens_cache,
                        orders_cache,
                        *token_id,
                        Amount::from_atoms(1),
                        key_manager,
                    );
                    new_inputs.push(input);
                    (new_inputs, new_outputs)
                }
                TxOutput::Htlc(v, htlc) => {
                    // TODO: currently only refund spending is supported
                    let timelock_passed = self.check_timelock(&input, &htlc.refund_timelock);

                    if timelock_passed {
                        self.spend_output_value(
                            rng,
                            tokens_cache,
                            pos_accounting_cache,
                            orders_cache,
                            input,
                            v,
                            key_manager,
                        )
                    } else {
                        (Vec::new(), Vec::new())
                    }
                }
                TxOutput::Burn(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateOrder(_) => unreachable!(),
            };

            result_inputs.extend(new_inputs);
            result_outputs.extend(new_outputs);
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
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        key_manager: &mut KeyManager,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        if coins == Amount::ZERO {
            return (Vec::new(), Vec::new());
        }

        let atoms_vec = test_utils::split_value(rng, coins.into_atoms())
            .into_iter()
            .filter(|v| *v > 0)
            .collect::<Vec<_>>();

        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for atoms_to_spend in atoms_vec {
            let switch = rng.gen_range(0..6);
            let amount_to_spend = Amount::from_atoms(atoms_to_spend);
            if switch == 0 && self.token_can_be_issued {
                // issue token v1
                let min_tx_fee = self.chainstate.get_chain_config().fungible_token_issuance_fee();
                if amount_to_spend >= min_tx_fee {
                    self.token_can_be_issued = false;
                    let change = (amount_to_spend - min_tx_fee).unwrap();
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    let outputs = vec![
                        TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                            random_token_issuance_v1(
                                self.chainstate.get_chain_config(),
                                key_manager
                                    .new_destination(self.chainstate.get_chain_config(), rng),
                                rng,
                            ),
                        ))),
                        TxOutput::Transfer(
                            OutputValue::Coin(change),
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                        ),
                    ];

                    result_outputs.extend_from_slice(&outputs);
                }
            } else if switch == 1 && self.token_can_be_issued {
                // issue nft v1
                let min_tx_fee =
                    self.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
                if amount_to_spend >= min_tx_fee {
                    self.token_can_be_issued = false;
                    let change = (amount_to_spend - min_tx_fee).unwrap();

                    let dummy_inputs = vec![TxInput::from_utxo(
                        OutPointSourceId::Transaction(Id::<Transaction>::new(H256::zero())),
                        0,
                    )];
                    let dummy_token_id = make_token_id(&dummy_inputs).unwrap();
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    let outputs = vec![
                        TxOutput::IssueNft(
                            dummy_token_id,
                            Box::new(NftIssuance::V0(random_nft_issuance(
                                self.chainstate.get_chain_config(),
                                rng,
                            ))),
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                        ),
                        TxOutput::Transfer(
                            OutputValue::Coin(change),
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                        ),
                    ];

                    result_outputs.extend_from_slice(&outputs);
                }
            } else if switch == 2 && self.order_can_be_created {
                // create order to exchange part of available coins for tokens
                if let Some((token_id, token_supply)) =
                    get_random_token(rng, self.tokens_store, tokens_cache)
                {
                    if token_supply > Amount::ZERO {
                        let ask_amount =
                            Amount::from_atoms(rng.gen_range(1u128..=token_supply.into_atoms()));
                        let give_amount = Amount::from_atoms(rng.gen_range(1u128..=atoms_to_spend));
                        let order_data = OrderData::new(
                            Destination::AnyoneCanSpend,
                            OutputValue::TokenV1(token_id, ask_amount),
                            OutputValue::Coin(give_amount),
                        );
                        let change = (amount_to_spend - give_amount).unwrap();

                        // Transfer output is created intentionally besides order output to not waste utxo
                        // (e.g. single genesis output on issuance)
                        let outputs = vec![
                            TxOutput::CreateOrder(Box::new(order_data)),
                            TxOutput::Transfer(
                                OutputValue::Coin(change),
                                key_manager
                                    .new_destination(self.chainstate.get_chain_config(), rng),
                            ),
                        ];

                        self.order_can_be_created = false;

                        result_outputs.extend_from_slice(&outputs);
                    }
                }
            } else if switch == 3 && !self.account_command_used {
                // try fill order
                let fill_value = OutputValue::Coin(amount_to_spend);
                if let Some(order_id) =
                    get_random_order_to_fill(self.orders_store, &orders_cache, &fill_value)
                {
                    let filled_value =
                        calculate_filled_order_value(&orders_cache, order_id, amount_to_spend)
                            .unwrap();

                    if let Some(filled_value) = filled_value {
                        if !is_frozen_token(&filled_value, tokens_cache)
                            && !is_frozen_order(&orders_cache, order_id)
                        {
                            let input =
                                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                                    order_id,
                                    amount_to_spend,
                                    key_manager
                                        .new_destination(self.chainstate.get_chain_config(), rng),
                                ));

                            let output = TxOutput::Transfer(
                                filled_value,
                                key_manager
                                    .new_destination(self.chainstate.get_chain_config(), rng),
                            );

                            let _ = orders_cache
                                .fill_order(order_id, amount_to_spend, OrdersVersion::V1)
                                .unwrap();
                            self.account_command_used = true;

                            result_inputs.push(input);
                            result_outputs.push(output);
                        }
                    }
                }
            } else if switch == 6 {
                // data deposit
                let min_tx_fee =
                    self.chainstate.get_chain_config().data_deposit_fee(BlockHeight::zero());
                if amount_to_spend >= min_tx_fee {
                    let change = (amount_to_spend - min_tx_fee).unwrap();

                    let deposited_data_len = self
                        .chainstate
                        .get_chain_config()
                        .data_deposit_max_size(BlockHeight::zero());
                    let deposited_data_len = rng.gen_range(0..deposited_data_len);
                    let deposited_data =
                        (0..deposited_data_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

                    let outputs = vec![
                        TxOutput::DataDeposit(deposited_data),
                        TxOutput::Transfer(
                            OutputValue::Coin(change),
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                        ),
                    ];

                    result_outputs.extend_from_slice(&outputs);
                }
            } else {
                // transfer coins
                let output = if amount_to_spend
                    >= self.chainstate.get_chain_config().min_stake_pool_pledge()
                    && self.stake_pool_can_be_created
                {
                    // If enough coins for pledge - create a pool
                    let dummy_pool_id = PoolId::new(H256::zero());
                    self.stake_pool_can_be_created = false;

                    let pool_data = StakePoolData::new(
                        amount_to_spend,
                        Destination::AnyoneCanSpend,
                        VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel).1,
                        Destination::AnyoneCanSpend,
                        PerThousand::new_from_rng(rng),
                        Amount::from_atoms(rng.gen_range(0..1000)),
                    );

                    TxOutput::CreateStakePool(dummy_pool_id, Box::new(pool_data))
                } else {
                    if rng.gen_bool(0.3) {
                        // Send coins to random delegation
                        if let Some((delegation_id, _)) = get_random_delegation_data(
                            rng,
                            self.pos_accounting_store,
                            &pos_accounting_cache,
                        ) {
                            let _ = pos_accounting_cache
                                .delegate_staking(*delegation_id, amount_to_spend)
                                .unwrap();
                            result_outputs
                                .push(TxOutput::DelegateStaking(amount_to_spend, *delegation_id));
                            continue;
                        }
                    }

                    let destination =
                        key_manager.new_destination(self.chainstate.get_chain_config(), rng);
                    let timelock = get_random_timelock(rng, self.chainstate);
                    match rng.gen_range(0..5) {
                        0 => TxOutput::LockThenTransfer(
                            OutputValue::Coin(amount_to_spend),
                            destination,
                            timelock,
                        ),
                        1 => TxOutput::Htlc(
                            OutputValue::Coin(amount_to_spend),
                            Box::new(HashedTimelockContract {
                                secret_hash: HtlcSecretHash::zero(),
                                spend_key: destination,
                                refund_timelock: timelock,
                                refund_key: key_manager.new_2_of_2_multisig_destination(
                                    self.chainstate.get_chain_config(),
                                    rng,
                                ),
                            }),
                        ),
                        2..=4 => {
                            TxOutput::Transfer(OutputValue::Coin(amount_to_spend), destination)
                        }
                        _ => unreachable!(),
                    }
                };

                result_outputs.push(output);

                // Occasionally create new delegation id
                if rng.gen::<bool>() && self.delegation_can_be_created {
                    if let Some((pool_id, _)) =
                        get_random_pool_data(rng, self.pos_accounting_store, &pos_accounting_cache)
                    {
                        self.delegation_can_be_created = false;

                        result_outputs.push(TxOutput::CreateDelegationId(
                            key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                            *pool_id,
                        ));
                    }
                }
            }
        }
        (result_inputs, result_outputs)
    }

    #[allow(clippy::too_many_arguments)]
    fn spend_output_value(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        input: TxInput,
        input_utxo_value: &OutputValue,
        key_manager: &mut KeyManager,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        let mut result_inputs = vec![input];
        let mut result_outputs = Vec::new();

        match input_utxo_value {
            OutputValue::Coin(coins) => {
                let (new_inputs, new_outputs) = self.spend_coins(
                    rng,
                    *coins,
                    tokens_cache,
                    pos_accounting_cache,
                    orders_cache,
                    key_manager,
                );
                result_inputs.extend(new_inputs);
                result_outputs.extend(new_outputs);
            }
            OutputValue::TokenV0(_) => {
                unimplemented!("deprecated tokens version")
            }
            OutputValue::TokenV1(token_id, amount) => {
                let token_data = tokens_cache.get_token_data(token_id).unwrap();
                if let Some(token_data) = token_data {
                    let tokens_accounting::TokenData::FungibleToken(token_data) = token_data;
                    if !token_data.is_frozen() {
                        let (new_inputs, new_outputs) = self.spend_tokens_v1(
                            rng,
                            tokens_cache,
                            orders_cache,
                            *token_id,
                            *amount,
                            key_manager,
                        );
                        result_inputs.extend(new_inputs);
                        result_outputs.extend(new_outputs);
                    }
                }
            }
        };

        (result_inputs, result_outputs)
    }

    fn spend_tokens_v1(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        token_id: TokenId,
        amount: Amount,
        key_manager: &mut KeyManager,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        if amount == Amount::ZERO {
            return (Vec::new(), Vec::new());
        }

        let atoms_vec = test_utils::split_value(rng, amount.into_atoms());
        let mut result_inputs = Vec::new();
        let mut result_outputs = Vec::new();

        for atoms in atoms_vec {
            if rng.gen::<bool>() {
                let output_value = OutputValue::TokenV1(token_id, Amount::from_atoms(atoms));
                if rng.gen::<bool>() {
                    // transfer
                    result_outputs.push(TxOutput::Transfer(
                        output_value,
                        key_manager.new_destination(self.chainstate.get_chain_config(), rng),
                    ));
                } else if !self.account_command_used {
                    // try fill order
                    if let Some(order_id) =
                        get_random_order_to_fill(self.orders_store, &orders_cache, &output_value)
                    {
                        let filled_value = calculate_filled_order_value(
                            &orders_cache,
                            order_id,
                            Amount::from_atoms(atoms),
                        )
                        .unwrap();

                        if let Some(filled_value) = filled_value {
                            if !is_frozen_token(&filled_value, tokens_cache)
                                && !is_frozen_order(orders_cache, order_id)
                            {
                                result_outputs.push(TxOutput::Transfer(
                                    filled_value,
                                    key_manager
                                        .new_destination(self.chainstate.get_chain_config(), rng),
                                ));

                                result_inputs.push(TxInput::OrderAccountCommand(
                                    OrderAccountCommand::FillOrder(
                                        order_id,
                                        Amount::from_atoms(atoms),
                                        key_manager.new_destination(
                                            self.chainstate.get_chain_config(),
                                            rng,
                                        ),
                                    ),
                                ));

                                let _ = orders_cache
                                    .fill_order(
                                        order_id,
                                        Amount::from_atoms(atoms),
                                        OrdersVersion::V1,
                                    )
                                    .unwrap();
                                self.account_command_used = true;
                            }
                        }
                    }
                }
            } else if rng.gen_bool(0.4) && !self.account_command_used {
                // unmint
                let token_data = tokens_cache.get_token_data(&token_id).unwrap();

                // check token_data as well because it can be an nft
                if let Some(token_data) = token_data {
                    let tokens_accounting::TokenData::FungibleToken(token_data) = token_data;
                    if !token_data.is_locked()
                        && !token_data.is_frozen()
                        && self.fee_input.is_some()
                    {
                        let to_unmint = Amount::from_atoms(atoms);

                        let circulating_supply =
                            tokens_cache.get_circulating_supply(&token_id).unwrap();
                        assert!(circulating_supply >= to_unmint);

                        let new_nonce = self.get_next_nonce(AccountType::Token(token_id));
                        let account_input = TxInput::AccountCommand(
                            new_nonce,
                            AccountCommand::UnmintTokens(token_id),
                        );

                        let (fee_input, fee_available_amount) = self.fee_input.take().unwrap();

                        result_inputs.extend(vec![account_input, fee_input]);

                        let required_fee = self
                            .chainstate
                            .get_chain_config()
                            .token_supply_change_fee(BlockHeight::zero());
                        let fee_change_output = TxOutput::Transfer(
                            OutputValue::Coin((fee_available_amount - required_fee).unwrap()),
                            Destination::AnyoneCanSpend,
                        );

                        let outputs = vec![
                            TxOutput::Burn(OutputValue::TokenV1(token_id, to_unmint)),
                            fee_change_output,
                        ];
                        result_outputs.extend(outputs);

                        self.unmint_for = Some(token_id);
                        self.account_command_used = true;
                    }
                }
            } else if rng.gen_bool(0.4) && self.order_can_be_created && atoms > 0 {
                // create order to exchange part of available tokens for coins or other tokens
                let random_token = get_random_token(rng, self.tokens_store, tokens_cache);
                let ask_value = if rng.gen::<bool>()
                    && random_token
                        .is_some_and(|(id, amount)| id != token_id && amount > Amount::ZERO)
                {
                    OutputValue::TokenV1(random_token.unwrap().0, random_token.unwrap().1)
                } else {
                    OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..10000)))
                };

                let give_value = OutputValue::TokenV1(token_id, Amount::from_atoms(atoms));
                let order_data = OrderData::new(Destination::AnyoneCanSpend, ask_value, give_value);
                result_outputs.push(TxOutput::CreateOrder(Box::new(order_data)));
                self.order_can_be_created = false;
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

    fn tx_outputs_post_process(
        rng: &mut (impl Rng + CryptoRng),
        pos_accounting_cache: &mut (impl PoSAccountingView + PoSAccountingOperations<PoSAccountingUndo>),
        tokens_cache: &mut (impl TokensAccountingView + TokensAccountingOperations),
        orders_cache: &mut (impl OrdersAccountingView + OrdersAccountingOperations),
        inputs: &[TxInput],
        outputs: Vec<TxOutput>,
    ) -> (Vec<TxOutput>, BTreeMap<PoolId, (PrivateKey, VRFPrivateKey)>) {
        let mut new_staking_pools = BTreeMap::new();

        let outputs = outputs
            .into_iter()
            .filter_map(|mut output| match &mut output {
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::Htlc(_, _) => Some(output),
                TxOutput::CreateStakePool(dummy_pool_id, pool_data) => {
                    let pool_id = make_pool_id(inputs[0].utxo_outpoint().unwrap());
                    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
                    let (staker_sk, staker_pk) =
                        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

                    *dummy_pool_id = pool_id;
                    *pool_data = Box::new(StakePoolData::new(
                        pool_data.pledge(),
                        Destination::PublicKey(staker_pk),
                        vrf_pk,
                        Destination::AnyoneCanSpend,
                        pool_data.margin_ratio_per_thousand(),
                        pool_data.cost_per_block(),
                    ));
                    let _ = pos_accounting_cache
                        .create_pool(pool_id, pool_data.as_ref().clone().into())
                        .unwrap();

                    new_staking_pools.insert(pool_id, (staker_sk, vrf_sk));

                    Some(output)
                }
                TxOutput::CreateDelegationId(destination, pool_id) => {
                    if pos_accounting_cache.pool_exists(*pool_id).unwrap() {
                        let _ = pos_accounting_cache
                            .create_delegation_id(
                                *pool_id,
                                destination.clone(),
                                inputs[0].utxo_outpoint().unwrap(),
                            )
                            .unwrap();
                        Some(output)
                    } else {
                        None // if a pool was decommissioned in this tx then skip creating a delegation
                    }
                }
                TxOutput::IssueFungibleToken(issuance) => {
                    let token_id = make_token_id(inputs).unwrap();
                    let data = tokens_accounting::TokenData::FungibleToken(
                        issuance.as_ref().clone().into(),
                    );
                    let _ = tokens_cache.issue_token(token_id, data);
                    Some(output)
                }
                TxOutput::IssueNft(dummy_token_id, _, _) => {
                    *dummy_token_id = make_token_id(inputs).unwrap();
                    Some(output)
                }
                TxOutput::CreateOrder(data) => {
                    let order_id = make_order_id(inputs[0].utxo_outpoint().unwrap());
                    let _ =
                        orders_cache.create_order(order_id, data.as_ref().clone().into()).unwrap();
                    Some(output)
                }
            })
            .collect();

        (outputs, new_staking_pools)
    }

    fn check_timelock(&self, input: &TxInput, timelock: &OutputTimeLock) -> bool {
        let utxo_block_height = self
            .chainstate
            .utxo(input.utxo_outpoint().unwrap())
            .unwrap()
            .unwrap()
            .source()
            .clone()
            .blockchain_height()
            .unwrap();
        let utxo_block_id = self
            .chainstate
            .get_block_id_from_height(&utxo_block_height)
            .unwrap()
            .unwrap()
            .classify(self.chainstate.get_chain_config());

        let time_of_tx = match utxo_block_id {
            GenBlockId::Block(id) => {
                self.chainstate.get_block_header(id).unwrap().unwrap().timestamp()
            }
            GenBlockId::Genesis(_) => {
                self.chainstate.get_chain_config().genesis_block().timestamp()
            }
        };
        let current_time = self
            .chainstate
            .calculate_median_time_past(&self.chainstate.get_best_block_id().unwrap())
            .unwrap();
        let current_height = self.chainstate.get_best_block_height().unwrap();

        tx_verifier::timelock_check::check_timelock(
            &utxo_block_height,
            &time_of_tx,
            timelock,
            &current_height,
            &current_time,
            input.utxo_outpoint().unwrap(),
        )
        .is_ok()
    }
}

fn is_frozen_token(value: &OutputValue, view: &impl TokensAccountingView) -> bool {
    match value {
        OutputValue::Coin(_) | OutputValue::TokenV0(_) => false,
        OutputValue::TokenV1(token_id, _) => {
            view.get_token_data(token_id).unwrap().is_some_and(|data| match data {
                tokens_accounting::TokenData::FungibleToken(data) => data.is_frozen(),
            })
        }
    }
}

fn is_frozen_order(view: &impl OrdersAccountingView, order_id: OrderId) -> bool {
    view.get_order_data(&order_id).unwrap().unwrap().is_frozen()
}

fn calculate_filled_order_value(
    view: &impl OrdersAccountingView,
    order_id: OrderId,
    fill: Amount,
) -> Result<Option<OutputValue>, orders_accounting::Error> {
    let order_data = view.get_order_data(&order_id).unwrap().unwrap();

    let result = orders_accounting::calculate_fill_order(view, order_id, fill, OrdersVersion::V1);

    match result {
        Ok(filled_amount) => Ok(Some(output_value_with_amount(
            order_data.give(),
            filled_amount,
        ))),
        Err(orders_accounting::Error::OrderUnderbid(..)) => Ok(None),
        Err(e) => Err(e),
    }
}
