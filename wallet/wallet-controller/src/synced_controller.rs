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

use std::collections::{BTreeMap, BTreeSet};

use common::{
    address::Address,
    chain::{
        signature::inputsig::arbitrary_message::ArbitraryMessageSignature,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, RPCTokenInfo, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        ChainConfig, DelegationId, Destination, PoolId, SignedTransaction, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Id},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use futures::{stream::FuturesUnordered, TryStreamExt};
use logging::log;
use mempool::FeeRate;
use node_comm::node_traits::NodeInterface;
use wallet::{
    account::{
        currency_grouper::Currency, PartiallySignedTransaction, TransactionToSign,
        UnconfirmedTokenInfo,
    },
    get_tx_output_destination,
    send_request::{
        make_address_output, make_address_output_token, make_create_delegation_output,
        make_data_deposit_output, SelectedInputs, StakePoolDataArguments,
    },
    wallet::WalletPoolsFilter,
    wallet_events::WalletEvents,
    DefaultWallet, WalletError, WalletResult,
};
use wallet_types::{
    utxo_types::{UtxoState, UtxoType},
    with_locked::WithLocked,
};

use crate::{into_balances, types::Balances, ControllerConfig, ControllerError};

pub struct SyncedController<'a, T, W> {
    wallet: &'a mut DefaultWallet,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    wallet_events: &'a W,
    staking_started: &'a mut BTreeSet<U31>,
    account_index: U31,
    config: ControllerConfig,
}

impl<'a, T: NodeInterface, W: WalletEvents> SyncedController<'a, T, W> {
    pub fn new(
        wallet: &'a mut DefaultWallet,
        rpc_client: T,
        chain_config: &'a ChainConfig,
        wallet_events: &'a W,
        staking_started: &'a mut BTreeSet<U31>,
        account_index: U31,
        config: ControllerConfig,
    ) -> Self {
        Self {
            wallet,
            rpc_client,
            chain_config,
            wallet_events,
            staking_started,
            account_index,
            config,
        }
    }

    pub async fn get_token_info(
        &self,
        token_id: TokenId,
    ) -> Result<RPCTokenInfo, ControllerError<T>> {
        self.rpc_client
            .get_token_info(token_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownTokenId(
                token_id,
            )))
    }

    async fn fetch_token_infos(
        &self,
        tokens: BTreeSet<TokenId>,
    ) -> Result<Vec<RPCTokenInfo>, ControllerError<T>> {
        let tasks: FuturesUnordered<_> =
            tokens.into_iter().map(|token_id| self.get_token_info(token_id)).collect();
        tasks.try_collect().await
    }

    /// Check that the selected UTXOs not contain tokens that are frozen and can't be used
    pub async fn check_tokens_in_selected_utxo(
        &self,
        input_utxos: &[UtxoOutPoint],
    ) -> Result<(), ControllerError<T>> {
        let utxos = self
            .wallet
            .find_used_tokens(self.account_index, input_utxos)
            .map_err(ControllerError::WalletError)?;

        for token_info in self.fetch_token_infos(utxos).await? {
            match token_info {
                RPCTokenInfo::FungibleToken(token_info) => self
                    .wallet
                    .get_token_unconfirmed_info(self.account_index, &token_info)
                    .map_err(ControllerError::WalletError)?
                    .check_can_be_used()
                    .map_err(ControllerError::WalletError)?,
                RPCTokenInfo::NonFungibleToken(_) => {}
            }
        }
        Ok(())
    }

    /// Filter out utxos that contain tokens that are frozen and can't be used
    async fn filter_out_utxos_with_frozen_tokens(
        &self,
        input_utxos: Vec<(UtxoOutPoint, TxOutput, Option<TokenId>)>,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput, Option<TokenId>)>, ControllerError<T>> {
        let mut result = vec![];
        for utxo in input_utxos {
            if let Some(token_id) = utxo.2 {
                let token_info = self.get_token_info(token_id).await?;

                let ok_to_use = match token_info {
                    RPCTokenInfo::FungibleToken(token_info) => self
                        .wallet
                        .get_token_unconfirmed_info(self.account_index, &token_info)
                        .map_err(ControllerError::WalletError)?
                        .check_can_be_used()
                        .is_ok(),
                    RPCTokenInfo::NonFungibleToken(_) => true,
                };
                if ok_to_use {
                    result.push(utxo);
                }
            } else {
                result.push(utxo);
            }
        }
        Ok(result)
    }

    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .abandon_transaction(self.account_index, tx_id)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_address(
        &mut self,
    ) -> Result<(ChildNumber, Address<Destination>), ControllerError<T>> {
        self.wallet
            .get_new_address(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn find_public_key(
        &mut self,
        address: Destination,
    ) -> Result<PublicKey, ControllerError<T>> {
        self.wallet
            .find_public_key(self.account_index, address)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_vrf_key(
        &mut self,
    ) -> Result<(ChildNumber, Address<VRFPublicKey>), ControllerError<T>> {
        self.wallet
            .get_vrf_key(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub async fn issue_new_token(
        &mut self,
        address: Address<Destination>,
        token_ticker: Vec<u8>,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
        token_total_supply: TokenTotalSupply,
        is_freezable: IsTokenFreezable,
    ) -> Result<(SignedTransaction, TokenId), ControllerError<T>> {
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.issue_new_token(
                    account_index,
                    TokenIssuance::V1(TokenIssuanceV1 {
                        token_ticker,
                        number_of_decimals,
                        metadata_uri,
                        total_supply: token_total_supply,
                        authority: address.into_object(),
                        is_freezable,
                    }),
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    pub async fn issue_new_nft(
        &mut self,
        address: Address<Destination>,
        metadata: Metadata,
    ) -> Result<(SignedTransaction, TokenId), ControllerError<T>> {
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.issue_new_nft(
                    account_index,
                    address,
                    metadata,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    pub async fn mint_tokens(
        &mut self,
        token_info: RPCTokenInfo,
        amount: Amount,
        address: Address<Destination>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                wallet.mint_tokens(
                    account_index,
                    token_info,
                    amount,
                    address,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }
    pub async fn unmint_tokens(
        &mut self,
        token_info: RPCTokenInfo,
        amount: Amount,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                wallet.unmint_tokens(
                    account_index,
                    token_info,
                    amount,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    pub async fn lock_token_supply(
        &mut self,
        token_info: RPCTokenInfo,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                wallet.lock_token_supply(
                    account_index,
                    token_info,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// After freezing a token all operations (transfer, mint, unmint...)
    /// on that token are forbidden until it is unfrozen
    pub async fn freeze_token(
        &mut self,
        token_info: RPCTokenInfo,
        is_token_unfreezable: IsTokenUnfreezable,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                wallet.freeze_token(
                    account_index,
                    token_info,
                    is_token_unfreezable,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// After unfreezing a token all operations on that token are again permitted
    pub async fn unfreeze_token(
        &mut self,
        token_info: RPCTokenInfo,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                wallet.unfreeze_token(
                    account_index,
                    token_info,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// After changing the authority of the token, all operations like mint/unmint/freeze/unfreeze
    /// will be controlled by the new authority
    pub async fn change_token_authority(
        &mut self,
        token_info: RPCTokenInfo,
        address: Address<Destination>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                wallet.change_token_authority(
                    account_index,
                    token_info,
                    address,
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    pub async fn deposit_data(
        &mut self,
        data: Vec<u8>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let outputs = make_data_deposit_output(self.chain_config, data)
            .map_err(ControllerError::WalletError)?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    outputs,
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// Create a transaction that transfers coins to the destination address and specified amount
    /// and broadcast it to the mempool.
    /// If the selected_utxos are not empty it will try to select inputs from those for the
    /// transaction, else it will use available ones from the wallet.
    pub async fn send_to_address(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        selected_utxos: Vec<UtxoOutPoint>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.check_tokens_in_selected_utxo(&selected_utxos).await?;

        let output = make_address_output(address, amount);
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(selected_utxos),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// Create a transaction that transfers all the coins and tokens to the destination address
    /// and broadcast it to the mempool.
    pub async fn sweep_addresses(
        &mut self,
        destination_address: Destination,
        from_addresses: BTreeSet<Destination>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let selected_utxos = self
            .wallet
            .get_utxos(
                self.account_index,
                UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
                UtxoState::Confirmed | UtxoState::Inactive,
                WithLocked::Unlocked,
            )
            .map_err(ControllerError::WalletError)?;

        let filtered_inputs = self
            .filter_out_utxos_with_frozen_tokens(selected_utxos)
            .await?
            .into_iter()
            .filter(|(_, output, _)| {
                get_tx_output_destination(output, &|_| None)
                    .map_or(false, |dest| from_addresses.contains(&dest))
            })
            .collect::<Vec<_>>();

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  _consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_sweep_transaction(
                    account_index,
                    destination_address,
                    filtered_inputs,
                    current_fee_rate,
                )
            },
        )
        .await
    }

    /// Create a transaction that transfers all the coins from a delegation to the destination address
    /// and broadcast it to the mempool.
    pub async fn sweep_delegation(
        &mut self,
        destination_address: Address<Destination>,
        delegation_id: DelegationId,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let pool_id = self
            .wallet
            .get_delegation(self.account_index, delegation_id)
            .map_err(ControllerError::WalletError)?
            .pool_id;

        let delegation_share = self
            .rpc_client
            .get_delegation_share(pool_id, delegation_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(
                WalletError::DelegationNotFound(delegation_id),
            ))?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  _consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_sweep_from_delegation_transaction(
                    account_index,
                    destination_address,
                    delegation_id,
                    delegation_share,
                    current_fee_rate,
                )
            },
        )
        .await
    }

    /// Create a partially signed transfer transaction to the destination address with the
    /// specified amount, from the specified utxo. The change from the transfer will be sent to the
    /// optionally specified change address, otherwise it will be sent to the destination from the
    /// input utxo itself.
    /// Returns the partially signed transaction and the fees that will be paid by it
    pub async fn request_send_to_address(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        selected_utxo: UtxoOutPoint,
        change_address: Option<Address<Destination>>,
    ) -> Result<(PartiallySignedTransaction, Balances), ControllerError<T>> {
        let output = make_address_output(address, amount);

        let utxo_output = self.fetch_utxo(&selected_utxo).await?;
        let change_address = if let Some(change_address) = change_address {
            change_address
        } else {
            let utxo_dest =
                get_tx_output_destination(&utxo_output, &|_| None).ok_or_else(|| {
                    ControllerError::WalletError(WalletError::UnsupportedTransactionOutput(
                        Box::new(utxo_output.clone()),
                    ))
                })?;
            Address::new(self.chain_config, utxo_dest).expect("addressable")
        };

        let selected_inputs = SelectedInputs::Inputs(vec![(selected_utxo, utxo_output)]);

        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let (req, fees) = self
            .wallet
            .create_unsigned_transaction_to_addresses(
                self.account_index,
                [output],
                selected_inputs,
                [(Currency::Coin, change_address)].into(),
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok((req, fees))
    }

    /// Create a transaction that creates a new delegation for the specified pool with the
    /// specified owner address, and broadcasts it to the mempool.
    /// Returns the new transaction's ID and the newly created Delegation ID
    pub async fn create_delegation(
        &mut self,
        address: Address<Destination>,
        pool_id: PoolId,
    ) -> Result<(SignedTransaction, DelegationId), ControllerError<T>> {
        let output = make_create_delegation_output(address, pool_id);
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_delegation(
                    account_index,
                    vec![output],
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// Create a transaction to stake to the specified delegation ID and broadcasts it to the
    /// mempool.
    pub async fn delegate_staking(
        &mut self,
        amount: Amount,
        delegation_id: DelegationId,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let output = TxOutput::DelegateStaking(amount, delegation_id);
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// Creates a transaction that sends coins from the specified delegation to the specified
    /// address destination, and broadcasts it to the mempool.
    pub async fn send_to_address_from_delegation(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let pool_id = self
            .wallet
            .get_delegation(self.account_index, delegation_id)
            .map_err(ControllerError::WalletError)?
            .pool_id;

        let delegation_share = self
            .rpc_client
            .get_delegation_share(pool_id, delegation_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(
                WalletError::DelegationNotFound(delegation_id),
            ))?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  _consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_transaction_to_addresses_from_delegation(
                    account_index,
                    address,
                    amount,
                    delegation_id,
                    delegation_share,
                    current_fee_rate,
                )
            },
        )
        .await
    }

    /// Creates a transaction that transfers tokens to the address destination, and broadcasts it
    /// to the mempool.
    pub async fn send_tokens_to_address(
        &mut self,
        token_info: RPCTokenInfo,
        address: Address<Destination>,
        amount: Amount,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let output = make_address_output_token(address, amount, token_info.token_id());
        self.create_and_send_token_tx(
            &token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                )
            },
        )
        .await
    }

    /// Creates a transaction that creates a new stake pool and broadcasts it to the mempool.
    pub async fn create_stake_pool_tx(
        &mut self,
        amount: Amount,
        decommission_key: Destination,
        margin_ratio_per_thousand: PerThousand,
        cost_per_block: Amount,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.create_stake_pool_tx(
                    account_index,
                    current_fee_rate,
                    consolidate_fee_rate,
                    StakePoolDataArguments {
                        amount,
                        margin_ratio_per_thousand,
                        cost_per_block,
                        decommission_key,
                    },
                )
            },
        )
        .await
    }

    /// Creates a transaction that decommissions a stake pool and broadcasts it to the mempool.
    pub async fn decommission_stake_pool(
        &mut self,
        pool_id: PoolId,
        output_address: Option<Destination>,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let staker_balance = self
            .rpc_client
            .get_staker_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownPoolId(
                pool_id,
            )))?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  _consolidate_fee_rate: FeeRate,
                  wallet: &mut DefaultWallet,
                  account_index: U31| {
                wallet.decommission_stake_pool(
                    account_index,
                    pool_id,
                    staker_balance,
                    output_address,
                    current_fee_rate,
                )
            },
        )
        .await
    }

    /// Creates a partially signed transaction that decommissions a stake pool.
    pub async fn decommission_stake_pool_request(
        &mut self,
        pool_id: PoolId,
        output_address: Option<Destination>,
    ) -> Result<PartiallySignedTransaction, ControllerError<T>> {
        let staker_balance = self
            .rpc_client
            .get_staker_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownPoolId(
                pool_id,
            )))?;

        let (current_fee_rate, _) = self.get_current_and_consolidation_fee_rate().await?;

        self.wallet
            .decommission_stake_pool_request(
                self.account_index,
                pool_id,
                staker_balance,
                output_address,
                current_fee_rate,
            )
            .map_err(ControllerError::WalletError)
    }

    /// Checks if the wallet has stake pools and marks this account for staking.
    pub fn start_staking(&mut self) -> Result<(), ControllerError<T>> {
        utils::ensure!(!self.wallet.is_locked(), ControllerError::WalletIsLocked);
        // Make sure that account_index is valid and that pools exist
        let pool_ids = self
            .wallet
            .get_pool_ids(self.account_index, WalletPoolsFilter::Stake)
            .map_err(ControllerError::WalletError)?;
        utils::ensure!(!pool_ids.is_empty(), ControllerError::NoStakingPool);
        log::info!("Start staking, account_index: {}", self.account_index);
        self.staking_started.insert(self.account_index);
        Ok(())
    }

    /// Tries to sign any unsigned inputs of a raw or partially signed transaction with the private
    /// keys in this wallet.
    pub fn sign_raw_transaction(
        &mut self,
        tx: TransactionToSign,
    ) -> Result<PartiallySignedTransaction, ControllerError<T>> {
        self.wallet
            .sign_raw_transaction(self.account_index, tx)
            .map_err(ControllerError::WalletError)
    }

    pub fn sign_challenge(
        &mut self,
        challenge: Vec<u8>,
        destination: Destination,
    ) -> Result<ArbitraryMessageSignature, ControllerError<T>> {
        self.wallet
            .sign_challenge(self.account_index, challenge, destination)
            .map_err(ControllerError::WalletError)
    }

    pub fn add_unconfirmed_tx(&mut self, tx: SignedTransaction) -> Result<(), ControllerError<T>> {
        self.wallet
            .add_unconfirmed_tx(tx, self.wallet_events)
            .map_err(ControllerError::WalletError)
    }

    async fn get_current_and_consolidation_fee_rate(
        &mut self,
    ) -> Result<(mempool::FeeRate, mempool::FeeRate), ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(self.config.in_top_x_mb)
            .await
            .map_err(ControllerError::NodeCallError)?;
        let consolidate_fee_rate = current_fee_rate;
        Ok((current_fee_rate, consolidate_fee_rate))
    }

    /// Broadcast a singed transaction to the mempool and update the wallets state if the
    /// transaction has been added to the mempool
    pub async fn broadcast_to_mempool(
        &mut self,
        tx: SignedTransaction,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        if self.config.broadcast_to_mempool {
            self.wallet
                .add_account_unconfirmed_tx(self.account_index, tx.clone(), self.wallet_events)
                .map_err(ControllerError::WalletError)?;

            self.rpc_client
                .submit_transaction(tx.clone(), Default::default())
                .await
                .map_err(ControllerError::NodeCallError)?;
        }

        Ok(tx)
    }

    /// Create a transaction and broadcast it
    async fn create_and_send_tx<
        F: FnOnce(FeeRate, FeeRate, &mut DefaultWallet, U31) -> WalletResult<SignedTransaction>,
    >(
        &mut self,
        tx_maker: F,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = tx_maker(
            current_fee_rate,
            consolidate_fee_rate,
            self.wallet,
            self.account_index,
        )
        .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    /// Create and broadcast a transaction that uses token,
    /// check if that token can be used i.e. not frozen
    async fn create_and_send_token_tx<
        F: FnOnce(
            FeeRate,
            FeeRate,
            &mut DefaultWallet,
            U31,
            &UnconfirmedTokenInfo,
        ) -> WalletResult<SignedTransaction>,
    >(
        &mut self,
        token_info: &RPCTokenInfo,
        tx_maker: F,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        // make sure we can use the token before create an tx using it
        let token_freezable_info = match token_info {
            RPCTokenInfo::FungibleToken(token_info) => self
                .wallet
                .get_token_unconfirmed_info(self.account_index, token_info)
                .map_err(ControllerError::WalletError)?,
            RPCTokenInfo::NonFungibleToken(info) => {
                UnconfirmedTokenInfo::NonFungibleToken(info.token_id)
            }
        };

        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = tx_maker(
            current_fee_rate,
            consolidate_fee_rate,
            self.wallet,
            self.account_index,
            &token_freezable_info,
        )
        .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    /// Similar to create_and_send_tx but some transactions also create an ID
    /// e.g. newly issued token, nft or delegation id
    async fn create_and_send_tx_with_id<
        ID,
        F: FnOnce(FeeRate, FeeRate, &mut DefaultWallet, U31) -> WalletResult<(ID, SignedTransaction)>,
    >(
        &mut self,
        tx_maker: F,
    ) -> Result<(SignedTransaction, ID), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let (id, tx) = tx_maker(
            current_fee_rate,
            consolidate_fee_rate,
            self.wallet,
            self.account_index,
        )
        .map_err(ControllerError::WalletError)?;

        let tx_id = self.broadcast_to_mempool(tx).await?;
        Ok((tx_id, id))
    }

    async fn fetch_utxo(&self, input: &UtxoOutPoint) -> Result<TxOutput, ControllerError<T>> {
        let utxo = self
            .rpc_client
            .get_utxo(input.clone())
            .await
            .map_err(ControllerError::NodeCallError)?;

        utxo.ok_or(ControllerError::WalletError(WalletError::CannotFindUtxo(
            input.clone(),
        )))
    }
}
