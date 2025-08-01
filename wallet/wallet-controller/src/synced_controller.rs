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

use chainstate::rpc::RpcOutputValueIn;
use futures::{stream::FuturesUnordered, TryStreamExt};

use common::{
    address::{pubkeyhash::PublicKeyHash, Address},
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        htlc::HashedTimelockContract,
        output_value::OutputValue,
        signature::inputsig::arbitrary_message::ArbitraryMessageSignature,
        tokens::{
            get_referenced_token_ids_ignore_issuance, IsTokenFreezable, IsTokenUnfreezable,
            Metadata, RPCFungibleTokenInfo, RPCTokenInfo, TokenId, TokenIssuance, TokenIssuanceV1,
            TokenTotalSupply,
        },
        ChainConfig, DelegationId, Destination, OrderId, PoolId, RpcOrderInfo, SignedTransaction,
        SignedTransactionIntent, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::RpcAmountIn, per_thousand::PerThousand, Amount, Id},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PrivateKey, PublicKey,
    },
    vrf::VRFPublicKey,
};
use logging::log;
use mempool::FeeRate;
use node_comm::node_traits::NodeInterface;
use utils::ensure;
use wallet::{
    account::{CoinSelectionAlgo, TransactionToSign, UnconfirmedTokenInfo},
    destination_getters::{get_tx_output_destination, HtlcSpendingCondition},
    send_request::{
        make_address_output, make_address_output_token, make_create_delegation_output,
        make_data_deposit_output, SelectedInputs, StakePoolCreationArguments,
    },
    wallet::WalletPoolsFilter,
    wallet_events::WalletEvents,
    WalletError, WalletResult,
};
use wallet_types::{
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, TokenAdditionalInfo, TxAdditionalInfo,
    },
    signature_status::SignatureStatus,
    utxo_types::{UtxoState, UtxoType},
    with_locked::WithLocked,
    Currency, SignedTxWithFees,
};

use crate::{
    helpers::{
        fetch_order_info, fetch_token_info, fetch_token_infos_into_tx_info, fetch_utxo,
        into_balances, tx_to_partially_signed_tx,
    },
    runtime_wallet::RuntimeWallet,
    types::{
        Balances, GenericCurrencyTransfer, NewTransaction, PreparedTransaction, SweepFromAddresses,
    },
    ControllerConfig, ControllerError,
};

pub struct SyncedController<'a, T, W, B: storage::Backend + 'static> {
    wallet: &'a mut RuntimeWallet<B>,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    wallet_events: &'a W,
    staking_started: &'a mut BTreeSet<U31>,
    account_index: U31,
    config: ControllerConfig,
}

impl<'a, T, W, B> SyncedController<'a, T, W, B>
where
    B: storage::Backend + 'static,
    T: NodeInterface,
    W: WalletEvents,
{
    pub fn new(
        wallet: &'a mut RuntimeWallet<B>,
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

    async fn fetch_token_infos(
        &self,
        tokens: impl IntoIterator<Item = TokenId>,
    ) -> Result<Vec<RPCTokenInfo>, ControllerError<T>> {
        let tasks: FuturesUnordered<_> = tokens
            .into_iter()
            .map(|token_id| fetch_token_info(&self.rpc_client, token_id))
            .collect();
        tasks.try_collect().await
    }

    /// Check that the selected UTXOs not contain tokens that are frozen and can't be used
    pub async fn check_tokens_in_selected_utxo(
        &self,
        input_utxos: &[UtxoOutPoint],
    ) -> Result<(), ControllerError<T>> {
        let token_ids = self
            .wallet
            .find_used_tokens(self.account_index, input_utxos)
            .map_err(ControllerError::WalletError)?;

        for token_info in self.fetch_token_infos(token_ids).await? {
            match token_info {
                RPCTokenInfo::FungibleToken(token_info) => {
                    self.check_fungible_token_is_usable(token_info)?
                }
                RPCTokenInfo::NonFungibleToken(_) => {}
            }
        }
        Ok(())
    }

    pub fn check_fungible_token_is_usable(
        &self,
        token_info: RPCFungibleTokenInfo,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .get_token_unconfirmed_info(self.account_index, token_info)
            .map_err(ControllerError::WalletError)?
            .check_can_be_used()
            .map_err(ControllerError::WalletError)?;

        Ok(())
    }

    /// Filter out utxos that contain tokens that are frozen and can't be used
    async fn filter_out_utxos_with_frozen_tokens(
        &self,
        input_utxos: Vec<(UtxoOutPoint, TxOutput)>,
    ) -> Result<(Vec<(UtxoOutPoint, TxOutput)>, TxAdditionalInfo), ControllerError<T>> {
        let mut result = vec![];
        let mut additional_info = TxAdditionalInfo::new();
        for utxo in input_utxos {
            let token_ids = get_referenced_token_ids_ignore_issuance(&utxo.1);
            if token_ids.is_empty() {
                result.push(utxo);
            } else {
                let token_infos = self.fetch_token_infos(token_ids).await?;
                let ok_to_use = token_infos.iter().try_fold(
                    true,
                    |all_ok, token_info| -> Result<bool, ControllerError<T>> {
                        let all_ok = all_ok
                            && match &token_info {
                                RPCTokenInfo::FungibleToken(token_info) => self
                                    .wallet
                                    .get_token_unconfirmed_info(
                                        self.account_index,
                                        token_info.clone(),
                                    )
                                    .map_err(ControllerError::WalletError)?
                                    .check_can_be_used()
                                    .is_ok(),
                                RPCTokenInfo::NonFungibleToken(_) => true,
                            };
                        Ok(all_ok)
                    },
                )?;

                if ok_to_use {
                    result.push(utxo);
                    for token_info in token_infos {
                        additional_info.add_token_info(
                            token_info.token_id(),
                            TokenAdditionalInfo {
                                num_decimals: token_info.token_number_of_decimals(),
                                ticker: token_info.token_ticker().to_vec(),
                            },
                        );
                    }
                }
            }
        }

        Ok((result, additional_info))
    }

    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .abandon_transaction(self.account_index, tx_id)
            .map_err(ControllerError::WalletError)
    }

    pub fn standalone_address_label_rename(
        &mut self,
        address: Destination,
        label: Option<String>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .standalone_address_label_rename(self.account_index, address, label)
            .map_err(ControllerError::WalletError)
    }

    pub fn add_standalone_address(
        &mut self,
        address: PublicKeyHash,
        label: Option<String>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .add_standalone_address(self.account_index, address, label)
            .map_err(ControllerError::WalletError)
    }

    pub fn add_standalone_private_key(
        &mut self,
        private_key: PrivateKey,
        label: Option<String>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .add_standalone_private_key(self.account_index, private_key, label)
            .map_err(ControllerError::WalletError)
    }

    pub fn add_standalone_multisig(
        &mut self,
        challenge: ClassicMultisigChallenge,
        label: Option<String>,
    ) -> Result<PublicKeyHash, ControllerError<T>> {
        self.wallet
            .add_standalone_multisig(self.account_index, challenge, label)
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
    ) -> Result<(NewTransaction, TokenId), ControllerError<T>> {
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<(NewTransaction, TokenId), ControllerError<T>> {
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
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

    pub async fn change_token_metadata_uri(
        &mut self,
        token_info: RPCTokenInfo,
        metadata_uri: Vec<u8>,
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                wallet.change_token_metadata_uri(
                    account_index,
                    token_info,
                    metadata_uri,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        let (_, best_block_height) = self.wallet.get_best_block_for_account(self.account_index)?;
        let outputs = make_data_deposit_output(self.chain_config, data, best_block_height)?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    outputs,
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                    TxAdditionalInfo::new(),
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        // TODO: this function seems to be dedicated to sending coins only, because we have the separate
        // `send_tokens_to_address` function for tokens. If so, it should probably be renamed and the call
        // to `check_tokens_in_selected_utxo` be replaced with another one that rejects all tokens.
        // If, on the other hand, this function can potentially be used for tokens, then the `TxAdditionalInfo`
        // passed to create_transaction_to_addresses should include token infos.

        self.check_tokens_in_selected_utxo(&selected_utxos).await?;

        let output = make_address_output(address.into_object(), amount);
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(selected_utxos),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                    TxAdditionalInfo::new(),
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
        from_addresses: SweepFromAddresses,
    ) -> Result<NewTransaction, ControllerError<T>> {
        let selected_utxos = self.wallet.get_utxos(
            self.account_index,
            UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
            UtxoState::Confirmed | UtxoState::Inactive,
            WithLocked::Unlocked,
        )?;

        let (inputs, additional_info) =
            self.filter_out_utxos_with_frozen_tokens(selected_utxos).await?;

        let filtered_inputs = inputs
            .into_iter()
            .filter(|(_, output)| {
                get_tx_output_destination(output, &|_| None, HtlcSpendingCondition::Skip)
                    .is_some_and(|dest| from_addresses.should_sweep_address(&dest))
            })
            .collect::<Vec<_>>();

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  _consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_sweep_transaction(
                    account_index,
                    destination_address,
                    filtered_inputs,
                    current_fee_rate,
                    additional_info,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
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
                  wallet: &mut RuntimeWallet<B>,
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
        let output = make_address_output(address.into_object(), amount);

        let utxo_output = fetch_utxo(&self.rpc_client, self.wallet, &selected_utxo).await?;
        let change_address = if let Some(change_address) = change_address {
            change_address
        } else {
            let utxo_dest =
                get_tx_output_destination(&utxo_output, &|_| None, HtlcSpendingCondition::Skip)
                    .ok_or_else(|| {
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
                None,
                [(Currency::Coin, change_address)].into(),
                current_fee_rate,
                consolidate_fee_rate,
                TxAdditionalInfo::new(),
            )
            .map_err(ControllerError::WalletError)?;

        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok((req, fees))
    }

    /// Create an unsigned transaction for transfer of tokens to the specified destinations.
    ///
    /// The inputs for the transfer are randomly selected from the provided `inputs` until
    /// target amounts are satisfied.
    ///
    /// The function will automatically select coin utxos to pay fees from (note that `inputs`
    /// is not supposed to contain coin utxos; if it does, there is no guarantee that exactly
    /// those utxos will be selected to pay the fee).
    ///
    /// The change will be sent to addresses specified in `change_addresses`.
    /// If there is no entry in `change_addresses` for a certain token, the change will be sent
    /// to the first unused address in the wallet.
    /// If there is no entry in `change_addresses` for coins, the destination for the change
    /// from the fee payment will be taken from one of the existing coin utxos.
    // TODO: this discrepancy between tokens/coins fee handling is a bit ugly, it's better to unify it.
    // Note: the reason for this specific fee change behavior is that this function is called from
    // `make_tx_to_send_tokens_from_multisig_address`, which is supposed to be used in automated
    // scenarios; issuing a new address for each call seems redundant in such a case.
    // The token change being sent to first unused address doesn't have any particular reason;
    // it's just how this function's callee behaves by default.
    pub async fn make_unsigned_tx_to_send_tokens_to_addresses(
        &mut self,
        inputs: Vec<(UtxoOutPoint, TxOutput)>,
        outputs: BTreeMap<TokenId, Vec<GenericCurrencyTransfer>>,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
    ) -> Result<(PartiallySignedTransaction, Balances), ControllerError<T>> {
        ensure!(
            !inputs.is_empty(),
            ControllerError::<T>::ExpectingNonEmptyInputs
        );
        ensure!(
            !outputs.is_empty(),
            ControllerError::<T>::ExpectingNonEmptyOutputs
        );

        let (outputs, additional_info) = {
            let mut result = Vec::new();
            let mut additional_info = TxAdditionalInfo::new();

            for (token_id, outputs_vec) in outputs {
                let token_info = fetch_token_info(&self.rpc_client, token_id).await?;
                additional_info.add_token_info(
                    token_id,
                    TokenAdditionalInfo {
                        num_decimals: token_info.token_number_of_decimals(),
                        ticker: token_info.token_ticker().to_vec(),
                    },
                );

                match &token_info {
                    RPCTokenInfo::FungibleToken(token_info) => {
                        self.check_fungible_token_is_usable(token_info.clone())?
                    }
                    RPCTokenInfo::NonFungibleToken(_) => {
                        return Err(ControllerError::<T>::NotFungibleToken(token_id));
                    }
                }

                itertools::process_results(
                    outputs_vec.into_iter().map(|output| output.into_token_tx_output(&token_info)),
                    |iter| result.extend(iter),
                )
                .map_err(ControllerError::InvalidTxOutput)?;
            }

            (result, additional_info)
        };

        let (inputs, change_addresses) = {
            let mut inputs = inputs;
            let mut change_addresses = change_addresses;

            let all_utxos = self.wallet.get_utxos(
                self.account_index,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
                WithLocked::Unlocked,
            )?;

            let all_coin_utxos = all_utxos
                .into_iter()
                .filter_map(|(o, txo)| {
                    let (val, dest) = match &txo {
                        TxOutput::Transfer(val, dest)
                        | TxOutput::LockThenTransfer(val, dest, _) => (val, dest),
                        TxOutput::CreateDelegationId(_, _)
                        | TxOutput::IssueNft(_, _, _)
                        | TxOutput::ProduceBlockFromStake(_, _)
                        | TxOutput::CreateStakePool(_, _)
                        | TxOutput::Htlc(_, _)
                        | TxOutput::Burn(_)
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::DataDeposit(_)
                        | TxOutput::CreateOrder(_) => return None,
                    };

                    match val {
                        OutputValue::Coin(_) => {
                            let o = o.clone();
                            let dest = dest.clone();
                            Some((o, txo, dest))
                        }
                        OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => None,
                    }
                })
                .collect::<Vec<_>>();

            match change_addresses.entry(Currency::Coin) {
                std::collections::btree_map::Entry::Vacant(e) => {
                    let coin_change_address = Address::new(
                        self.chain_config,
                        all_coin_utxos
                            .first()
                            .ok_or(ControllerError::<T>::NoCoinUtxosToPayFeeFrom)?
                            .2
                            .clone(),
                    )
                    .expect("addressable");

                    e.insert(coin_change_address);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }

            inputs.extend(all_coin_utxos.into_iter().map(|(o, txo, _)| (o, txo)));

            (inputs, change_addresses)
        };

        let selected_inputs = SelectedInputs::Inputs(inputs);

        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let (tx, fees) = self.wallet.create_unsigned_transaction_to_addresses(
            self.account_index,
            outputs,
            selected_inputs,
            Some(CoinSelectionAlgo::Randomize),
            change_addresses,
            current_fee_rate,
            consolidate_fee_rate,
            additional_info,
        )?;

        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok((tx, fees))
    }

    /// Create a transaction that creates a new delegation for the specified pool with the
    /// specified owner address, and broadcasts it to the mempool.
    /// Returns the new transaction's ID and the newly created Delegation ID
    pub async fn create_delegation(
        &mut self,
        address: Address<Destination>,
        pool_id: PoolId,
    ) -> Result<(NewTransaction, DelegationId), ControllerError<T>> {
        let output = make_create_delegation_output(address, pool_id);
        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_delegation(
                    account_index,
                    output,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        let output = TxOutput::DelegateStaking(amount, delegation_id);
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                    TxAdditionalInfo::new(),
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        let pool_id = self.wallet.get_delegation(self.account_index, delegation_id)?.pool_id;

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
                  wallet: &mut RuntimeWallet<B>,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
        let output =
            make_address_output_token(address.into_object(), amount, token_info.token_id());
        self.create_and_send_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                let additional_info = TxAdditionalInfo::new().with_token_info(
                    token_info.token_id(),
                    TokenAdditionalInfo {
                        num_decimals: token_info.num_decimals(),
                        ticker: token_info.token_ticker().to_vec(),
                    },
                );
                wallet.create_transaction_to_addresses(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    current_fee_rate,
                    consolidate_fee_rate,
                    additional_info,
                )
            },
        )
        .await
    }

    /// Creates a transaction that transfers tokens to the address destination.
    pub async fn create_transaction_for_sending_tokens_to_address_with_intent(
        &mut self,
        token_info: RPCTokenInfo,
        address: Address<Destination>,
        amount: Amount,
        intent: String,
    ) -> Result<(SignedTxWithFees, SignedTransactionIntent), ControllerError<T>> {
        let output =
            make_address_output_token(address.into_object(), amount, token_info.token_id());
        self.create_token_tx(
            token_info,
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31,
                  token_info: &UnconfirmedTokenInfo| {
                token_info.check_can_be_used()?;
                let additional_info = TxAdditionalInfo::new().with_token_info(
                    token_info.token_id(),
                    TokenAdditionalInfo {
                        num_decimals: token_info.num_decimals(),
                        ticker: token_info.token_ticker().to_vec(),
                    },
                );
                wallet.create_transaction_to_addresses_with_intent(
                    account_index,
                    [output],
                    SelectedInputs::Utxos(vec![]),
                    BTreeMap::new(),
                    intent,
                    current_fee_rate,
                    consolidate_fee_rate,
                    additional_info,
                )
            },
        )
        .await
    }

    /// Creates a transaction that creates a new stake pool and broadcasts it to the mempool.
    pub async fn create_stake_pool(
        &mut self,
        amount: Amount,
        decommission_key: Destination,
        margin_ratio_per_thousand: PerThousand,
        cost_per_block: Amount,
        staker_key: Option<Destination>,
        vrf_public_key: Option<VRFPublicKey>,
    ) -> Result<NewTransaction, ControllerError<T>> {
        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_stake_pool(
                    account_index,
                    current_fee_rate,
                    consolidate_fee_rate,
                    StakePoolCreationArguments {
                        amount,
                        margin_ratio_per_thousand,
                        cost_per_block,
                        decommission_key,
                        staker_key,
                        vrf_public_key,
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
    ) -> Result<NewTransaction, ControllerError<T>> {
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
                  wallet: &mut RuntimeWallet<B>,
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

    pub async fn create_htlc_tx(
        &mut self,
        amount: RpcAmountIn,
        token_id: Option<TokenId>,
        htlc: HashedTimelockContract,
    ) -> Result<PreparedTransaction, ControllerError<T>> {
        let mut tx_additional_info = TxAdditionalInfo::new();
        let output_value =
            self.convert_rpc_amount_in(amount, token_id, &mut tx_additional_info).await?;

        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let SignedTxWithFees { tx, fees } = self.wallet.create_htlc_tx(
            self.account_index,
            output_value,
            htlc,
            current_fee_rate,
            consolidate_fee_rate,
            tx_additional_info,
        )?;

        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok(PreparedTransaction { tx, fees })
    }

    pub async fn create_order(
        &mut self,
        ask_value: RpcOutputValueIn,
        give_value: RpcOutputValueIn,
        conclude_key: Address<Destination>,
    ) -> Result<(NewTransaction, OrderId), ControllerError<T>> {
        let mut tx_additional_info = TxAdditionalInfo::new();
        let mut convert_value = async |value| -> Result<_, ControllerError<T>> {
            let (amount, token_id) = match value {
                RpcOutputValueIn::Coin { amount } => (amount, None),
                RpcOutputValueIn::Token { id, amount } => {
                    let token_id = id
                        .decode_object(self.chain_config)
                        .map_err(|_| ControllerError::InvalidTokenId)?;
                    (amount, Some(token_id))
                }
            };
            self.convert_rpc_amount_in(amount, token_id, &mut tx_additional_info).await
        };

        let ask_value = convert_value(ask_value).await?;
        let give_value = convert_value(give_value).await?;

        self.create_and_send_tx_with_id(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_order_tx(
                    account_index,
                    ask_value,
                    give_value,
                    conclude_key,
                    current_fee_rate,
                    consolidate_fee_rate,
                    tx_additional_info,
                )
            },
        )
        .await
    }

    pub async fn conclude_order(
        &mut self,
        order_id: OrderId,
        output_address: Option<Destination>,
    ) -> Result<NewTransaction, ControllerError<T>> {
        let order_info = fetch_order_info(&self.rpc_client, order_id).await?;
        let tx_additional_info =
            self.additional_info_for_order_update_tx(order_id, &order_info).await?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_conclude_order_tx(
                    account_index,
                    order_id,
                    order_info,
                    output_address,
                    current_fee_rate,
                    consolidate_fee_rate,
                    tx_additional_info,
                )
            },
        )
        .await
    }

    pub async fn fill_order(
        &mut self,
        order_id: OrderId,
        fill_amount_in_ask_currency: RpcAmountIn,
        output_address: Option<Destination>,
    ) -> Result<NewTransaction, ControllerError<T>> {
        let order_info = fetch_order_info(&self.rpc_client, order_id).await?;
        let tx_additional_info =
            self.additional_info_for_order_update_tx(order_id, &order_info).await?;

        let ask_currency_decimals = match order_info.initially_asked.token_id() {
            Some(token_id) => tx_additional_info
                .get_token_info(token_id)
                .expect(
                    "token info should be present after additional_info_for_order_update_tx call",
                )
                .num_decimals,
            None => self.chain_config.coin_decimals(),
        };

        let fill_amount_in_ask_currency = fill_amount_in_ask_currency
            .to_amount(ask_currency_decimals)
            .ok_or(ControllerError::InvalidCoinAmount)?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_fill_order_tx(
                    account_index,
                    order_id,
                    order_info,
                    fill_amount_in_ask_currency,
                    output_address,
                    current_fee_rate,
                    consolidate_fee_rate,
                    tx_additional_info,
                )
            },
        )
        .await
    }

    pub async fn freeze_order(
        &mut self,
        order_id: OrderId,
    ) -> Result<NewTransaction, ControllerError<T>> {
        let order_info = fetch_order_info(&self.rpc_client, order_id).await?;
        let tx_additional_info =
            self.additional_info_for_order_update_tx(order_id, &order_info).await?;

        self.create_and_send_tx(
            move |current_fee_rate: FeeRate,
                  consolidate_fee_rate: FeeRate,
                  wallet: &mut RuntimeWallet<B>,
                  account_index: U31| {
                wallet.create_freeze_order_tx(
                    account_index,
                    order_id,
                    order_info,
                    current_fee_rate,
                    consolidate_fee_rate,
                    tx_additional_info,
                )
            },
        )
        .await
    }

    async fn convert_rpc_amount_in(
        &self,
        amount: RpcAmountIn,
        token_id: Option<TokenId>,
        tx_additional_info: &mut TxAdditionalInfo,
    ) -> Result<OutputValue, ControllerError<T>> {
        let output_value = match token_id {
            Some(token_id) => {
                let token_info = fetch_token_info(&self.rpc_client, token_id).await?;
                let amount = amount
                    .to_amount(token_info.token_number_of_decimals())
                    .ok_or(ControllerError::InvalidCoinAmount)?;
                tx_additional_info.add_token_info(
                    token_id,
                    TokenAdditionalInfo {
                        num_decimals: token_info.token_number_of_decimals(),
                        ticker: token_info.token_ticker().to_vec(),
                    },
                );
                OutputValue::TokenV1(token_id, amount)
            }
            None => {
                let amount = amount
                    .to_amount(self.chain_config.coin_decimals())
                    .ok_or(ControllerError::InvalidCoinAmount)?;
                OutputValue::Coin(amount)
            }
        };

        Ok(output_value)
    }

    async fn additional_info_for_order_update_tx(
        &self,
        order_id: OrderId,
        order_info: &RpcOrderInfo,
    ) -> Result<TxAdditionalInfo, ControllerError<T>> {
        let mut tx_info = TxAdditionalInfo::new().with_order_info(
            order_id,
            OrderAdditionalInfo {
                initially_asked: order_info.initially_asked.into(),
                initially_given: order_info.initially_given.into(),
                ask_balance: order_info.ask_balance,
                give_balance: order_info.give_balance,
            },
        );

        let token1_id = order_info.initially_asked.token_id().cloned();
        let token2_id = order_info.initially_given.token_id().cloned();

        fetch_token_infos_into_tx_info(
            &self.rpc_client,
            token1_id.into_iter().chain(token2_id.into_iter()),
            &mut tx_info,
        )
        .await?;

        Ok(tx_info)
    }

    /// Checks if the wallet has stake pools and marks this account for staking.
    pub fn start_staking(&mut self) -> Result<(), ControllerError<T>> {
        utils::ensure!(!self.wallet.is_locked(), ControllerError::WalletIsLocked);
        // Make sure that account_index is valid and that pools exist
        let pool_ids = self.wallet.get_pool_ids(self.account_index, WalletPoolsFilter::Stake)?;
        utils::ensure!(!pool_ids.is_empty(), ControllerError::NoStakingPool);
        log::info!("Start staking, account_index: {}", self.account_index);
        self.staking_started.insert(self.account_index);
        Ok(())
    }

    /// Tries to sign any unsigned inputs of a raw or partially signed transaction with the private
    /// keys in this wallet.
    // TODO: this function only supports HTLC inputs if a PartiallySignedTransaction is passed
    // (which could be created with compose_transaction, for example) and not if it's a simple
    // Transaction; to support HTLC inputs in the latter case we need to somehow pass HTLC secrets
    // here (probably `TransactionToSign::Tx` should contain the secrets too).
    pub async fn sign_raw_transaction(
        &mut self,
        tx: TransactionToSign,
    ) -> Result<
        (
            PartiallySignedTransaction,
            Vec<SignatureStatus>,
            Vec<SignatureStatus>,
        ),
        ControllerError<T>,
    > {
        let ptx = match tx {
            TransactionToSign::Partial(ptx) => ptx,
            TransactionToSign::Tx(tx) => {
                tx_to_partially_signed_tx(&self.rpc_client, self.wallet, tx, None).await?
            }
        };

        self.wallet
            .sign_raw_transaction(self.account_index, ptx)
            .map_err(ControllerError::WalletError)
    }

    pub fn sign_challenge(
        &mut self,
        challenge: &[u8],
        destination: &Destination,
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
        // Submit the tx first and only add it to the wallet after the submission has succeeded.
        // Note: if the call order is reversed and the mempool rejects the tx for some reason, we'll
        // end up having a bogus unconfirmed tx in the wallet; after that, any new tx created by
        // the wallet has a chance to be an orphan if it happens to consume some outputs of the
        // bogus tx.
        self.rpc_client
            .submit_transaction(tx.clone(), Default::default())
            .await
            .map_err(ControllerError::NodeCallError)?;

        self.wallet
            .add_account_unconfirmed_tx(self.account_index, &tx, self.wallet_events)
            .map_err(ControllerError::WalletError)?;

        Ok(tx)
    }

    /// Broadcast to the mempool if specified by the controller config
    /// sometimes broadcasting is disabled when a prior confirmation is needed
    async fn broadcast_to_mempool_if_needed(
        &mut self,
        tx: SignedTransaction,
    ) -> Result<(SignedTransaction, bool), ControllerError<T>> {
        if self.config.broadcast_to_mempool {
            self.broadcast_to_mempool(tx).await.map(|tx| (tx, true))
        } else {
            Ok((tx, false))
        }
    }

    /// Create a transaction and broadcast it if needed
    async fn create_and_send_tx<E, F>(
        &mut self,
        tx_maker: F,
    ) -> Result<NewTransaction, ControllerError<T>>
    where
        F: FnOnce(FeeRate, FeeRate, &mut RuntimeWallet<B>, U31) -> Result<SignedTxWithFees, E>,
        ControllerError<T>: From<E>,
    {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let SignedTxWithFees { tx, fees } = tx_maker(
            current_fee_rate,
            consolidate_fee_rate,
            self.wallet,
            self.account_index,
        )?;

        let (tx, broadcasted) = self.broadcast_to_mempool_if_needed(tx).await?;
        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok(NewTransaction {
            tx,
            fees,
            broadcasted,
        })
    }

    /// Create a transaction that uses a token, check if that token can be used i.e. not frozen.
    async fn create_token_tx<F, R>(
        &mut self,
        token_info: RPCTokenInfo,
        tx_maker: F,
    ) -> Result<R, ControllerError<T>>
    where
        F: FnOnce(
            FeeRate,
            FeeRate,
            &mut RuntimeWallet<B>,
            U31,
            &UnconfirmedTokenInfo,
        ) -> WalletResult<R>,
    {
        let token_freezable_info = self.unconfirmed_token_info(token_info)?;

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

        Ok(tx)
    }

    /// Create and broadcast a transaction that uses a token,
    /// check if that token can be used i.e. not frozen.
    async fn create_and_send_token_tx<
        F: FnOnce(
            FeeRate,
            FeeRate,
            &mut RuntimeWallet<B>,
            U31,
            &UnconfirmedTokenInfo,
        ) -> WalletResult<SignedTxWithFees>,
    >(
        &mut self,
        token_info: RPCTokenInfo,
        tx_maker: F,
    ) -> Result<NewTransaction, ControllerError<T>> {
        let SignedTxWithFees { tx, fees } = self.create_token_tx(token_info, tx_maker).await?;
        let (tx, broadcasted) = self.broadcast_to_mempool_if_needed(tx).await?;
        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok(NewTransaction {
            tx,
            fees,
            broadcasted,
        })
    }

    fn unconfirmed_token_info(
        &mut self,
        token_info: RPCTokenInfo,
    ) -> Result<UnconfirmedTokenInfo, ControllerError<T>> {
        let token_freezable_info = match token_info {
            RPCTokenInfo::FungibleToken(token_info) => {
                self.wallet.get_token_unconfirmed_info(self.account_index, token_info)?
            }
            RPCTokenInfo::NonFungibleToken(info) => {
                UnconfirmedTokenInfo::NonFungibleToken(info.token_id, info.as_ref().into())
            }
        };
        Ok(token_freezable_info)
    }

    /// Similar to create_and_send_tx but some transactions also create an ID
    /// e.g. newly issued token, nft or delegation id
    async fn create_and_send_tx_with_id<
        ID,
        F: FnOnce(
            FeeRate,
            FeeRate,
            &mut RuntimeWallet<B>,
            U31,
        ) -> WalletResult<(ID, SignedTxWithFees)>,
    >(
        &mut self,
        tx_maker: F,
    ) -> Result<(NewTransaction, ID), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let (id, SignedTxWithFees { tx, fees }) = tx_maker(
            current_fee_rate,
            consolidate_fee_rate,
            self.wallet,
            self.account_index,
        )
        .map_err(ControllerError::WalletError)?;

        let (tx, broadcasted) = self.broadcast_to_mempool_if_needed(tx).await?;
        let fees = into_balances(&self.rpc_client, self.chain_config, fees).await?;

        Ok((
            NewTransaction {
                tx,
                fees,
                broadcasted,
            },
            id,
        ))
    }
}
