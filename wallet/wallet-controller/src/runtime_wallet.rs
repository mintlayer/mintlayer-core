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
    address::{pubkeyhash::PublicKeyHash, Address},
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        htlc::HashedTimelockContract,
        output_value::OutputValue,
        signature::inputsig::arbitrary_message::ArbitraryMessageSignature,
        tokens::{IsTokenUnfreezable, Metadata, RPCFungibleTokenInfo, TokenId, TokenIssuance},
        AccountCommand, AccountOutPoint, DelegationId, Destination, GenBlock, OrderAccountCommand,
        OrderId, PoolId, RpcOrderInfo, SignedTransaction, SignedTransactionIntent, Transaction,
        TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, Id, H256},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PrivateKey, PublicKey,
    },
    vrf::VRFPublicKey,
};
use mempool::FeeRate;
use wallet::{
    account::{
        transaction_list::TransactionList, CoinSelectionAlgo, DelegationData, PoolData, TxInfo,
        UnconfirmedTokenInfo,
    },
    send_request::{SelectedInputs, StakePoolCreationArguments},
    signer::software_signer::SoftwareSignerProvider,
    wallet::WalletPoolsFilter,
    wallet_events::WalletEvents,
    Wallet, WalletError, WalletResult,
};
use wallet_types::{
    account_info::{StandaloneAddressDetails, StandaloneAddresses},
    partially_signed_transaction::{PartiallySignedTransaction, TxAdditionalInfo},
    seed_phrase::SerializableSeedPhrase,
    signature_status::SignatureStatus,
    utxo_types::{UtxoState, UtxoStates, UtxoTypes},
    wallet_tx::TxData,
    with_locked::WithLocked,
    Currency, KeyPurpose, KeychainUsageState, SignedTxWithFees,
};

#[cfg(feature = "trezor")]
use wallet::signer::trezor_signer::TrezorSignerProvider;

pub enum RuntimeWallet<B: storage::Backend + 'static> {
    Software(Wallet<B, SoftwareSignerProvider>),
    #[cfg(feature = "trezor")]
    Trezor(Wallet<B, TrezorSignerProvider>),
}

impl<B: storage::Backend + 'static> RuntimeWallet<B> {
    pub fn find_unspent_utxo_and_destination(
        &self,
        input: &UtxoOutPoint,
    ) -> Option<(TxOutput, Destination)> {
        match self {
            RuntimeWallet::Software(w) => w.find_unspent_utxo_and_destination(input),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_unspent_utxo_and_destination(input),
        }
    }

    pub fn find_account_destination(&self, acc_outpoint: &AccountOutPoint) -> Option<Destination> {
        match self {
            RuntimeWallet::Software(w) => w.find_account_destination(acc_outpoint),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_account_destination(acc_outpoint),
        }
    }

    pub fn find_account_command_destination(&self, cmd: &AccountCommand) -> Option<Destination> {
        match self {
            RuntimeWallet::Software(w) => w.find_account_command_destination(cmd),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_account_command_destination(cmd),
        }
    }

    pub fn find_order_account_command_destination(
        &self,
        cmd: &OrderAccountCommand,
    ) -> Option<Destination> {
        match self {
            RuntimeWallet::Software(w) => w.find_order_account_command_destination(cmd),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_order_account_command_destination(cmd),
        }
    }

    pub fn seed_phrase(&self) -> Result<Option<SerializableSeedPhrase>, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.seed_phrase(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.seed_phrase(),
        }
    }

    pub fn delete_seed_phrase(&self) -> Result<Option<SerializableSeedPhrase>, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.delete_seed_phrase(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.delete_seed_phrase(),
        }
    }

    pub fn reset_wallet_to_genesis(&mut self) -> Result<(), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.reset_wallet_to_genesis(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.reset_wallet_to_genesis(),
        }
    }

    pub fn encrypt_wallet(&mut self, password: &Option<String>) -> Result<(), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.encrypt_wallet(password),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.encrypt_wallet(password),
        }
    }

    pub fn unlock_wallet(&mut self, password: &String) -> Result<(), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.unlock_wallet(password),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.unlock_wallet(password),
        }
    }

    pub fn lock_wallet(&mut self) -> Result<(), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.lock_wallet(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.lock_wallet(),
        }
    }

    pub fn set_lookahead_size(
        &mut self,
        lookahead_size: u32,
        force_reduce: bool,
    ) -> Result<(), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.set_lookahead_size(lookahead_size, force_reduce),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.set_lookahead_size(lookahead_size, force_reduce),
        }
    }

    pub fn wallet_info(&self) -> (H256, Vec<Option<String>>) {
        match self {
            RuntimeWallet::Software(w) => w.wallet_info(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.wallet_info(),
        }
    }

    pub fn create_next_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.create_next_account(name),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_next_account(name),
        }
    }

    pub fn set_account_name(
        &mut self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.set_account_name(account_index, name),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.set_account_name(account_index, name),
        }
    }

    pub fn get_pos_gen_block_data(
        &self,
        account_index: U31,
        pool_id: PoolId,
    ) -> Result<consensus::PoSGenerateBlockInputData, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.get_pos_gen_block_data(account_index, pool_id),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(_) => Err(WalletError::UnsupportedHardwareWalletOperation),
        }
    }

    pub fn get_pos_gen_block_data_by_pool_id(
        &self,
        pool_id: PoolId,
    ) -> Result<consensus::PoSGenerateBlockInputData, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.get_pos_gen_block_data_by_pool_id(pool_id),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(_) => Err(WalletError::UnsupportedHardwareWalletOperation),
        }
    }

    pub fn get_pool_ids(
        &self,
        account_index: U31,
        filter: WalletPoolsFilter,
    ) -> WalletResult<Vec<(PoolId, PoolData)>> {
        match self {
            RuntimeWallet::Software(w) => w.get_pool_ids(account_index, filter),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_pool_ids(account_index, filter),
        }
    }

    pub fn get_best_block(&self) -> BTreeMap<U31, (Id<GenBlock>, BlockHeight)> {
        match self {
            RuntimeWallet::Software(w) => w.get_best_block(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_best_block(),
        }
    }

    pub fn get_best_block_for_account(
        &self,
        account_index: U31,
    ) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        match self {
            RuntimeWallet::Software(w) => w.get_best_block_for_account(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_best_block_for_account(account_index),
        }
    }

    pub fn is_locked(&self) -> bool {
        match self {
            RuntimeWallet::Software(w) => w.is_locked(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.is_locked(),
        }
    }

    pub fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, WalletError> {
        match self {
            RuntimeWallet::Software(w) => {
                w.get_utxos(account_index, utxo_types, utxo_states, with_locked)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.get_utxos(account_index, utxo_types, utxo_states, with_locked)
            }
        }
    }

    pub fn get_transactions_to_be_broadcast(
        &mut self,
    ) -> Result<Vec<SignedTransaction>, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.get_transactions_to_be_broadcast(),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_transactions_to_be_broadcast(),
        }
    }

    pub fn get_balance(
        &self,
        account_index: U31,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        match self {
            RuntimeWallet::Software(w) => w.get_balance(account_index, utxo_states, with_locked),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_balance(account_index, utxo_states, with_locked),
        }
    }

    pub fn get_multisig_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WalletResult<Vec<(UtxoOutPoint, TxOutput)>> {
        match self {
            RuntimeWallet::Software(w) => {
                w.get_multisig_utxos(account_index, utxo_types, utxo_states, with_locked)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.get_multisig_utxos(account_index, utxo_types, utxo_states, with_locked)
            }
        }
    }

    pub fn pending_transactions(
        &self,
        account_index: U31,
    ) -> WalletResult<Vec<WithId<&Transaction>>> {
        match self {
            RuntimeWallet::Software(w) => w.pending_transactions(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.pending_transactions(account_index),
        }
    }

    pub fn mainchain_transactions(
        &self,
        account_index: U31,
        destination: Option<Destination>,
        limit: usize,
    ) -> WalletResult<Vec<TxInfo>> {
        match self {
            RuntimeWallet::Software(w) => {
                w.mainchain_transactions(account_index, destination, limit)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.mainchain_transactions(account_index, destination, limit),
        }
    }

    pub fn get_transaction_list(
        &self,
        account_index: U31,
        skip: usize,
        count: usize,
    ) -> WalletResult<TransactionList> {
        match self {
            RuntimeWallet::Software(w) => w.get_transaction_list(account_index, skip, count),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_transaction_list(account_index, skip, count),
        }
    }

    pub fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> WalletResult<&TxData> {
        match self {
            RuntimeWallet::Software(w) => w.get_transaction(account_index, transaction_id),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_transaction(account_index, transaction_id),
        }
    }

    pub fn get_all_issued_addresses(
        &self,
        account_index: U31,
        key_purpose: KeyPurpose,
    ) -> WalletResult<BTreeMap<ChildNumber, Address<Destination>>> {
        match self {
            RuntimeWallet::Software(w) => w.get_all_issued_addresses(account_index, key_purpose),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_all_issued_addresses(account_index, key_purpose),
        }
    }

    pub fn get_address_coin_balances(
        &self,
        account_index: U31,
    ) -> WalletResult<BTreeMap<Destination, Amount>> {
        match self {
            RuntimeWallet::Software(w) => w.get_address_coin_balances(
                account_index,
                UtxoState::Confirmed.into(),
                WithLocked::Unlocked,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_address_coin_balances(
                account_index,
                UtxoState::Confirmed.into(),
                WithLocked::Unlocked,
            ),
        }
    }

    pub fn get_all_issued_vrf_public_keys(
        &self,
        account_index: U31,
    ) -> WalletResult<BTreeMap<ChildNumber, (Address<VRFPublicKey>, bool)>> {
        match self {
            RuntimeWallet::Software(w) => w.get_all_issued_vrf_public_keys(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(_) => Err(WalletError::UnsupportedHardwareWalletOperation),
        }
    }

    pub fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> WalletResult<Address<VRFPublicKey>> {
        match self {
            RuntimeWallet::Software(w) => w.get_legacy_vrf_public_key(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(_) => Err(WalletError::UnsupportedHardwareWalletOperation),
        }
    }

    pub fn get_addresses_usage(
        &self,
        account_index: U31,
        key_purpose: KeyPurpose,
    ) -> WalletResult<&KeychainUsageState> {
        match self {
            RuntimeWallet::Software(w) => w.get_addresses_usage(account_index, key_purpose),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_addresses_usage(account_index, key_purpose),
        }
    }

    pub fn get_all_standalone_addresses(
        &self,
        account_index: U31,
    ) -> WalletResult<StandaloneAddresses> {
        match self {
            RuntimeWallet::Software(w) => w.get_all_standalone_addresses(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_all_standalone_addresses(account_index),
        }
    }

    pub fn get_all_standalone_address_details(
        &self,
        account_index: U31,
        address: Destination,
    ) -> WalletResult<(
        Destination,
        BTreeMap<Currency, Amount>,
        StandaloneAddressDetails,
    )> {
        match self {
            RuntimeWallet::Software(w) => {
                w.get_all_standalone_address_details(account_index, address)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.get_all_standalone_address_details(account_index, address)
            }
        }
    }

    pub fn get_created_blocks(
        &self,
        account_index: U31,
    ) -> WalletResult<Vec<(BlockHeight, Id<GenBlock>, PoolId)>> {
        match self {
            RuntimeWallet::Software(w) => w.get_created_blocks(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_created_blocks(account_index),
        }
    }

    pub fn find_used_tokens(
        &self,
        account_index: U31,
        input_utxos: &[UtxoOutPoint],
    ) -> WalletResult<BTreeSet<TokenId>> {
        match self {
            RuntimeWallet::Software(w) => w.find_used_tokens(account_index, input_utxos),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_used_tokens(account_index, input_utxos),
        }
    }

    pub fn get_token_unconfirmed_info(
        &self,
        account_index: U31,
        token_info: RPCFungibleTokenInfo,
    ) -> WalletResult<UnconfirmedTokenInfo> {
        match self {
            RuntimeWallet::Software(w) => w.get_token_unconfirmed_info(account_index, token_info),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_token_unconfirmed_info(account_index, token_info),
        }
    }

    pub fn abandon_transaction(
        &mut self,
        account_index: U31,
        tx_id: Id<Transaction>,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => w.abandon_transaction(account_index, tx_id),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.abandon_transaction(account_index, tx_id),
        }
    }

    pub fn standalone_address_label_rename(
        &mut self,
        account_index: U31,
        address: Destination,
        label: Option<String>,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => {
                w.standalone_address_label_rename(account_index, address, label)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.standalone_address_label_rename(account_index, address, label)
            }
        }
    }

    pub fn add_standalone_address(
        &mut self,
        account_index: U31,
        address: PublicKeyHash,
        label: Option<String>,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => w.add_standalone_address(account_index, address, label),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.add_standalone_address(account_index, address, label),
        }
    }

    pub fn add_standalone_private_key(
        &mut self,
        account_index: U31,
        private_key: PrivateKey,
        label: Option<String>,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => {
                w.add_standalone_private_key(account_index, private_key, label)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.add_standalone_private_key(account_index, private_key, label)
            }
        }
    }

    pub fn add_standalone_multisig(
        &mut self,
        account_index: U31,
        challenge: ClassicMultisigChallenge,
        label: Option<String>,
    ) -> WalletResult<PublicKeyHash> {
        match self {
            RuntimeWallet::Software(w) => {
                w.add_standalone_multisig(account_index, challenge, label)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.add_standalone_multisig(account_index, challenge, label),
        }
    }

    pub fn get_new_address(
        &mut self,
        account_index: U31,
    ) -> WalletResult<(ChildNumber, Address<Destination>)> {
        match self {
            RuntimeWallet::Software(w) => w.get_new_address(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_new_address(account_index),
        }
    }

    pub fn find_public_key(
        &mut self,
        account_index: U31,
        address: Destination,
    ) -> WalletResult<PublicKey> {
        match self {
            RuntimeWallet::Software(w) => w.find_public_key(account_index, address),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.find_public_key(account_index, address),
        }
    }

    pub fn get_vrf_key(
        &mut self,
        account_index: U31,
    ) -> WalletResult<(ChildNumber, Address<VRFPublicKey>)> {
        match self {
            RuntimeWallet::Software(w) => w.get_vrf_key(account_index),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(_) => Err(WalletError::UnsupportedHardwareWalletOperation),
        }
    }

    pub fn issue_new_token(
        &mut self,
        account_index: U31,
        token_issuance: TokenIssuance,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTxWithFees)> {
        match self {
            RuntimeWallet::Software(w) => w.issue_new_token(
                account_index,
                token_issuance,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.issue_new_token(
                account_index,
                token_issuance,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn issue_new_nft(
        &mut self,
        account_index: U31,
        address: Address<Destination>,
        metadata: Metadata,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTxWithFees)> {
        match self {
            RuntimeWallet::Software(w) => w.issue_new_nft(
                account_index,
                address,
                metadata,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.issue_new_nft(
                account_index,
                address,
                metadata,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn mint_tokens(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        amount: Amount,
        address: Address<Destination>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.mint_tokens(
                account_index,
                token_info,
                amount,
                address,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.mint_tokens(
                account_index,
                token_info,
                amount,
                address,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn unmint_tokens(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        amount: Amount,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.unmint_tokens(
                account_index,
                token_info,
                amount,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.unmint_tokens(
                account_index,
                token_info,
                amount,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn lock_token_supply(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.lock_token_supply(
                account_index,
                token_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.lock_token_supply(
                account_index,
                token_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn freeze_token(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        is_token_unfreezable: IsTokenUnfreezable,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.freeze_token(
                account_index,
                token_info,
                is_token_unfreezable,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.freeze_token(
                account_index,
                token_info,
                is_token_unfreezable,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn unfreeze_token(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.unfreeze_token(
                account_index,
                token_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.unfreeze_token(
                account_index,
                token_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn change_token_authority(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        address: Address<Destination>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.change_token_authority(
                account_index,
                token_info,
                address,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.change_token_authority(
                account_index,
                token_info,
                address,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn change_token_metadata_uri(
        &mut self,
        account_index: U31,
        token_info: &UnconfirmedTokenInfo,
        metadata_uri: Vec<u8>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> Result<SignedTxWithFees, WalletError> {
        match self {
            RuntimeWallet::Software(w) => w.change_token_metadata_uri(
                account_index,
                token_info,
                metadata_uri,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.change_token_metadata_uri(
                account_index,
                token_info,
                metadata_uri,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_transaction_to_addresses(
        &mut self,
        account_index: U31,
        outputs: impl IntoIterator<Item = TxOutput>,
        inputs: SelectedInputs,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_transaction_to_addresses(
                account_index,
                outputs,
                inputs,
                change_addresses,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_transaction_to_addresses(
                account_index,
                outputs,
                inputs,
                change_addresses,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    pub fn create_sweep_transaction(
        &mut self,
        account_index: U31,
        destination_address: Destination,
        filtered_inputs: Vec<(UtxoOutPoint, TxOutput)>,
        current_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_sweep_transaction(
                account_index,
                destination_address,
                filtered_inputs,
                current_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_sweep_transaction(
                account_index,
                destination_address,
                filtered_inputs,
                current_fee_rate,
                additional_info,
            ),
        }
    }

    pub fn get_delegation(
        &self,
        account_index: U31,
        delegation_id: DelegationId,
    ) -> WalletResult<&DelegationData> {
        match self {
            RuntimeWallet::Software(w) => w.get_delegation(account_index, delegation_id),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.get_delegation(account_index, delegation_id),
        }
    }

    pub fn create_sweep_from_delegation_transaction(
        &mut self,
        account_index: U31,
        destination_address: Address<Destination>,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_sweep_from_delegation_transaction(
                account_index,
                destination_address,
                delegation_id,
                delegation_share,
                current_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_sweep_from_delegation_transaction(
                account_index,
                destination_address,
                delegation_id,
                delegation_share,
                current_fee_rate,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_unsigned_transaction_to_addresses(
        &mut self,
        account_index: U31,
        outputs: impl IntoIterator<Item = TxOutput>,
        selected_inputs: SelectedInputs,
        selection_algo: Option<CoinSelectionAlgo>,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<(PartiallySignedTransaction, BTreeMap<Currency, Amount>)> {
        match self {
            RuntimeWallet::Software(w) => w.create_unsigned_transaction_to_addresses(
                account_index,
                outputs,
                selected_inputs,
                selection_algo,
                change_addresses,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_unsigned_transaction_to_addresses(
                account_index,
                outputs,
                selected_inputs,
                selection_algo,
                change_addresses,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    pub fn create_delegation(
        &mut self,
        account_index: U31,
        output: TxOutput,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(DelegationId, SignedTxWithFees)> {
        match self {
            RuntimeWallet::Software(w) => w.create_delegation(
                account_index,
                vec![output],
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_delegation(
                account_index,
                vec![output],
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn create_transaction_to_addresses_from_delegation(
        &mut self,
        account_index: U31,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_transaction_to_addresses_from_delegation(
                account_index,
                address,
                amount,
                delegation_id,
                delegation_share,
                current_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_transaction_to_addresses_from_delegation(
                account_index,
                address,
                amount,
                delegation_id,
                delegation_share,
                current_fee_rate,
            ),
        }
    }

    pub fn create_stake_pool(
        &mut self,
        account_index: U31,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        stake_pool_arguments: StakePoolCreationArguments,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_stake_pool(
                account_index,
                current_fee_rate,
                consolidate_fee_rate,
                stake_pool_arguments,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_stake_pool_with_vrf_key(
                account_index,
                current_fee_rate,
                consolidate_fee_rate,
                stake_pool_arguments,
            ),
        }
    }

    pub fn decommission_stake_pool(
        &mut self,
        account_index: U31,
        pool_id: PoolId,
        staker_balance: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.decommission_stake_pool(
                account_index,
                pool_id,
                staker_balance,
                output_address,
                current_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.decommission_stake_pool(
                account_index,
                pool_id,
                staker_balance,
                output_address,
                current_fee_rate,
            ),
        }
    }

    pub fn decommission_stake_pool_request(
        &mut self,
        account_index: U31,
        pool_id: PoolId,
        staker_balance: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
    ) -> WalletResult<PartiallySignedTransaction> {
        match self {
            RuntimeWallet::Software(w) => w.decommission_stake_pool_request(
                account_index,
                pool_id,
                staker_balance,
                output_address,
                current_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.decommission_stake_pool_request(
                account_index,
                pool_id,
                staker_balance,
                output_address,
                current_fee_rate,
            ),
        }
    }

    pub fn create_htlc_tx(
        &mut self,
        account_index: U31,
        output_value: OutputValue,
        htlc: HashedTimelockContract,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_htlc_tx(
                account_index,
                output_value,
                htlc,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_htlc_tx(
                account_index,
                output_value,
                htlc,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_order_tx(
        &mut self,
        account_index: U31,
        ask_value: OutputValue,
        give_value: OutputValue,
        conclude_key: Address<Destination>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<(OrderId, SignedTxWithFees)> {
        match self {
            RuntimeWallet::Software(w) => w.create_order_tx(
                account_index,
                ask_value,
                give_value,
                conclude_key,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_order_tx(
                account_index,
                ask_value,
                give_value,
                conclude_key,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_conclude_order_tx(
        &mut self,
        account_index: U31,
        order_id: OrderId,
        order_info: RpcOrderInfo,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_conclude_order_tx(
                account_index,
                order_id,
                order_info,
                output_address,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_conclude_order_tx(
                account_index,
                order_id,
                order_info,
                output_address,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_fill_order_tx(
        &mut self,
        account_index: U31,
        order_id: OrderId,
        order_info: RpcOrderInfo,
        fill_amount_in_ask_currency: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_fill_order_tx(
                account_index,
                order_id,
                order_info,
                fill_amount_in_ask_currency,
                output_address,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_fill_order_tx(
                account_index,
                order_id,
                order_info,
                fill_amount_in_ask_currency,
                output_address,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    pub fn create_freeze_order_tx(
        &mut self,
        account_index: U31,
        order_id: OrderId,
        order_info: RpcOrderInfo,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<SignedTxWithFees> {
        match self {
            RuntimeWallet::Software(w) => w.create_freeze_order_tx(
                account_index,
                order_id,
                order_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_freeze_order_tx(
                account_index,
                order_id,
                order_info,
                current_fee_rate,
                consolidate_fee_rate,
            ),
        }
    }

    pub fn sign_raw_transaction(
        &mut self,
        account_index: U31,
        ptx: PartiallySignedTransaction,
    ) -> WalletResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        match self {
            RuntimeWallet::Software(w) => w.sign_raw_transaction(account_index, ptx),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.sign_raw_transaction(account_index, ptx),
        }
    }

    pub fn sign_challenge(
        &mut self,
        account_index: U31,
        challenge: &[u8],
        destination: &Destination,
    ) -> WalletResult<ArbitraryMessageSignature> {
        match self {
            RuntimeWallet::Software(w) => w.sign_challenge(account_index, challenge, destination),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.sign_challenge(account_index, challenge, destination),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_transaction_to_addresses_with_intent(
        &mut self,
        account_index: U31,
        outputs: impl IntoIterator<Item = TxOutput>,
        inputs: SelectedInputs,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        intent: String,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<(SignedTxWithFees, SignedTransactionIntent)> {
        match self {
            RuntimeWallet::Software(w) => w.create_transaction_to_addresses_with_intent(
                account_index,
                outputs,
                inputs,
                change_addresses,
                intent,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.create_transaction_to_addresses_with_intent(
                account_index,
                outputs,
                inputs,
                change_addresses,
                intent,
                current_fee_rate,
                consolidate_fee_rate,
                additional_info,
            ),
        }
    }

    pub fn add_unconfirmed_tx(
        &mut self,
        tx: SignedTransaction,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => w.add_unconfirmed_tx(tx, wallet_events),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w.add_unconfirmed_tx(tx, wallet_events),
        }
    }

    pub fn add_account_unconfirmed_tx(
        &mut self,
        account_index: U31,
        tx: &SignedTransaction,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        match self {
            RuntimeWallet::Software(w) => {
                w.add_account_unconfirmed_tx(account_index, tx.clone(), wallet_events)
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                w.add_account_unconfirmed_tx(account_index, tx.clone(), wallet_events)
            }
        }
    }

    pub fn get_delegations(
        &self,
        account_index: U31,
    ) -> WalletResult<Box<dyn Iterator<Item = (&DelegationId, &DelegationData)> + '_>> {
        match self {
            RuntimeWallet::Software(w) => w
                .get_delegations(account_index)
                .map(|it| -> Box<dyn Iterator<Item = _>> { Box::new(it) }),
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => w
                .get_delegations(account_index)
                .map(|it| -> Box<dyn Iterator<Item = _>> { Box::new(it) }),
        }
    }
}
