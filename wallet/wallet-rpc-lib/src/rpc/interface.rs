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

// Note: can't specify this on individual functions because the `rpc` proc macro doesn't propagate
// extra attributes.
#![allow(clippy::too_many_arguments)]

use std::{collections::BTreeMap, num::NonZeroUsize};

use chainstate::rpc::RpcOutputValueIn;
use common::{
    address::RpcAddress,
    chain::{
        block::timestamp::BlockTimestamp, tokens::TokenId, Block, DelegationId, Destination,
        GenBlock, OrderId, PoolId, SignedTransaction, SignedTransactionIntent, Transaction,
        TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use crypto::{key::PrivateKey, vrf::VRFPublicKey};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use rpc::types::RpcHexString;
use wallet::account::TxInfo;
use wallet_controller::{
    types::{BlockInfo, CreatedBlockInfo, GenericTokenTransfer, SeedWithPassPhrase, WalletInfo},
    ConnectedPeer,
};
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, with_locked::WithLocked,
};

use crate::types::{
    AccountArg, AddressInfo, AddressWithUsageInfo, Balances, ChainInfo, ComposedTransaction,
    CreatedWallet, DelegationInfo, HardwareWalletType, HexEncoded, LegacyVrfPublicKeyInfo,
    MaybeSignedTransaction, NewAccountInfo, NewDelegation, NewOrder, NewTransaction, NftMetadata,
    NodeVersion, OpenedWallet, PoolInfo, PublicKeyInfo, RpcAmountIn, RpcHashedTimelockContract,
    RpcInspectTransaction, RpcStandaloneAddresses, RpcTokenId, RpcUtxoOutpoint, RpcUtxoState,
    RpcUtxoType, SendTokensFromMultisigAddressResult, StakePoolBalance, StakingStatus,
    StandaloneAddressWithDetails, TokenMetadata, TransactionOptions, TxOptionsOverrides,
    VrfPublicKeyInfo,
};

use super::types::UtxoInfo;

#[rpc::rpc(server)]
trait WalletEventsRpc {
    #[subscription(name = "subscribe_wallet_events", item = Event)]
    async fn subscribe_wallet_events(&self) -> rpc::subscription::Reply;
}

/// RPC methods available in the cold wallet mode.
#[rpc::describe]
#[rpc::rpc(server, client)]
trait ColdWalletRpc {
    #[method(name = "shutdown")]
    async fn shutdown(&self) -> rpc::RpcResult<()>;

    /// Print the version of the wallet software and possibly the git commit hash, if found WWW!!
    #[method(name = "version")]
    async fn version(&self) -> rpc::RpcResult<String>;

    /// Create a new wallet, this will skip scanning the blockchain
    #[method(name = "wallet_create")]
    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> rpc::RpcResult<CreatedWallet>;

    /// Recover new wallet, this will rescan the blockchain upon creation
    #[method(name = "wallet_recover")]
    async fn recover_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> rpc::RpcResult<CreatedWallet>;

    /// Open an exiting wallet by specifying the file location of the wallet file
    #[method(name = "wallet_open")]
    async fn open_wallet(
        &self,
        path: String,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> rpc::RpcResult<OpenedWallet>;

    /// Close the currently open wallet file
    #[method(name = "wallet_close")]
    async fn close_wallet(&self) -> rpc::RpcResult<()>;

    /// Check the current wallet's number of accounts and their names
    #[method(name = "wallet_info")]
    async fn wallet_info(&self) -> rpc::RpcResult<WalletInfo>;

    /// Encrypts the private keys with a new password, expects the wallet to be unlocked
    #[method(name = "wallet_encrypt_private_keys")]
    async fn encrypt_private_keys(&self, password: String) -> rpc::RpcResult<()>;

    /// Completely and totally remove any existing encryption, expects the wallet to be unlocked.
    /// WARNING: After this, your wallet file will be USABLE BY ANYONE without a password.
    #[method(name = "wallet_disable_private_keys_encryption")]
    async fn remove_private_key_encryption(&self) -> rpc::RpcResult<()>;

    /// Unlocks the private keys for usage.
    #[method(name = "wallet_unlock_private_keys")]
    async fn unlock_private_keys(&self, password: String) -> rpc::RpcResult<()>;

    /// Locks the private keys so they can't be used until they are unlocked again
    #[method(name = "wallet_lock_private_keys")]
    async fn lock_private_key_encryption(&self) -> rpc::RpcResult<()>;

    /// Show the seed phrase for the loaded wallet if it has been stored.
    #[method(name = "wallet_show_seed_phrase")]
    async fn get_seed_phrase(&self) -> rpc::RpcResult<Option<SeedWithPassPhrase>>;

    /// Delete the seed phrase from the loaded wallet's database, if it has been stored.
    #[method(name = "wallet_purge_seed_phrase")]
    async fn purge_seed_phrase(&self) -> rpc::RpcResult<Option<SeedWithPassPhrase>>;

    /// Set the lookahead size for key generation.
    ///
    /// The lookahead size, also known as the gap limit, determines the number of addresses
    /// to generate and monitor on the blockchain for incoming transactions, following the last
    /// known address with a transaction.
    /// Only reduce this value if you are certain there are no incoming transactions on these addresses.
    #[method(name = "wallet_set_lookahead_size")]
    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> rpc::RpcResult<()>;

    /// Show receive-addresses with their usage state.
    /// Note that whether an address is used isn't based on the wallet,
    /// but on the blockchain. So if an address is used in a transaction,
    /// it will be marked as used only when the transaction is included
    /// in a block.
    #[method(name = "address_show")]
    async fn get_issued_addresses(
        &self,
        account: AccountArg,
        include_change_addresses: bool,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>>;

    /// Show standalone added addresses with their labels.
    #[method(name = "standalone_address_show")]
    async fn get_standalone_addresses(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<RpcStandaloneAddresses>;

    /// Show standalone addresses details.
    #[method(name = "standalone_address_details")]
    async fn get_standalone_address_details(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<StandaloneAddressWithDetails>;

    /// Generate a new unused address
    #[method(name = "address_new")]
    async fn issue_address(&self, account: AccountArg) -> rpc::RpcResult<AddressInfo>;

    /// Reveal the public key behind this address in hex encoding and address encoding.
    /// Note that this isn't a normal address to be used in transactions.
    /// It's preferred to take the address from address-show command
    #[method(name = "address_reveal_public_key")]
    async fn reveal_public_key(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<PublicKeyInfo>;

    /// Issue a new staking VRF (Verifiable Random Function) key for this account.
    /// VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
    /// where no one can control the possible outcomes, to ensure decentralization.
    /// NOTE: Under normal circumstances you don't need to generate VRF keys manually.
    /// Creating a new staking pool will do it for you. This is available for specialized use-cases.
    #[method(name = "staking_new_vrf_public_key")]
    async fn new_vrf_public_key(&self, account: AccountArg) -> rpc::RpcResult<VrfPublicKeyInfo>;

    /// Shows the legacy VRF key that uses an abandoned derivation mechanism.
    /// This will not be used for new pools and should be avoided
    #[method(name = "staking_show_legacy_vrf_key")]
    async fn get_legacy_vrf_public_key(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<LegacyVrfPublicKeyInfo>;

    /// Show the issued staking VRF (Verifiable Random Function) keys for this account.
    /// These keys are generated when pools are created.
    /// VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
    /// where no one can control the possible outcomes, to ensure decentralization.
    #[method(name = "staking_show_vrf_public_keys")]
    async fn get_vrf_public_key(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<Vec<VrfPublicKeyInfo>>;

    #[method(name = "account_sign_raw_transaction")]
    /// Signs the inputs that are not yet signed.
    /// The input is a special format of the transaction serialized to hex. This format is automatically used in this wallet
    /// in functions such as staking-decommission-pool-request. Once all signatures are complete, the result can be broadcast
    /// to the network.
    async fn sign_raw_transaction(
        &self,
        account: AccountArg,
        raw_tx: RpcHexString,
        options: TransactionOptions,
    ) -> rpc::RpcResult<MaybeSignedTransaction>;

    #[method(name = "challenge_sign_plain")]
    /// Signs a challenge with a private key corresponding to the provided address destination.
    async fn sign_challenge(
        &self,
        account: AccountArg,
        challenge: String,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<RpcHexString>;

    #[method(name = "challenge_sign_hex")]
    /// Signs a challenge with a private key corresponding to the provided address destination.
    async fn sign_challenge_hex(
        &self,
        account: AccountArg,
        challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<RpcHexString>;

    #[method(name = "challenge_verify_plain")]
    /// Verifies a signed challenge against an address destination
    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<()>;

    #[method(name = "challenge_verify_hex")]
    /// Verifies a signed challenge against an address destination
    async fn verify_challenge_hex(
        &self,
        message: RpcHexString,
        signed_challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<()>;
}

/// RPC methods available in the hot wallet mode.
#[rpc::describe]
#[rpc::rpc(server, client)]
trait WalletRpc {
    /// Force the wallet to scan the remaining blocks from node until the tip is reached
    #[method(name = "wallet_sync")]
    async fn sync(&self) -> rpc::RpcResult<()>;

    /// Rescan the blockchain and re-detect all operations related to the selected account in this wallet
    #[method(name = "wallet_rescan")]
    async fn rescan(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_best_block")]
    async fn best_block(&self) -> rpc::RpcResult<BlockInfo>;

    /// Creates a new account with an optional name.
    /// Returns an error if the last created account does not have a transaction history.
    #[method(name = "account_create")]
    async fn create_account(&self, name: Option<String>) -> rpc::RpcResult<NewAccountInfo>;

    /// Renames the selected account with an optional name.
    /// If the name is not specified, it will remove any existing name for the account.
    #[method(name = "account_rename")]
    async fn rename_account(
        &self,
        account: AccountArg,
        name: Option<String>,
    ) -> rpc::RpcResult<NewAccountInfo>;

    /// Add, rename or delete a label to an already added standalone address.
    /// Specifying a label will add or replace the existing one,
    /// and not specifying a label will remove the existing one.
    #[method(name = "standalone_address_label_rename")]
    async fn standalone_address_label_rename(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        label: Option<String>,
    ) -> rpc::RpcResult<()>;

    /// Add a new standalone watch only address not derived from the selected account's key chain
    #[method(name = "standalone_add_watch_only_address")]
    async fn add_standalone_address(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<()>;

    /// Add a new standalone private key not derived from the selected account's key chain to be watched
    #[method(name = "standalone_add_private_key_from_hex")]
    async fn add_standalone_private_key(
        &self,
        account: AccountArg,
        hex_private_key: HexEncoded<PrivateKey>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<()>;

    /// Add a new standalone multi signature address
    /// Use the `transaction_compose` command to use the new multisig address as input or output
    #[method(name = "standalone_add_multisig")]
    async fn add_standalone_multisig(
        &self,
        account: AccountArg,
        min_required_signatures: u8,
        public_keys: Vec<RpcAddress<Destination>>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<String>;

    /// Lists all the utxos owned by a multisig watched by this account
    #[method(name = "standalone_multisig_utxos")]
    async fn get_multisig_utxos(
        &self,
        account: AccountArg,
        utxo_types: Vec<RpcUtxoType>,
        utxo_states: Vec<RpcUtxoState>,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Vec<UtxoInfo>>;

    /// Get the total balance in the selected account in this wallet. See available options to include more categories, like locked coins.
    #[method(name = "account_balance")]
    async fn get_balance(
        &self,
        account: AccountArg,
        utxo_states: Vec<RpcUtxoState>,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances>;

    /// Lists all the utxos owned by this account
    #[method(name = "account_utxos")]
    async fn get_utxos(&self, account: AccountArg) -> rpc::RpcResult<Vec<UtxoInfo>>;

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network
    #[method(name = "node_submit_transaction")]
    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Send a given coin amount to a given address. The wallet will automatically calculate the required information
    /// Optionally, one can also mention the utxos to be used.
    #[method(name = "address_send")]
    async fn send_coins(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxos: Vec<RpcUtxoOutpoint>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Sweep all spendable coins or tokens from an address or addresses to a given address.
    /// Spendable coins are any coins that are not locked, and tokens that are not frozen or locked.
    /// The wallet will automatically calculate the required fees
    #[method(name = "address_sweep_spendable")]
    async fn sweep_addresses(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        from_addresses: Vec<RpcAddress<Destination>>,
        all: Option<bool>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Sweep all the coins from a delegation to a given address.
    /// The wallet will automatically calculate the required fees
    #[method(name = "staking_sweep_delegation")]
    async fn sweep_delegation(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Creates a transaction that spends from a specific address,
    /// and returns the change to the same address (unless one is specified), without signature.
    /// This transaction is used for "withdrawing" small amounts from a cold storage
    /// without changing the ownership address. Once this is created,
    /// it can be signed using account-sign-raw-transaction in the cold wallet
    /// and then broadcast through any hot wallet.
    /// In summary, this creates a transaction with one input and two outputs,
    /// with one of the outputs being change returned to the same owner of the input.
    #[method(name = "transaction_create_from_cold_input")]
    async fn transaction_from_cold_input(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxo: RpcUtxoOutpoint,
        change_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<ComposedTransaction>;

    /// Print the summary of the transaction
    #[method(name = "transaction_inspect")]
    async fn transaction_inspect(
        &self,
        transaction: RpcHexString,
    ) -> rpc::RpcResult<RpcInspectTransaction>;

    /// Create a staking pool. The pool will be capable of creating blocks and gaining rewards,
    /// and will be capable of taking delegations from other users and staking.
    ///
    /// The decommission key is the key that can decommission the pool.
    ///
    /// Cost per block, and margin ratio are parameters that control how delegators receive rewards.
    /// The cost per block is an amount in coins to be subtracted from the total rewards in a block first,
    /// and handed to the staking pool. After subtracting the cost per block, a fraction equal to
    /// margin ratio is taken from what is left, and given to the staking pool. Finally, what is left
    /// is distributed among delegators, pro-rata, based on their delegation amounts.
    ///
    /// The optional parameters `staker_address` and `vrf_public_key` specify the key that will sign new blocks
    /// and the VRF key that will be used to produce POS hashes during staking.
    /// You only need to specify them if the wallet where the pool is being created differs from
    /// the one where the actual staking will be performed.
    /// In such a case, make sure that the specified keys are owned by the wallet that will be used to stake.
    /// On the other hand, if the current wallet will be used for staking, just leave them empty
    /// and the wallet will select appropriate values itself.
    /// Note: staker_address must be a "public key" address and not a "public key hash" one.
    #[method(name = "staking_create_pool")]
    async fn create_stake_pool(
        &self,
        account: AccountArg,
        amount: RpcAmountIn,
        cost_per_block: RpcAmountIn,
        margin_ratio_per_thousand: String,
        decommission_address: RpcAddress<Destination>,
        staker_address: Option<RpcAddress<Destination>>,
        vrf_public_key: Option<RpcAddress<VRFPublicKey>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Decommission a staking pool, given its id. This assumes that the decommission key is owned
    /// by the selected account in this wallet.
    #[method(name = "staking_decommission_pool")]
    async fn decommission_stake_pool(
        &self,
        account: AccountArg,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Create a request to decommission a pool. This assumes that the decommission key is owned
    /// by another wallet. The output of this command should be passed to account-sign-raw-transaction
    /// in the wallet that owns the decommission key. The result from signing, assuming success, can
    /// then be broadcast to network to commence with decommissioning.
    #[method(name = "staking_decommission_pool_request")]
    async fn decommission_stake_pool_request(
        &self,
        account: AccountArg,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<HexEncoded<PartiallySignedTransaction>>;

    /// Create a delegation to a given pool id and the owner address/destination.
    /// The owner of a delegation is the key authorized to withdraw from the delegation.
    /// The delegation creation will result in creating a delegation id, where coins sent to that id will be staked by the pool id provided, automatically.
    /// The pool, to which the delegation is made, doesn't have the authority to spend the coins.
    #[method(name = "delegation_create")]
    async fn create_delegation(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        pool_id: RpcAddress<PoolId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation>;

    /// Send coins to a delegation id to be staked
    #[method(name = "delegation_stake")]
    async fn delegate_staking(
        &self,
        account: AccountArg,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Send coins from a delegation id (that you own) to stop staking them.
    /// Note that stopping the delegation requires a lock period.
    #[method(name = "delegation_withdraw")]
    async fn withdraw_from_delegation(
        &self,
        account: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Start staking, assuming there are staking pools in the selected account in this wallet.
    #[method(name = "staking_start")]
    async fn start_staking(&self, account: AccountArg) -> rpc::RpcResult<()>;

    /// Stop staking, assuming there are staking pools staking currently in the selected account in this wallet.
    #[method(name = "staking_stop")]
    async fn stop_staking(&self, account: AccountArg) -> rpc::RpcResult<()>;

    /// Show the staking status for the currently selected account in this wallet.
    #[method(name = "staking_status")]
    async fn staking_status(&self, account: AccountArg) -> rpc::RpcResult<StakingStatus>;

    /// List ids of pools that are controlled by the selected account in this wallet
    #[method(name = "staking_list_pools")]
    async fn list_pools(&self, account: AccountArg) -> rpc::RpcResult<Vec<PoolInfo>>;

    /// List pools that can be decommissioned by the selected account in this wallet
    #[method(name = "staking_list_owned_pools_for_decommission")]
    async fn list_pools_for_decommission(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<Vec<PoolInfo>>;

    /// Print the balance of available staking pools
    #[method(name = "staking_pool_balance")]
    async fn stake_pool_balance(
        &self,
        pool_id: RpcAddress<PoolId>,
    ) -> rpc::RpcResult<StakePoolBalance>;

    /// List delegation ids controlled by the selected account in this wallet with their balances
    #[method(name = "delegation_list_ids")]
    async fn list_delegation_ids(&self, account: AccountArg)
        -> rpc::RpcResult<Vec<DelegationInfo>>;

    /// List the blocks created by the selected account in this wallet through staking/mining/etc
    #[method(name = "staking_list_created_block_ids")]
    async fn list_created_blocks_ids(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<Vec<CreatedBlockInfo>>;

    /// Issue a new non-fungible token (NFT) from scratch
    #[method(name = "token_nft_issue_new")]
    async fn issue_new_nft(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        metadata: NftMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId>;

    /// Issue a new fungible token from scratch.
    /// Notice that issuing a token fills an issuers supply. To have tokens that are spendable,
    /// the issuer must "mint" tokens to take from the supply
    #[method(name = "token_issue_new")]
    async fn issue_new_token(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        metadata: TokenMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId>;

    /// Change the authority of a token; i.e., the cryptographic authority that can do all authority token operations
    #[method(name = "token_change_authority")]
    async fn change_token_authority(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Change the metadata URI of a token
    #[method(name = "token_change_metadata_uri")]
    async fn change_token_metadata_uri(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        metadata_uri: RpcHexString,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Given a token that is already issued, mint new tokens and increase the total supply
    #[method(name = "token_mint")]
    async fn mint_tokens(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Unmint existing tokens and reduce the total supply
    /// Unminting reduces the total supply and puts the unminted tokens back at the issuer's control.
    /// The wallet must own the tokens that are being unminted.
    #[method(name = "token_unmint")]
    async fn unmint_tokens(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Lock the circulating supply for the token. THIS IS IRREVERSIBLE.
    ///
    /// Once locked, tokens lose the ability to be minted/unminted.
    #[method(name = "token_lock_supply")]
    async fn lock_token_supply(
        &self,
        account_index: AccountArg,
        token_id: RpcAddress<TokenId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Freezing the token (by token authority) forbids any operation with all the tokens (except for the optional unfreeze).
    ///
    /// After a token is frozen, no transfers, spends, or any other operation can be done.
    /// This wallet (and selected account) must own the authority keys to be able to freeze.
    #[method(name = "token_freeze")]
    async fn freeze_token(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        is_unfreezable: bool,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// By unfreezing the token all operations are available for the tokens again.
    ///
    /// Notice that this is only possible if the tokens were made to be unfreezable during freezing.
    /// This wallet (and selected account) must own the authority keys to be able to unfreeze.
    #[method(name = "token_unfreeze")]
    async fn unfreeze_token(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Send the given token amount to the given address. The wallet will automatically calculate the required information.
    #[method(name = "token_send")]
    async fn send_tokens(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Create a transaction for sending tokens to the given address, without submitting it.
    /// The wallet will automatically calculate the required information.
    ///
    /// The "intent" is an arbitrary string that will be concatenated with the id of the created transaction
    /// and signed by all the keys that were used to sign the transaction itself; this can be used to declare
    /// the intent of the transaction.
    /// E.g. when bridging Mintlayer tokens to another chain, you need to send tokens to an address provided
    /// by the bridge and provide the bridge with the destination address on the foreign chain where you want
    /// to receive them. In this case you will set "intent" to this foreign destination address; the signed intent
    /// will then serve as a proof to the bridge that the provided destination address is what it's meant to be.
    #[method(name = "token_make_tx_for_sending_with_intent")]
    async fn make_tx_for_sending_tokens_with_intent(
        &self,
        account: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        intent: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<(
        HexEncoded<SignedTransaction>,
        HexEncoded<SignedTransactionIntent>,
    )>;

    /// Create a transaction for sending tokens from a multisig address to other addresses, returning the change to
    /// the original multisig address.
    ///
    /// The utxos to pay fees from will be selected automatically; these will be normal, single-sig utxos.
    /// The `fee_change_address` parameter specifies the destination for the change for the fee payment;
    /// If it's `None`, the destination will be taken from one of existing single-sig utxos.
    #[method(name = "make_tx_to_send_tokens_from_multisig_address")]
    async fn make_tx_to_send_tokens_from_multisig_address(
        &self,
        account_arg: AccountArg,
        from_address: RpcAddress<Destination>,
        fee_change_address: Option<RpcAddress<Destination>>,
        outputs: Vec<GenericTokenTransfer>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<SendTokensFromMultisigAddressResult>;

    /// Store data on the blockchain, the data is provided as hex encoded string.
    /// Note that there is a high fee for storing data on the blockchain.
    #[method(name = "address_deposit_data")]
    async fn deposit_data(
        &self,
        account: AccountArg,
        data: RpcHexString,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Creates a transaction that locks a given number of coins or tokens in a Hashed Timelock Contract.
    /// Created transaction is not broadcasted by this function.
    #[method(name = "create_htlc_transaction")]
    async fn create_htlc_transaction(
        &self,
        account: AccountArg,
        amount: RpcAmountIn,
        token_id: Option<RpcAddress<TokenId>>,
        htlc: RpcHashedTimelockContract,
        options: TransactionOptions,
    ) -> rpc::RpcResult<HexEncoded<SignedTransaction>>;

    /// Create an order for exchanging "given" amount of an arbitrary currency (coins or tokens) for
    /// an arbitrary amount of "asked" currency.
    /// Conclude key is the key that can authorize a conclude order command closing the order and withdrawing
    /// all the remaining funds from it.
    #[method(name = "create_order")]
    async fn create_order(
        &self,
        account: AccountArg,
        ask: RpcOutputValueIn,
        give: RpcOutputValueIn,
        conclude_address: RpcAddress<Destination>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewOrder>;

    /// Conclude an order, given its id. This assumes that the conclude key is owned
    /// by the selected account in this wallet.
    /// Optionally output address can be provided where remaining funds from the order are transferred.
    #[method(name = "conclude_order")]
    async fn conclude_order(
        &self,
        account: AccountArg,
        order_id: RpcAddress<OrderId>,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Fill order completely or partially given its id and an amount that satisfy what an order can offer.
    /// Optionally output address can be provided where the exchanged funds from the order are transferred.
    #[method(name = "fill_order")]
    async fn fill_order(
        &self,
        account: AccountArg,
        order_id: RpcAddress<OrderId>,
        fill_amount_in_ask_currency: RpcAmountIn,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Freeze an order given its id. This prevents an order from being filled.
    /// Only a conclude operation is allowed afterwards.
    #[method(name = "freeze_order")]
    async fn freeze_order(
        &self,
        account: AccountArg,
        order_id: RpcAddress<OrderId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction>;

    /// Node version
    #[method(name = "node_version")]
    async fn node_version(&self) -> rpc::RpcResult<NodeVersion>;

    /// Node shutdown
    #[method(name = "node_shutdown")]
    async fn node_shutdown(&self) -> rpc::RpcResult<()>;

    /// Enable or disable p2p networking in the node
    #[method(name = "node_enable_networking")]
    async fn node_enable_networking(&self, enable: bool) -> rpc::RpcResult<()>;

    /// Connect to a remote peer in the node
    #[method(name = "node_connect_to_peer")]
    async fn connect_to_peer(&self, address: String) -> rpc::RpcResult<()>;

    /// Disconnected a remote peer in the node
    #[method(name = "node_disconnect_peer")]
    async fn disconnect_peer(&self, peer_id: u64) -> rpc::RpcResult<()>;

    /// List banned addresses/peers in the node
    #[method(name = "node_list_banned_peers")]
    async fn list_banned(
        &self,
    ) -> rpc::RpcResult<Vec<(BannableAddress, common::primitives::time::Time)>>;

    /// Ban an address in the node for the specified duration
    #[method(name = "node_ban_peer_address")]
    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> rpc::RpcResult<()>;

    /// Unban address in the node
    #[method(name = "node_unban_peer_address")]
    async fn unban_address(&self, address: BannableAddress) -> rpc::RpcResult<()>;

    /// List discouraged addresses/peers in the node
    #[method(name = "node_list_discouraged_peers")]
    async fn list_discouraged(
        &self,
    ) -> rpc::RpcResult<Vec<(BannableAddress, common::primitives::time::Time)>>;

    /// Undiscourage address in the node
    #[method(name = "node_undiscourage_peer_address")]
    async fn undiscourage_address(&self, address: BannableAddress) -> rpc::RpcResult<()>;

    /// Get the number of connected peer in the node
    #[method(name = "node_peer_count")]
    async fn peer_count(&self) -> rpc::RpcResult<usize>;

    /// Get connected peers in the node
    #[method(name = "node_list_connected_peers")]
    async fn connected_peers(&self) -> rpc::RpcResult<Vec<ConnectedPeer>>;

    /// Get reserved peers in the node
    #[method(name = "node_list_reserved_peers")]
    async fn reserved_peers(&self) -> rpc::RpcResult<Vec<SocketAddress>>;

    /// Add a reserved peer in the node
    #[method(name = "node_add_reserved_peer")]
    async fn add_reserved_peer(&self, address: String) -> rpc::RpcResult<()>;

    /// Remove a reserved peer from the node
    #[method(name = "node_remove_reserved_peer")]
    async fn remove_reserved_peer(&self, address: String) -> rpc::RpcResult<()>;

    /// Submit a block to be included in the chain
    #[method(name = "node_submit_block")]
    async fn submit_block(&self, block: HexEncoded<Block>) -> rpc::RpcResult<()>;

    /// Returns the current node's chainstate (block height information and more)
    #[method(name = "node_chainstate_info")]
    async fn chainstate_info(&self) -> rpc::RpcResult<ChainInfo>;

    /// Abandon an unconfirmed transaction in the wallet database, and make the consumed inputs available to be used again
    /// Note that this doesn't necessarily mean that the network will agree. This assumes the transaction is either still
    /// not confirmed in the network or somehow invalid.
    #[method(name = "transaction_abandon")]
    async fn abandon_transaction(
        &self,
        account: AccountArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<()>;

    /// List the pending transactions that can be abandoned
    #[method(name = "transaction_list_pending")]
    async fn list_pending_transactions(
        &self,
        account: AccountArg,
    ) -> rpc::RpcResult<Vec<Id<Transaction>>>;

    /// List mainchain transactions with optional address filter
    #[method(name = "transaction_list_by_address")]
    async fn list_transactions_by_address(
        &self,
        account: AccountArg,
        address: Option<RpcAddress<Destination>>,
        limit: usize,
    ) -> rpc::RpcResult<Vec<TxInfo>>;

    /// Get a transaction from the wallet, if present
    #[method(name = "transaction_get")]
    async fn get_transaction(
        &self,
        account: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<serde_json::Value>;

    /// Get a transaction from the wallet, if present, as hex encoded raw transaction
    #[method(name = "transaction_get_raw")]
    async fn get_raw_transaction(
        &self,
        account: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<HexEncoded<Transaction>>;

    /// Get a signed transaction from the wallet, if present, as hex encoded raw transaction
    #[method(name = "transaction_get_signed_raw")]
    async fn get_raw_signed_transaction(
        &self,
        account: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<HexEncoded<SignedTransaction>>;

    /// Compose a new transaction from the specified outputs and selected utxos
    /// The transaction is returned in a hex encoded form that can be passed to account-sign-raw-transaction
    /// and also prints the fees that will be paid by the transaction
    #[method(name = "transaction_compose")]
    async fn compose_transaction(
        &self,
        inputs: Vec<RpcUtxoOutpoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<RpcHexString>>>,
        only_transaction: bool,
    ) -> rpc::RpcResult<ComposedTransaction>;

    /// Returns the current best block hash
    #[method(name = "node_best_block_id")]
    async fn node_best_block_id(&self) -> rpc::RpcResult<Id<GenBlock>>;

    /// Returns the current best block height
    #[method(name = "node_best_block_height")]
    async fn node_best_block_height(&self) -> rpc::RpcResult<BlockHeight>;

    /// Get the block ID of the block at a given height
    #[method(name = "node_block_id")]
    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> rpc::RpcResult<Option<Id<GenBlock>>>;

    /// Generate a block with the given transactions to the specified
    /// reward destination. If transactions are None, the block will be
    /// generated with available transactions in the mempool
    #[method(name = "node_generate_block")]
    async fn node_generate_block(
        &self,
        account: AccountArg,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> rpc::RpcResult<()>;

    #[method(name = "node_generate_blocks")]
    async fn node_generate_blocks(
        &self,
        account: AccountArg,
        block_count: u32,
    ) -> rpc::RpcResult<()>;

    /// For each block height in the specified range, find timestamps where staking is/was possible
    /// for the given pool.
    ///
    /// `min_height` must not be zero; `max_height` must not exceed the best block height plus one.
    ///
    /// If `check_all_timestamps_between_blocks` is `false`, `seconds_to_check_for_height + 1` is the number
    /// of seconds that will be checked at each height in the range.
    /// If `check_all_timestamps_between_blocks` is `true`, `seconds_to_check_for_height` only applies to the
    /// last height in the range; for all other heights the maximum timestamp is the timestamp
    /// of the next block.
    #[method(name = "node_find_timestamps_for_staking")]
    async fn node_find_timestamps_for_staking(
        &self,
        pool_id: RpcAddress<PoolId>,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> rpc::RpcResult<BTreeMap<BlockHeight, Vec<BlockTimestamp>>>;

    /// Get a block by its hash, represented with hex encoded bytes
    #[method(name = "node_get_block")]
    async fn node_block(&self, block_id: Id<Block>) -> rpc::RpcResult<Option<HexEncoded<Block>>>;

    /// Returns mainchain block ids with heights in the range start_height..end_height using
    /// the given step.
    #[method(name = "node_get_block_ids_as_checkpoints")]
    async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> rpc::RpcResult<Vec<(BlockHeight, Id<GenBlock>)>>;
}
