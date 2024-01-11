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

mod helper_types;

use std::{fmt::Write, path::PathBuf, str::FromStr, sync::Arc};

use chainstate::TokenIssuanceError;
use clap::Parser;
use common::{
    address::Address,
    chain::{
        tokens::{Metadata, TokenCreator},
        Block, ChainConfig, SignedTransaction, Transaction, UtxoOutPoint,
    },
    primitives::{BlockHeight, Id, H256},
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use mempool::tx_accumulator::PackingStrategy;
use p2p_types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use utils::ensure;
use wallet::{version::get_version, wallet_events::WalletEventsNoOp, WalletError};
use wallet_controller::{
    read::ReadOnlyController, synced_controller::SyncedController, ControllerConfig,
    ControllerError, NodeInterface, NodeRpcClient, PeerId, DEFAULT_ACCOUNT_INDEX,
};

use crate::{
    commands::helper_types::{parse_address, parse_token_supply},
    errors::WalletCliError,
    CliController,
};

use self::helper_types::{
    format_delegation_info, format_pool_info, parse_coin_amount, parse_pool_id, parse_token_amount,
    parse_token_id, parse_utxo_outpoint, print_coin_amount, to_per_thousand, CliForceReduce,
    CliIsFreezable, CliIsUnfreezable, CliStoreSeedPhrase, CliUtxoState, CliUtxoTypes,
    CliWithLocked,
};

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum WalletCommand {
    /// Creates a new account with an optional name.
    /// Returns an error if the last created account does not have a transaction history.
    #[clap(name = "account-create")]
    CreateNewAccount { name: Option<String> },

    /// Switch to a given wallet account.
    #[clap(name = "account-select")]
    SelectAccount { account_index: U31 },

    /// Lists all the utxos owned by this account
    #[clap(name = "account-utxos")]
    ListUtxo {
        /// The type of utxo to be listed. Default is "all".
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        /// Whether to include locked outputs. Default is "unlocked"
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of the utxos; e.g., confirmed, unconfirmed, etc.
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    /// Get the total balance in the selected account in this wallet. See available options to include more categories, like locked coins.
    #[clap(name = "account-balance")]
    GetBalance {
        /// Whether to include locked outputs (outputs that cannot be spend and need time to mature)
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of utxos to be included (confirmed, unconfirmed, etc)
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    /// Issue a new non-fungible token (NFT) from scratch
    #[clap(name = "token-nft-issue-new")]
    IssueNewNft {
        /// The receiver of the token
        destination_address: String,
        /// The hash of the media, whose ownership is represented by the NFT
        media_hash: String,
        /// Name of the token
        name: String,
        /// Description of the token
        description: String,
        /// Ticker of the token
        ticker: String,
        /// The owner, represented by a public key (hex encoded)
        creator: Option<HexEncoded<PublicKey>>,
        /// URI for the icon of the NFT
        icon_uri: Option<String>,
        /// URI of the media
        media_uri: Option<String>,
        additional_metadata_uri: Option<String>,
    },

    /// Issue a new fungible token from scratch.
    /// Notice that issuing a token fills an issuers supply. To have tokens that are spendable,
    /// the issuer must "mint" tokens to take from the supply
    #[clap(name = "token-issue-new")]
    IssueNewToken {
        /// The ticker/symbol of the token created
        token_ticker: String,
        /// The maximum number of digits after the decimal points
        number_of_decimals: u8,
        /// URI for data related to the token (website, media, etc)
        metadata_uri: String,
        /// The address of the receiver of this token
        destination_address: String,
        /// The total supply of this token
        token_supply: String,
        /// Whether it's possible to centrally freeze this token for all users (due to migration requirements, for example)
        is_freezable: CliIsFreezable,
    },

    /// Change the authority of a token; i.e., the cryptographic authority that can do all authority token operations
    #[clap(name = "token-change-authority")]
    ChangeTokenAuthority { token_id: String, address: String },

    /// Given a token that is already issued, mint new tokens and increase the total supply
    #[clap(name = "token-mint")]
    MintTokens {
        /// The token id of the tokens to be minted
        token_id: String,
        /// The receiving address of the minted tokens
        address: String,
        /// The amount to be minted
        amount: String,
    },

    /// Unmint existing tokens and reduce the total supply
    /// Unminting reduces the total supply and puts the unminted tokens back at the issuer's control.
    /// The wallet must own the tokens that are being unminted.
    #[clap(name = "token-unmint")]
    UnmintTokens {
        /// The token id of the tokens to be unminted
        token_id: String,
        /// The amount to be unminted
        amount: String,
    },

    /// Lock the circulating supply for the token. THIS IS IRREVERSIBLE.
    /// Tokens that can be locked will lose the ability to mint/unmint them
    #[clap(name = "token-lock-supply")]
    LockTokenSupply {
        /// The token id of the token, whose supply will be locked
        token_id: String,
    },

    /// Freezing the token (by token authority) forbids any operation with all the tokens (except for the optional unfreeze).
    ///
    /// After a token is frozen, no transfers, spends, or any other operation can be done.
    /// This wallet (and selected account) must own the authority keys to be able to freeze.
    #[clap(name = "token-freeze")]
    FreezeToken {
        /// The token id of the token to be frozen.
        token_id: String,
        /// Whether these tokens can be unfrozen again, or permanently freeze them.
        is_unfreezable: CliIsUnfreezable,
    },

    /// By unfreezing the token all operations are available for the tokens again.
    ///
    /// Notice that this is only possible if the tokens were made to be unfreezable during freezing.
    /// This wallet (and selected account) must own the authority keys to be able to unfreeze.
    #[clap(name = "token-unfreeze")]
    UnfreezeToken {
        /// The token id of the token to be unfrozen.
        token_id: String,
    },

    /// Send a given token amount to a given address. The wallet will automatically calculate the required information
    #[clap(name = "token-send")]
    SendTokensToAddress {
        /// The token id of the tokens to be sent
        token_id: String,
        /// The destination address receiving the tokens
        address: String,
        /// The amount of tokens to be sent
        amount: String,
    },

    /// Generate a new unused address
    #[clap(name = "address-new")]
    NewAddress,

    /// Generate a new unused public key
    #[clap(name = "address-new-public-key")]
    NewPublicKey,

    /// Show receive-addresses with their usage state.
    /// Note that whether an address is used isn't based on the wallet,
    /// but on the blockchain. So if an address is used in a transaction,
    /// it will be marked as used only when the transaction is included
    /// in a block.
    #[clap(name = "address-show")]
    ShowReceiveAddresses,

    /// Send a given coin amount to a given address. The wallet will automatically calculate the required information
    /// Optionally, one can also mention the utxos to be used.
    #[clap(name = "address-send")]
    SendToAddress {
        /// The receiving address of the coins
        address: String,
        /// The amount to be sent, in decimal format
        amount: String,
        /// You can choose what utxos to spend (space separated as additional arguments). A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        #[arg(default_values_t = Vec::<String>::new())]
        utxos: Vec<String>,
    },

    /// Store data on the blockchain, the data is provided as hex encoded string.
    /// Note that there is a high fee for storing data on the blockchain.
    #[clap(name = "address-deposit-data")]
    DepositData {
        /// The data to be deposited on the blockchain as hex. DO NOT start the data with 0x.
        hex_data: String,
    },

    /// Create a delegation to a given pool id and the owner address/destination.
    /// The owner of a delegation is the key authorized to withdraw from the delegation.
    /// The delegation creation will result in creating a delegation id, where coins sent to that id will be staked by the pool id provided, automatically.
    /// The pool, to which the delegation is made, doesn't have the authority to spend the coins.
    #[clap(name = "delegation-create")]
    CreateDelegation {
        /// The address, that will have the authority to sign withdrawals from a pool.
        owner: String,
        /// The pool id of the pool that will get the delegation and stake the coins.
        pool_id: String,
    },

    /// List delegation ids controlled by the selected account in this wallet with their balances
    #[clap(name = "delegation-list-ids")]
    ListDelegationIds,

    /// Send coins to a delegation id to be staked
    #[clap(name = "delegation-stake")]
    DelegateStaking {
        /// The amount to be delegated for staking
        amount: String,
        /// The delegation id that was created. Every pool you want to delegate to must have a delegation id.
        delegation_id: String,
    },

    /// Send coins from a delegation id (that you own) to stop staking them.
    /// Note that stopping the delegation requires a lock period.
    #[clap(name = "delegation-send-to-address")]
    SendFromDelegationToAddress {
        /// The address that will be receiving the coins
        address: String,
        /// The amount that will be taken away from the delegation
        amount: String,
        /// The delegation id, from which the delegated coins will be taken
        delegation_id: String,
    },

    /// List ids of pools that are controlled by the selected account in this wallet
    #[clap(name = "staking-list-pool-ids")]
    ListPoolIds,

    /// Start staking, assuming there are staking pools in the selected account in this wallet.
    #[clap(name = "staking-start")]
    StartStaking,

    /// Stop staking, assuming there are staking pools staking currently in the selected account in this wallet.
    #[clap(name = "staking-stop")]
    StopStaking,

    /// Print the balance of available staking pools
    #[clap(name = "staking-pool-balance")]
    StakePoolBalance { pool_id: String },

    /// List the blocks created by the selected account in this wallet through staking/mining/etc
    #[clap(name = "staking-list-created-block-ids")]
    ListCreatedBlocksIds,

    /// Get the current staking VRF key for this account
    #[clap(name = "staking-get-vrf-key")]
    GetVrfPublicKey,

    /// Create a staking pool. The pool will be capable of creating blocks and gaining rewards,
    /// and will be capable of taking delegations from other users and staking.
    /// The decommission key is the key that can decommission the pool.
    /// Cost per block, and margin ratio are parameters that control how delegators receive rewards.
    /// The cost per block is an amount in coins to be subtracted from the total rewards in a block,
    /// and handed to the staking pool. After subtracting the cost per block, a fraction equal to
    /// margin ratio is taken from what is left, and given to the staking pool. Finally, what is left
    /// is distributed among stakers, pro-rata, based on their delegation amounts.
    #[clap(name = "staking-create-pool")]
    CreateStakePool {
        /// The amount to be pledged to the pool. There is a minimum to be accepted.
        /// This amount, and the rewards gained by the pool, CANNOT be taken out without decommissioning the pool.
        /// If you'd like to withdraw rewards, consider creating a pool and delegating to yourself.
        /// Delegators have no restrictions on withdrawals.
        amount: String,

        /// An amount in coins to be subtracted from the total rewards in a block and handed to the pool.
        cost_per_block: String,

        /// After subtracting "cost per block" from the reward, this ratio is taken from the rewards and is handed to the pool.
        /// What is left is distributed among delegators, pro-rata, based on their delegation amounts.
        margin_ratio_per_thousand: String,

        /// The key that can decommission the pool. It's recommended to keep the decommission key in a cold storage.
        /// If not provided, the selected account in this wallet will control both decommission and staking.
        /// This is NOT RECOMMENDED.
        decommission_key: Option<HexEncoded<PublicKey>>,
    },

    /// Decommission a staking pool, given its id. This assumes that the decommission key is owned
    /// by the selected account in this wallet.
    #[clap(name = "staking-decommission-pool")]
    DecommissionStakePool {
        /// The pool id of the pool to be decommissioned.
        /// Notice that this only works if the selected account in this wallet owns the decommission key.
        pool_id: String,
    },

    /// Create new wallet
    #[clap(name = "wallet-create")]
    CreateWallet {
        /// File path of the wallet file
        wallet_path: PathBuf,

        /// If 'store-seed-phrase', the seed-phrase will be stored in the wallet file.
        /// If 'do-not-store-seed-phrase', the seed-phrase will only be printed on the screen.
        /// Not storing the seed-phrase can be seen as a security measure
        /// to ensure sufficient secrecy in case that seed-phrase is reused
        /// elsewhere if this wallet is compromised.
        whether_to_store_seed_phrase: CliStoreSeedPhrase,

        /// Mnemonic phrase (12, 15, or 24 words as a single quoted argument). If not specified, a new mnemonic phrase is generated and printed.
        mnemonic: Option<String>,
    },

    /// Open an exiting wallet by specifying the file location of the wallet file
    #[clap(name = "wallet-open")]
    OpenWallet {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,
    },

    /// Close the currently open wallet file
    #[clap(name = "wallet-close")]
    CloseWallet,

    /// Rescan the blockchain and re-detect all operations related to the selected account in this wallet
    #[clap(name = "wallet-rescan")]
    Rescan,

    /// Force the wallet to scan the remaining blocks from node until the tip is reached
    #[clap(name = "wallet-sync")]
    SyncWallet,

    /// Show the seed phrase for the loaded wallet if it has been stored.
    #[clap(name = "wallet-show-seed-phrase")]
    ShowSeedPhrase,

    /// Delete the seed phrase from the loaded wallet's database, if it has been stored.
    #[clap(name = "wallet-purge-seed-phrase")]
    PurgeSeedPhrase,

    /// Set the lookahead size for key generation.
    ///
    /// Lookahead size (or called gap) is the number of addresses to generate and the blockchain for incoming transactions to them
    /// after the last address that was seen to contain a transaction on the blockchain.
    /// Do not attempt to reduce the size of this value unless you're sure there are no incoming transactions in these addresses.
    #[clap(name = "wallet-set-lookahead-size")]
    SetLookaheadSize {
        /// The new lookahead size
        lookahead_size: u32,

        /// Forces the reduction of lookahead size even below the known last used address
        /// the new wallet can lose track of known addresses and balance
        i_know_what_i_am_doing: Option<CliForceReduce>,
    },

    /// Encrypts the private keys with a new password, expects the wallet to be unlocked
    #[clap(name = "wallet-encrypt-private-keys")]
    EncryptPrivateKeys {
        /// The new encryption password
        password: String,
    },

    /// Completely and totally remove any existing encryption, expects the wallet to be unlocked.
    /// WARNING: After this, your wallet file will be USABLE BY ANYONE without a password.
    #[clap(name = "wallet-disable-private-keys-encryption")]
    RemovePrivateKeysEncryption,

    /// Unlocks the private keys for usage.
    #[clap(name = "wallet-unlock-private-keys")]
    UnlockPrivateKeys {
        /// The current encryption password.
        password: String,
    },

    /// Locks the private keys so they can't be used until they are unlocked again
    #[clap(name = "wallet-lock-private-keys")]
    LockPrivateKeys,

    /// Node version
    #[clap(name = "node-version")]
    NodeVersion,

    /// Node shutdown
    #[clap(name = "node-shutdown")]
    NodeShutdown,

    /// Connect to a remote peer in the node
    #[clap(name = "node-connect-to-peer")]
    Connect { address: IpOrSocketAddress },

    /// Disconnected a remote peer in the node
    #[clap(name = "node-disconnect-peer")]
    Disconnect { peer_id: PeerId },

    /// List banned addresses/peers in the node
    #[clap(name = "node-list-banned-peers")]
    ListBanned,

    /// Ban address in the node
    #[clap(name = "node-ban-peer-address")]
    Ban { address: BannableAddress },

    /// Unban address in the node
    #[clap(name = "node-unban-peer-address")]
    Unban { address: BannableAddress },

    /// Get the number of connected peer in the node
    #[clap(name = "node-peer-count")]
    PeerCount,

    /// Get connected peers in the node
    #[clap(name = "node-list-connected-peers")]
    ConnectedPeers,

    /// Get connected peers in JSON format
    #[clap(name = "node-list-connected-peers-json")]
    ConnectedPeersJson,

    /// Add a reserved peer in the node
    #[clap(name = "node-add-reserved-peer")]
    AddReservedPeer { address: IpOrSocketAddress },

    /// Remove a reserved peer from the node
    #[clap(name = "node-remove-reserved-peer")]
    RemoveReservedPeer { address: IpOrSocketAddress },

    /// Submit a block to be included in the chain
    #[clap(name = "node-submit-block")]
    SubmitBlock {
        /// Hex encoded block
        block: HexEncoded<Block>,
    },

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network
    #[clap(name = "node-submit-transaction")]
    SubmitTransaction {
        /// Hex encoded transaction.
        transaction: HexEncoded<SignedTransaction>,
    },

    /// Returns the current node's chainstate (block height information and more)
    #[clap(name = "node-chainstate-info")]
    ChainstateInfo,

    /// Returns the current best block hash
    #[clap(name = "node-best-block")]
    BestBlock,

    /// Returns the current best block height
    #[clap(name = "node-best-block-height")]
    BestBlockHeight,

    /// Get the block ID of the block at a given height
    #[clap(name = "node-block-id")]
    BlockId {
        /// Block height
        height: BlockHeight,
    },

    /// Get a block by its hash, represented with hex encoded bytes
    #[clap(name = "node-get-block")]
    GetBlock {
        /// Block hash
        hash: String,
    },

    /// Generate a block with the given transactions to the specified
    /// reward destination. If transactions are None, the block will be
    /// generated with available transactions in the mempool
    #[clap(name = "node-generate-block")]
    GenerateBlock {
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },

    #[clap(name = "node-generate-blocks")]
    #[clap(hide = true)]
    GenerateBlocks { block_count: u32 },

    /// Abandon an unconfirmed transaction in the wallet database, and make the consumed inputs available to be used again
    /// Note that this doesn't necessarily mean that the network will agree. This assumes the transaction is either still
    /// not confirmed in the network or somehow invalid.
    #[clap(name = "transaction-abandon")]
    AbandonTransaction {
        /// The id of the transaction that will be abandoned, in hex.
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// List the pending transactions that can be abandoned
    #[clap(name = "transaction-list-pending")]
    ListPendingTransactions,

    /// Get a transaction from the wallet, if present
    #[clap(name = "transaction-get")]
    GetTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get a transaction from the wallet, if present, as hex encoded raw transaction
    #[clap(name = "transaction-get-raw")]
    GetRawTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get a signed transaction from the wallet, if present, as hex encoded raw transaction
    #[clap(name = "transaction-get-signed-raw")]
    GetRawSignedTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Print command history in the wallet for this execution
    #[clap(name = "history-print")]
    PrintHistory,

    /// Clear command history for this execution
    #[clap(name = "history-clear")]
    ClearHistory,

    /// Clear screen
    #[clap(name = "screen-clear")]
    ClearScreen,

    /// Print the version of the wallet software and possibly the git commit hash, if found
    Version,

    /// Exit the wallet
    Exit,
}

#[derive(Debug)]
pub enum ConsoleCommand {
    Print(String),
    ClearScreen,
    PrintHistory,
    ClearHistory,
    SetStatus {
        status: String,
        print_message: String,
    },
    Exit,
}

struct CliWalletState {
    selected_account: U31,
}

pub struct CommandHandler {
    // the CliController if there is a loaded wallet
    state: Option<(CliController, CliWalletState)>,
    config: ControllerConfig,
}

impl CommandHandler {
    pub fn new(config: ControllerConfig) -> Self {
        CommandHandler {
            state: None,
            config,
        }
    }

    fn set_selected_account(&mut self, account_index: U31) -> Result<(), WalletCliError> {
        let (controller, CliWalletState { selected_account }) =
            self.state.as_mut().ok_or(WalletCliError::NoWallet)?;

        if account_index.into_u32() as usize >= controller.account_names().count() {
            return Err(WalletCliError::AccountNotFound(account_index));
        }

        *selected_account = account_index;
        Ok(())
    }

    fn repl_status(&mut self) -> String {
        match self.state.as_ref() {
            Some((controller, CliWalletState { selected_account })) => {
                let accounts: Vec<&Option<String>> = controller.account_names().collect();
                if accounts.len() > 1 {
                    match accounts.get(selected_account.into_u32() as usize) {
                        Some(Some(name)) => format!("(Account {})", name),
                        _ => format!("(Account No. {})", selected_account),
                    }
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    }

    pub fn controller_opt(&mut self) -> Option<&mut CliController> {
        self.state.as_mut().map(|(controller, _)| controller)
    }

    pub fn controller(&mut self) -> Result<&mut CliController, WalletCliError> {
        self.state
            .as_mut()
            .map(|(controller, _)| controller)
            .ok_or(WalletCliError::NoWallet)
    }

    fn get_controller_and_selected_acc(
        &mut self,
    ) -> Result<(&mut CliController, U31), WalletCliError> {
        self.state
            .as_mut()
            .map(|(controller, state)| (controller, state.selected_account))
            .ok_or(WalletCliError::NoWallet)
    }

    async fn get_synced_controller(
        &mut self,
    ) -> Result<SyncedController<'_, NodeRpcClient, WalletEventsNoOp>, WalletCliError> {
        let (controller, state) = self.state.as_mut().ok_or(WalletCliError::NoWallet)?;
        controller
            .synced_controller(state.selected_account, self.config)
            .await
            .map_err(WalletCliError::Controller)
    }

    fn get_readonly_controller(
        &mut self,
    ) -> Result<ReadOnlyController<'_, NodeRpcClient>, WalletCliError> {
        let (controller, state) = self.state.as_mut().ok_or(WalletCliError::NoWallet)?;
        Ok(controller.readonly_controller(state.selected_account))
    }

    pub fn tx_submitted_command() -> ConsoleCommand {
        let status_text = "The transaction was submitted successfully";
        ConsoleCommand::Print(status_text.to_owned())
    }

    pub async fn broadcast_transaction(
        rpc_client: &NodeRpcClient,
        tx: SignedTransaction,
    ) -> Result<ConsoleCommand, WalletCliError> {
        rpc_client
            .submit_transaction(tx, Default::default())
            .await
            .map_err(WalletCliError::RpcError)?;
        Ok(Self::tx_submitted_command())
    }

    pub async fn handle_wallet_command(
        &mut self,
        chain_config: &Arc<ChainConfig>,
        rpc_client: &NodeRpcClient,
        command: WalletCommand,
    ) -> Result<ConsoleCommand, WalletCliError> {
        match command {
            WalletCommand::CreateWallet {
                wallet_path,
                mnemonic,
                whether_to_store_seed_phrase,
            } => {
                utils::ensure!(self.state.is_none(), WalletCliError::WalletFileAlreadyOpen);

                // TODO: Support other languages
                let language = wallet::wallet::Language::English;
                let newly_generated_mnemonic = mnemonic.is_none();
                let mnemonic = match &mnemonic {
                    Some(mnemonic) => {
                        wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
                            .map_err(WalletCliError::InvalidMnemonic)?
                    }
                    None => wallet_controller::mnemonic::generate_new_mnemonic(language),
                };

                let wallet = if newly_generated_mnemonic {
                    let info =
                        rpc_client.chainstate_info().await.map_err(WalletCliError::RpcError)?;
                    CliController::create_wallet(
                        Arc::clone(chain_config),
                        wallet_path,
                        mnemonic.clone(),
                        None,
                        whether_to_store_seed_phrase.to_walet_type(),
                        info.best_block_height,
                        info.best_block_id,
                    )
                } else {
                    CliController::recover_wallet(
                        Arc::clone(chain_config),
                        wallet_path,
                        mnemonic.clone(),
                        None,
                        whether_to_store_seed_phrase.to_walet_type(),
                    )
                }
                .map_err(WalletCliError::Controller)?;

                self.state = Some((
                    CliController::new(
                        Arc::clone(chain_config),
                        rpc_client.clone(),
                        wallet,
                        WalletEventsNoOp,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?,
                    CliWalletState {
                        selected_account: DEFAULT_ACCOUNT_INDEX,
                    },
                ));

                let msg = if newly_generated_mnemonic {
                    format!(
                    "New wallet created successfully\nYour mnemonic: {}\nPlease write it somewhere safe to be able to restore your wallet."
                , mnemonic)
                } else {
                    "New wallet created successfully".to_owned()
                };
                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: msg,
                })
            }

            WalletCommand::OpenWallet {
                wallet_path,
                encryption_password,
            } => {
                utils::ensure!(self.state.is_none(), WalletCliError::WalletFileAlreadyOpen);

                let password = encryption_password;

                let wallet =
                    CliController::open_wallet(Arc::clone(chain_config), wallet_path, password)
                        .map_err(WalletCliError::Controller)?;

                self.state = Some((
                    CliController::new(
                        Arc::clone(chain_config),
                        rpc_client.clone(),
                        wallet,
                        WalletEventsNoOp,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?,
                    CliWalletState {
                        selected_account: DEFAULT_ACCOUNT_INDEX,
                    },
                ));

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: "Wallet loaded successfully".to_owned(),
                })
            }

            WalletCommand::CloseWallet => {
                utils::ensure!(self.state.is_some(), WalletCliError::NoWallet);

                self.state = None;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: "Successfully closed the wallet.".to_owned(),
                })
            }

            WalletCommand::EncryptPrivateKeys { password } => {
                self.controller()?
                    .encrypt_wallet(&Some(password))
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(
                    "Successfully encrypted the private keys of the wallet.".to_owned(),
                ))
            }

            WalletCommand::RemovePrivateKeysEncryption => {
                self.controller()?.encrypt_wallet(&None).map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(
                    "Successfully removed the encryption from the private keys.".to_owned(),
                ))
            }

            WalletCommand::UnlockPrivateKeys { password } => {
                self.controller()?
                    .unlock_wallet(&password)
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now unlocked.".to_owned(),
                ))
            }

            WalletCommand::LockPrivateKeys => {
                self.controller()?.lock_wallet().map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now locked.".to_owned(),
                ))
            }

            WalletCommand::SetLookaheadSize {
                lookahead_size,
                i_know_what_i_am_doing,
            } => {
                let force_reduce = match i_know_what_i_am_doing {
                    Some(CliForceReduce::IKnowWhatIAmDoing) => true,
                    None => false,
                };

                self.controller()?
                    .set_lookahead_size(lookahead_size, force_reduce)
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(
                    "Success. Lookahead size has been updated, will rescan the blockchain."
                        .to_owned(),
                ))
            }

            WalletCommand::ChainstateInfo => {
                let info = rpc_client.chainstate_info().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(format!("{info:#?}")))
            }

            WalletCommand::BestBlock => {
                let id = rpc_client.get_best_block_id().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(id.hex_encode()))
            }

            WalletCommand::BestBlockHeight => {
                let height =
                    rpc_client.get_best_block_height().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(height.to_string()))
            }

            WalletCommand::BlockId { height } => {
                let hash = rpc_client
                    .get_block_id_at_height(height)
                    .await
                    .map_err(WalletCliError::RpcError)?;
                match hash {
                    Some(id) => Ok(ConsoleCommand::Print(id.hex_encode())),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GetBlock { hash } => {
                let hash = H256::from_str(&hash)
                    .map_err(|e| WalletCliError::InvalidInput(e.to_string()))?;
                let hash =
                    rpc_client.get_block(hash.into()).await.map_err(WalletCliError::RpcError)?;
                match hash {
                    Some(block) => Ok(ConsoleCommand::Print(block.hex_encode())),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GenerateBlock { transactions } => {
                let transactions = transactions.into_iter().map(HexEncoded::take).collect();
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let block = controller
                    .generate_block(
                        selected_account,
                        transactions,
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                rpc_client.submit_block(block).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GenerateBlocks { block_count } => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .generate_blocks(selected_account, block_count)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::CreateNewAccount { name } => {
                let (new_account_index, _name) =
                    self.controller()?.create_account(name).map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: format!(
                        "Success, the new account index is: {}",
                        new_account_index
                    ),
                })
            }

            WalletCommand::SelectAccount { account_index } => {
                self.set_selected_account(account_index).map(|_| ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: "Success".into(),
                })
            }

            WalletCommand::StartStaking => {
                self.get_synced_controller()
                    .await?
                    .start_staking()
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "Staking started successfully".to_owned(),
                ))
            }

            WalletCommand::StopStaking => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller.stop_staking(selected_account).map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::StakePoolBalance { pool_id } => {
                let pool_id = parse_pool_id(chain_config, pool_id.as_str())?;
                let balance_opt = rpc_client
                    .get_stake_pool_balance(pool_id)
                    .await
                    .map_err(WalletCliError::RpcError)?;
                match balance_opt {
                    Some(balance) => Ok(ConsoleCommand::Print(print_coin_amount(
                        chain_config,
                        balance,
                    ))),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::SubmitBlock { block } => {
                rpc_client.submit_block(block.take()).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(
                    "The block was submitted successfully".to_owned(),
                ))
            }

            WalletCommand::SubmitTransaction { transaction } => {
                Self::broadcast_transaction(rpc_client, transaction.take()).await
            }

            WalletCommand::AbandonTransaction { transaction_id } => {
                self.get_synced_controller()
                    .await?
                    .abandon_transaction(transaction_id.take())
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "The transaction was marked as abandoned successfully".to_owned(),
                ))
            }

            WalletCommand::IssueNewToken {
                token_ticker,
                number_of_decimals,
                metadata_uri,
                destination_address,
                token_supply,
                is_freezable,
            } => {
                ensure!(
                    number_of_decimals <= chain_config.token_max_dec_count(),
                    WalletCliError::Controller(ControllerError::WalletError(
                        WalletError::TokenIssuance(TokenIssuanceError::IssueErrorTooManyDecimals),
                    ))
                );

                let destination_address = parse_address(chain_config, &destination_address)?;
                let token_supply = parse_token_supply(&token_supply, number_of_decimals)?;

                let token_id = self
                    .get_synced_controller()
                    .await?
                    .issue_new_token(
                        destination_address,
                        token_ticker.into_bytes(),
                        number_of_decimals,
                        metadata_uri.into_bytes(),
                        token_supply,
                        is_freezable.to_wallet_types(),
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!(
                    "A new token has been issued with ID: {}",
                    Address::new(chain_config, &token_id)
                        .expect("Encoding token id should never fail"),
                )))
            }

            WalletCommand::IssueNewNft {
                destination_address,
                media_hash,
                name,
                description,
                ticker,
                creator,
                icon_uri,
                media_uri,
                additional_metadata_uri,
            } => {
                let destination_address = parse_address(chain_config, &destination_address)?;

                let metadata = Metadata {
                    creator: creator.map(|pk| TokenCreator {
                        public_key: pk.take(),
                    }),
                    name: name.into_bytes(),
                    description: description.into_bytes(),
                    ticker: ticker.into_bytes(),
                    icon_uri: icon_uri.map(|x| x.into_bytes()).into(),
                    additional_metadata_uri: additional_metadata_uri.map(|x| x.into_bytes()).into(),
                    media_uri: media_uri.map(|x| x.into_bytes()).into(),
                    media_hash: media_hash.into_bytes(),
                };

                let token_id = self
                    .get_synced_controller()
                    .await?
                    .issue_new_nft(destination_address, metadata)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!(
                    "A new NFT has been issued with ID: {}",
                    Address::new(chain_config, &token_id)
                        .expect("Encoding token id should never fail"),
                )))
            }

            WalletCommand::MintTokens {
                token_id,
                address,
                amount,
            } => {
                // TODO: maybe extract token_id and token_info in a helper function
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let address = parse_address(chain_config, &address)?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                let amount = parse_token_amount(token_info.token_number_of_decimals(), &amount)?;

                self.get_synced_controller()
                    .await?
                    .mint_tokens(token_info, amount, address)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::UnmintTokens { token_id, amount } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                let amount = parse_token_amount(token_info.token_number_of_decimals(), &amount)?;

                self.get_synced_controller()
                    .await?
                    .unmint_tokens(token_info, amount)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::LockTokenSupply { token_id } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                self.get_synced_controller()
                    .await?
                    .lock_token_supply(token_info)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::FreezeToken {
                token_id,
                is_unfreezable,
            } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                self.get_synced_controller()
                    .await?
                    .freeze_token(token_info, is_unfreezable.to_wallet_types())
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::UnfreezeToken { token_id } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                self.get_synced_controller()
                    .await?
                    .unfreeze_token(token_info)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::ChangeTokenAuthority { token_id, address } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let address = parse_address(chain_config, &address)?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                self.get_synced_controller()
                    .await?
                    .change_token_authority(token_info, address)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::Rescan => {
                let controller = self.controller()?;
                controller.reset_wallet_to_genesis().map_err(WalletCliError::Controller)?;
                controller.sync_once().await.map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "Successfully rescanned the blockchain".to_owned(),
                ))
            }

            WalletCommand::SyncWallet => {
                self.controller()?.sync_once().await.map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GetBalance {
                utxo_states,
                with_locked,
            } => {
                let (coins, tokens) = self
                    .get_readonly_controller()?
                    .get_decimal_balance(
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await
                    .map_err(WalletCliError::Controller)?
                    .into_coins_and_tokens();

                let mut output = format!("Coins amount: {coins}\n");

                for (token_id, amount) in tokens {
                    let token_id = Address::new(chain_config, &token_id)
                        .expect("Encoding token id should never fail");
                    writeln!(&mut output, "Token: {token_id} amount: {amount}")
                        .expect("Writing to a memory buffer should not fail");
                }
                output.pop();

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::ListUtxo {
                utxo_type,
                utxo_states,
                with_locked,
            } => {
                let utxos = self
                    .get_readonly_controller()?
                    .get_utxos(
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::ListPendingTransactions => {
                let utxos = self
                    .get_readonly_controller()?
                    .pending_transactions()
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::NewAddress => {
                let address = self
                    .get_synced_controller()
                    .await?
                    .new_address()
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(address.1.get().to_owned()))
            }

            WalletCommand::NewPublicKey => {
                let public_key = self
                    .get_synced_controller()
                    .await?
                    .new_public_key()
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(public_key.hex_encode()))
            }

            WalletCommand::GetVrfPublicKey => {
                let vrf_public_key = self
                    .get_synced_controller()
                    .await?
                    .get_vrf_public_key()
                    .map_err(WalletCliError::Controller)?;
                let vrf_public_key =
                    Address::new(chain_config, &vrf_public_key).expect("should not fail");
                Ok(ConsoleCommand::Print(vrf_public_key.get().to_string()))
            }

            WalletCommand::GetTransaction { transaction_id } => {
                let tx = self
                    .get_readonly_controller()?
                    .get_transaction(transaction_id.take())
                    .map(|tx| format!("{:?}", tx))
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawTransaction { transaction_id } => {
                let tx = self
                    .get_readonly_controller()?
                    .get_transaction(transaction_id.take())
                    .map(|tx| HexEncode::hex_encode(tx.get_transaction()))
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawSignedTransaction { transaction_id } => {
                let tx = self
                    .get_readonly_controller()?
                    .get_transaction(transaction_id.take())
                    .map(|tx| HexEncode::hex_encode(tx.get_signed_transaction()))
                    .map_err(WalletCliError::Controller)?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::SendToAddress {
                address,
                amount,
                utxos,
            } => {
                let input_utxos: Vec<UtxoOutPoint> = utxos
                    .into_iter()
                    .map(parse_utxo_outpoint)
                    .collect::<Result<Vec<_>, WalletCliError>>()?;
                let amount = parse_coin_amount(chain_config, &amount)?;
                let address = parse_address(chain_config, &address)?;
                self.get_synced_controller()
                    .await?
                    .send_to_address(address, amount, input_utxos)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::SendTokensToAddress {
                token_id,
                address,
                amount,
            } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let address = parse_address(chain_config, &address)?;
                let token_info = self
                    .controller()?
                    .get_token_info(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                let amount = parse_token_amount(token_info.token_number_of_decimals(), &amount)?;

                self.get_synced_controller()
                    .await?
                    .send_tokens_to_address(token_info, address, amount)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::CreateDelegation { owner, pool_id } => {
                let address = parse_address(chain_config, &owner)?;
                let pool_id_address = Address::from_str(chain_config, &pool_id)?;

                let delegation_id = self
                    .get_synced_controller()
                    .await?
                    .create_delegation(address, pool_id_address.decode_object(chain_config)?)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!(
                    "Success, the creation of delegation transaction was broadcast to the network. Delegation id: {}",
                    Address::new(chain_config, &delegation_id)?
                )))
            }

            WalletCommand::DelegateStaking {
                amount,
                delegation_id,
            } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let delegation_id_address = Address::from_str(chain_config, &delegation_id)?;

                self.get_synced_controller()
                    .await?
                    .delegate_staking(amount, delegation_id_address.decode_object(chain_config)?)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "Success, the delegation staking transaction was broadcast to the network"
                        .to_owned(),
                ))
            }

            WalletCommand::SendFromDelegationToAddress {
                address,
                amount,
                delegation_id,
            } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let delegation_id_address = Address::from_str(chain_config, &delegation_id)?;
                let address = parse_address(chain_config, &address)?;
                self.get_synced_controller()
                    .await?
                    .send_to_address_from_delegation(
                        address,
                        amount,
                        delegation_id_address.decode_object(chain_config)?,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "Success. The transaction was broadcast to the network".to_owned(),
                ))
            }

            WalletCommand::CreateStakePool {
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_key,
            } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let decommission_key = decommission_key.map(HexEncoded::take);
                let cost_per_block = parse_coin_amount(chain_config, &cost_per_block)?;
                let margin_ratio_per_thousand =
                    to_per_thousand(&margin_ratio_per_thousand, "margin ratio")?;
                self.get_synced_controller()
                    .await?
                    .create_stake_pool_tx(
                        amount,
                        decommission_key,
                        margin_ratio_per_thousand,
                        cost_per_block,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::DecommissionStakePool { pool_id } => {
                let pool_id = parse_pool_id(chain_config, pool_id.as_str())?;
                self.get_synced_controller()
                    .await?
                    .decommission_stake_pool(pool_id)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::DepositData { hex_data } => {
                let data = hex::decode(hex_data).map_err(|e| {
                    WalletCliError::InvalidInput(format!("invalid hex data: {}", e))
                })?;
                self.get_synced_controller()
                    .await?
                    .deposit_data(data)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::ShowSeedPhrase => {
                let phrase =
                    self.controller()?.seed_phrase().map_err(WalletCliError::Controller)?;

                let msg = if let Some(phrase) = phrase {
                    format!("The stored seed phrase is \"{}\"", phrase.join(" "))
                } else {
                    "No stored seed phrase for this wallet. This was your choice when you created the wallet as a security option. Make sure not to lose this wallet file if you don't have the seed-phrase stored elsewhere when you created the wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            WalletCommand::PurgeSeedPhrase => {
                let phrase =
                    self.controller()?.delete_seed_phrase().map_err(WalletCliError::Controller)?;

                let msg = if let Some(phrase) = phrase {
                    format!("The seed phrase has been deleted, you can store it if you haven't do so yet: \"{}\"", phrase.join(" "))
                } else {
                    "No stored seed phrase for this wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            WalletCommand::NodeVersion => {
                let version = rpc_client.node_version().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(version))
            }

            WalletCommand::ListPoolIds => {
                let pool_ids: Vec<_> = self
                    .get_readonly_controller()?
                    .get_pool_ids()
                    .await
                    .map_err(WalletCliError::Controller)?
                    .into_iter()
                    .map(|(pool_id, block_info, balance)| {
                        format_pool_info(
                            pool_id,
                            balance,
                            block_info.height,
                            block_info.timestamp,
                            chain_config.as_ref(),
                        )
                    })
                    .collect();
                Ok(ConsoleCommand::Print(pool_ids.join("\n").to_string()))
            }

            WalletCommand::ListDelegationIds => {
                let delegations: Vec<_> = self
                    .get_readonly_controller()?
                    .get_delegations()
                    .await
                    .map_err(WalletCliError::Controller)?
                    .into_iter()
                    .map(|(delegation_id, balance)| {
                        format_delegation_info(delegation_id, balance, chain_config.as_ref())
                    })
                    .collect();
                Ok(ConsoleCommand::Print(delegations.join("\n").to_string()))
            }

            WalletCommand::ListCreatedBlocksIds => {
                let block_ids = self
                    .get_readonly_controller()?
                    .get_created_blocks()
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{block_ids:#?}")))
            }

            WalletCommand::NodeShutdown => {
                rpc_client.node_shutdown().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::Connect { address } => {
                rpc_client.p2p_connect(address).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Disconnect { peer_id } => {
                rpc_client.p2p_disconnect(peer_id).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::ListBanned => {
                let list = rpc_client.p2p_list_banned().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(format!("{list:#?}")))
            }
            WalletCommand::Ban { address } => {
                rpc_client.p2p_ban(address).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Unban { address } => {
                rpc_client.p2p_unban(address).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::PeerCount => {
                let peer_count =
                    rpc_client.p2p_get_peer_count().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(peer_count.to_string()))
            }
            WalletCommand::ConnectedPeers => {
                let peers =
                    rpc_client.p2p_get_connected_peers().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(format!("{peers:#?}")))
            }
            WalletCommand::ConnectedPeersJson => {
                let peers =
                    rpc_client.p2p_get_connected_peers().await.map_err(WalletCliError::RpcError)?;
                let peers_json = serde_json::to_string(&peers)?;
                Ok(ConsoleCommand::Print(peers_json))
            }
            WalletCommand::AddReservedPeer { address } => {
                rpc_client
                    .p2p_add_reserved_node(address)
                    .await
                    .map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::RemoveReservedPeer { address } => {
                rpc_client
                    .p2p_remove_reserved_node(address)
                    .await
                    .map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::ShowReceiveAddresses => {
                let controller = self.get_readonly_controller()?;

                let addresses_with_usage = controller.get_addresses_with_usage().map_err(|e| {
                    WalletCliError::AddressesRetrievalFailed(
                        controller.account_index(),
                        e.to_string(),
                    )
                })?;

                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row![
                        "Index",
                        "Address",
                        "Is used in transaction history",
                    ]);

                    addresses_table.extend(addresses_with_usage.into_iter().map(
                        |(index, (address, is_used))| {
                            let is_used = if is_used { "Yes" } else { "No" };
                            prettytable::row![index, address, is_used]
                        },
                    ));

                    addresses_table
                };

                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            WalletCommand::Version => Ok(ConsoleCommand::Print(get_version())),

            WalletCommand::Exit => Ok(ConsoleCommand::Exit),
            WalletCommand::PrintHistory => Ok(ConsoleCommand::PrintHistory),
            WalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            WalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }
}
