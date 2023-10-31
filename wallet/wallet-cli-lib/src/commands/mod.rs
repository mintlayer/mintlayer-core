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

use std::{path::PathBuf, str::FromStr, sync::Arc};

use chainstate::TokenIssuanceError;
use clap::Parser;
use common::{
    address::Address,
    chain::{
        tokens::{Metadata, TokenCreator},
        Block, ChainConfig, SignedTransaction, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, H256},
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use mempool::tx_accumulator::PackingStrategy;
use p2p_types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use utils::ensure;
use wallet::{
    account::Currency, version::get_version, wallet_events::WalletEventsNoOp, WalletError,
};
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
    parse_token_id, parse_utxo_outpoint, print_coin_amount, print_token_amount, to_per_thousand,
    CliIsFreezable, CliIsUnfreezable, CliStoreSeedPhrase, CliUtxoState, CliUtxoTypes,
    CliWithLocked,
};

#[derive(Debug, Parser)]
#[clap(rename_all = "lower")]
pub enum WalletCommand {
    /// Create new wallet
    CreateWallet {
        /// File path
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

    /// Open exiting wallet
    OpenWallet {
        /// File path
        wallet_path: PathBuf,
        // The existing password.
        password: Option<String>,
    },

    /// Close wallet file
    CloseWallet,

    /// Encrypts the private keys with a new password, expects the wallet to be unlocked
    EncryptPrivateKeys {
        // The new password
        password: String,
    },

    /// Remove any existing encryption, expects the wallet to be unlocked
    RemovePrivateKeysEncryption,

    // Unlocks the private keys for usage.
    UnlockPrivateKeys {
        // The existing password.
        password: String,
    },

    // Locks the private keys so they can't be used until they are unlocked again
    LockPrivateKeys,

    /// Returns the node chainstate
    ChainstateInfo,

    /// Show receive-addresses with their usage state.
    /// Note that whether an address is used isn't based on the wallet,
    /// but on the blockchain. So if an address is used in a transaction,
    /// it will be marked as used only when the transaction is included
    /// in a block.
    ShowReceiveAddresses,

    /// Returns the current best block hash
    BestBlock,

    /// Returns the current best block height
    BestBlockHeight,

    /// Get a block ID at height
    BlockId {
        /// Block height
        height: BlockHeight,
    },

    /// Get a block by its hash
    GetBlock {
        /// Block hash
        hash: String,
    },

    /// Generate a block with the given transactions to the specified
    /// reward destination. If transactions are None, the block will be
    /// generated with available transactions in the mempool
    GenerateBlock {
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },

    GenerateBlocks {
        block_count: u32,
    },

    /// Creates a new account
    /// returns an error if the last created account does not have a transaction history
    CreateNewAccount {
        name: Option<String>,
    },

    /// Select a wallet account for usage
    SelectAccount {
        account_index: U31,
    },

    /// Start staking
    StartStaking,

    StopStaking,

    StakePoolBalance {
        pool_id: String,
    },

    /// Submit a block to be included in the chain
    ///
    /// More information about block submits.
    /// More information about block submits.
    ///
    /// Even more information about block submits.
    /// Even more information about block submits.
    /// Even more information about block submits.
    /// Even more information about block submits.
    SubmitBlock {
        /// Hex encoded block
        block: HexEncoded<Block>,
    },

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network
    SubmitTransaction {
        /// Hex encoded transaction
        transaction: HexEncoded<SignedTransaction>,
    },

    /// Abandon an unconfirmed transaction, and make the consumed inputs available to be used again
    AbandonTransaction {
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Issue a new token
    IssueNewToken {
        token_ticker: String,
        number_of_decimals: u8,
        metadata_uri: String,
        destination_address: String,
        token_supply: String,
        is_freezable: CliIsFreezable,
    },

    /// Issue a new token
    IssueNewNft {
        destination_address: String,
        media_hash: String,
        name: String,
        description: String,
        ticker: String,
        creator: Option<HexEncoded<PublicKey>>,
        icon_uri: Option<String>,
        media_uri: Option<String>,
        additional_metadata_uri: Option<String>,
    },

    /// Mint new tokens and increase the total supply
    MintTokens {
        token_id: String,
        address: String,
        amount: String,
    },

    /// Unmint existing tokens and reduce the total supply
    UnmintTokens {
        token_id: String,
        amount: String,
    },

    /// Lock the circulating supply for the token
    LockTokenSupply {
        token_id: String,
    },

    /// Freezing the token forbids any operation with all the tokens (except for optional unfreeze)
    FreezeToken {
        token_id: String,
        is_unfreezable: CliIsUnfreezable,
    },

    /// By unfreezing the token all operations are available for the tokens again
    UnfreezeToken {
        token_id: String,
    },

    /// Rescan
    Rescan,

    SyncWallet,

    GetBalance {
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    ListUtxo {
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    /// List the pending transactions that can be abandoned
    ListPendingTransactions,

    /// List available Pool Ids
    ListPoolIds,

    /// List available Delegation Ids with their balances
    ListDelegationIds,

    /// Generate a new unused address
    NewAddress,

    /// Generate a new unused public key
    NewPublicKey,

    /// Get the transaction from the wallet if present
    GetTransaction {
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get the transaction from the wallet if present as hex encoded raw transaction
    GetRawTransaction {
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get the signed transaction from the wallet if present as hex encoded raw transaction
    GetRawSignedTransaction {
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    GetVrfPublicKey,

    SendToAddress {
        address: String,
        amount: String,
        #[arg(default_values_t = Vec::<String>::new())]
        utxos: Vec<String>,
    },

    SendTokensToAddress {
        token_id: String,
        address: String,
        amount: String,
    },

    CreateDelegation {
        address: String,
        pool_id: String,
    },

    DelegateStaking {
        amount: String,
        delegation_id: String,
    },

    SendFromDelegationToAddress {
        address: String,
        amount: String,
        delegation_id: String,
    },

    CreateStakePool {
        amount: String,

        cost_per_block: String,

        margin_ratio_per_thousand: String,

        decommission_key: Option<HexEncoded<PublicKey>>,
    },

    DecommissionStakePool {
        pool_id: String,
    },

    /// Show the seed phrase for the loaded wallet if it has been stored
    ShowSeedPhrase,

    /// Delete the seed phrase from the loaded wallet if it has been stored
    PurgeSeedPhrase,

    /// Node version
    NodeVersion,

    /// Node shutdown
    NodeShutdown,

    /// Connect to the remote peer
    Connect {
        address: IpOrSocketAddress,
    },

    /// Disconnected the remote peer
    Disconnect {
        peer_id: PeerId,
    },

    /// List banned addresses
    ListBanned,

    /// Ban address
    Ban {
        address: BannableAddress,
    },

    /// Unban address
    Unban {
        address: BannableAddress,
    },

    /// Get connected peer count
    PeerCount,

    /// Get connected peers
    ConnectedPeers,

    /// Add reserved peer
    AddReservedPeer {
        address: IpOrSocketAddress,
    },

    /// Remove reserved peer
    RemoveReservedPeer {
        address: IpOrSocketAddress,
    },

    /// Print the version of the software and optionally the git commit hash
    Version,

    /// Quit the REPL
    Exit,

    /// Print history
    History,

    /// Clear screen
    #[clap(name = "clear")]
    ClearScreen,

    /// Clear history
    ClearHistory,
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
        rpc_client.submit_transaction(tx).await.map_err(WalletCliError::RpcError)?;
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
                password,
            } => {
                utils::ensure!(self.state.is_none(), WalletCliError::WalletFileAlreadyOpen);

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
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let address = parse_address(chain_config, &address)?;
                let amount = {
                    let token_number_of_decimals = self
                        .controller()?
                        .get_token_number_of_decimals(token_id)
                        .await
                        .map_err(WalletCliError::Controller)?;
                    parse_token_amount(token_number_of_decimals, &amount)?
                };

                self.get_synced_controller()
                    .await?
                    .mint_tokens(token_id, amount, address)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::UnmintTokens { token_id, amount } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;
                let amount = {
                    let token_number_of_decimals = self
                        .controller()?
                        .get_token_number_of_decimals(token_id)
                        .await
                        .map_err(WalletCliError::Controller)?;
                    parse_token_amount(token_number_of_decimals, &amount)?
                };

                self.get_synced_controller()
                    .await?
                    .unmint_tokens(token_id, amount)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::LockTokenSupply { token_id } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;

                self.get_synced_controller()
                    .await?
                    .lock_token_supply(token_id)
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::FreezeToken {
                token_id,
                is_unfreezable,
            } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;

                self.get_synced_controller()
                    .await?
                    .freeze_token(token_id, is_unfreezable.to_wallet_types())
                    .await
                    .map_err(WalletCliError::Controller)?;

                Ok(Self::tx_submitted_command())
            }

            WalletCommand::UnfreezeToken { token_id } => {
                let token_id = parse_token_id(chain_config, token_id.as_str())?;

                self.get_synced_controller()
                    .await?
                    .unfreeze_token(token_id)
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
                let mut balances = self
                    .get_readonly_controller()?
                    .get_balance(
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .map_err(WalletCliError::Controller)?;
                let coin_balance = balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);
                let mut output = String::new();
                for (currency, amount) in
                    std::iter::once((Currency::Coin, coin_balance)).chain(balances.into_iter())
                {
                    let out = match currency {
                        Currency::Token(token_id) => {
                            let token_number_of_decimals = self
                                .controller()?
                                .get_token_number_of_decimals(token_id)
                                .await
                                .map_err(WalletCliError::Controller)?;
                            format!(
                                "Token: {} amount: {}",
                                Address::new(chain_config, &token_id)
                                    .expect("Encoding token id should never fail"),
                                print_token_amount(token_number_of_decimals, amount)
                            )
                        }
                        Currency::Coin => {
                            format!("Coins amount: {}", print_coin_amount(chain_config, amount))
                        }
                    };
                    output.push_str(&out);
                    output.push('\n');
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
                Ok(ConsoleCommand::Print(vrf_public_key.hex_encode()))
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
                let utxos: Vec<UtxoOutPoint> = utxos
                    .into_iter()
                    .map(parse_utxo_outpoint)
                    .collect::<Result<Vec<_>, WalletCliError>>()?;
                let amount = parse_coin_amount(chain_config, &amount)?;
                let address = parse_address(chain_config, &address)?;
                self.get_synced_controller()
                    .await?
                    .send_to_address(address, amount, utxos)
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
                let amount = {
                    let token_number_of_decimals = self
                        .controller()?
                        .get_token_number_of_decimals_if_not_frozen(token_id)
                        .await
                        .map_err(WalletCliError::Controller)?;
                    parse_token_amount(token_number_of_decimals, &amount)?
                };

                self.get_synced_controller()
                    .await?
                    .send_tokens_to_address(token_id, address, amount)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::CreateDelegation { address, pool_id } => {
                let address = parse_address(chain_config, &address)?;
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
            WalletCommand::History => Ok(ConsoleCommand::PrintHistory),
            WalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            WalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }
}
