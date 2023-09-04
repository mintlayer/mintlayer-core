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

use clap::Parser;
use common::{
    address::Address,
    chain::{
        tokens::{Metadata, TokenCreator, TokenId},
        Block, ChainConfig, Destination, PoolId, SignedTransaction, Transaction,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, H256},
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use p2p_types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use wallet::{account::Currency, wallet_events::WalletEventsNoOp};
use wallet_controller::{NodeInterface, NodeRpcClient, PeerId, DEFAULT_ACCOUNT_INDEX};

use crate::{errors::WalletCliError, CliController};

use self::helper_types::{
    format_delegation_info, format_pool_info, CliStoreSeedPhrase, CliUtxoState, CliUtxoTypes,
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
        save_seed_phrase: CliStoreSeedPhrase,

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

    /// Show receive-addresses with their usage state
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
        transactions: Option<Vec<HexEncoded<SignedTransaction>>>,
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
        amount_to_issue: String,
        number_of_decimals: u8,
        metadata_uri: String,
        destination_address: String,
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

    GetVrfPublicKey,

    SendToAddress {
        address: String,
        amount: String,
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

    /// Show the seed phrase for the loaded wallet if it has been saved
    ShowSeedPhrase,

    /// Delete the seed phrase from the loaded wallet if it has been saved
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

fn to_per_thousand(value_str: &str, variable_name: &str) -> Result<PerThousand, WalletCliError> {
    PerThousand::from_decimal_str(value_str).ok_or(WalletCliError::InvalidInput(format!(
        "Failed to parse {variable_name} the decimal that must be in the range [0.001,1.000] or [0.1%,100%]",
    )))
}

fn parse_address(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<Address<Destination>, WalletCliError> {
    Address::from_str(chain_config, address)
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid address '{address}': {e}")))
}

fn parse_pool_id(chain_config: &ChainConfig, pool_id: &str) -> Result<PoolId, WalletCliError> {
    Address::<PoolId>::from_str(chain_config, pool_id)
        .and_then(|address| address.decode_object(chain_config))
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid pool ID '{pool_id}': {e}")))
}

fn parse_token_id(chain_config: &ChainConfig, token_id: &str) -> Result<TokenId, WalletCliError> {
    Address::<TokenId>::from_str(chain_config, token_id)
        .and_then(|address| address.decode_object(chain_config))
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid token ID '{token_id}': {e}")))
}

fn parse_coin_amount(chain_config: &ChainConfig, value: &str) -> Result<Amount, WalletCliError> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
        .ok_or_else(|| WalletCliError::InvalidInput(value.to_owned()))
}

fn parse_token_amount(token_number_of_decimals: u8, value: &str) -> Result<Amount, WalletCliError> {
    Amount::from_fixedpoint_str(value, token_number_of_decimals)
        .ok_or_else(|| WalletCliError::InvalidInput(value.to_owned()))
}

fn print_coin_amount(chain_config: &ChainConfig, value: Amount) -> String {
    value.into_fixedpoint_str(chain_config.coin_decimals())
}

struct CliWalletState {
    selected_account: U31,
}

pub struct CommandHandler {
    // the CliController if there is a loaded wallet
    state: Option<(CliController, CliWalletState)>,
}

impl CommandHandler {
    pub fn new() -> Self {
        CommandHandler { state: None }
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
                save_seed_phrase,
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
                        save_seed_phrase.to_walet_type(),
                        info.best_block_height,
                        info.best_block_id,
                    )
                } else {
                    CliController::recover_wallet(
                        Arc::clone(chain_config),
                        wallet_path,
                        mnemonic.clone(),
                        None,
                        save_seed_phrase.to_walet_type(),
                    )
                }
                .map_err(WalletCliError::Controller)?;

                self.state = Some((
                    CliController::new(
                        Arc::clone(chain_config),
                        rpc_client.clone(),
                        wallet,
                        WalletEventsNoOp,
                    ),
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
                    ),
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
                let transactions_opt =
                    transactions.map(|txs| txs.into_iter().map(HexEncoded::take).collect());
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let block = controller
                    .generate_block(selected_account, transactions_opt)
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller.start_staking(selected_account).map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .abandon_transaction(selected_account, transaction_id.take())
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(
                    "The transaction was marked as abandoned successfully".to_owned(),
                ))
            }

            WalletCommand::IssueNewToken {
                token_ticker,
                amount_to_issue,
                number_of_decimals,
                metadata_uri,
                destination_address,
            } => {
                let amount_to_issue = parse_coin_amount(chain_config, &amount_to_issue)?;
                let destination_address = parse_address(chain_config, &destination_address)?;

                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let token_id = controller
                    .issue_new_token(
                        selected_account,
                        destination_address,
                        token_ticker.into_bytes(),
                        amount_to_issue,
                        number_of_decimals,
                        metadata_uri.into_bytes(),
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
                creator,
                name,
                description,
                ticker,
                icon_uri,
                additional_metadata_uri,
                media_uri,
                media_hash,
                destination_address,
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

                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let token_id = controller
                    .issue_new_nft(selected_account, destination_address, metadata)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!(
                    "A new NFT has been issued with ID: {}",
                    Address::new(chain_config, &token_id)
                        .expect("Encoding token id should never fail"),
                )))
            }

            WalletCommand::Rescan => Ok(ConsoleCommand::Print("Not implemented".to_owned())),

            WalletCommand::SyncWallet => {
                self.controller()?.sync_once().await.map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GetBalance {
                utxo_states,
                with_locked,
            } => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let mut balances = controller
                    .get_balance(
                        selected_account,
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .map_err(WalletCliError::Controller)?;
                let coin_balance = balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);

                let output = std::iter::once((Currency::Coin, coin_balance))
                    .chain(balances.into_iter())
                    .map(|(currency, amount)| match currency {
                        Currency::Token(token_id) => {
                            format!(
                                "Token: {} amount: {}",
                                Address::new(chain_config, &token_id)
                                    .expect("Encoding token id should never fail"),
                                print_coin_amount(chain_config, amount)
                            )
                        }
                        Currency::Coin => {
                            format!("Coins amount: {}", print_coin_amount(chain_config, amount))
                        }
                    })
                    .collect::<Vec<String>>()
                    .join("\n");

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::ListUtxo {
                utxo_type,
                utxo_states,
                with_locked,
            } => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let utxos = controller
                    .get_utxos(
                        selected_account,
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::ListPendingTransactions => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let utxos = controller
                    .pending_transactions(selected_account)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::NewAddress => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let address =
                    controller.new_address(selected_account).map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(address.1.get().to_owned()))
            }

            WalletCommand::NewPublicKey => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let public_key = controller
                    .new_public_key(selected_account)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(public_key.hex_encode()))
            }

            WalletCommand::GetVrfPublicKey => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let vrf_public_key = controller
                    .get_vrf_public_key(selected_account)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(vrf_public_key.hex_encode()))
            }

            WalletCommand::SendToAddress { address, amount } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let address = parse_address(chain_config, &address)?;
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .send_to_address(selected_account, address, amount)
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
                        .get_token_number_of_decimals(token_id)
                        .await
                        .map_err(WalletCliError::Controller)?;
                    parse_token_amount(token_number_of_decimals, &amount)?
                };

                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .send_tokens_to_address(selected_account, token_id, address, amount)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::CreateDelegation { address, pool_id } => {
                let address = parse_address(chain_config, &address)?;
                let pool_id_address = Address::from_str(chain_config, &pool_id)?;

                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let delegation_id = controller
                    .create_delegation(
                        selected_account,
                        address,
                        pool_id_address.decode_object(chain_config)?,
                    )
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

                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .delegate_staking(
                        selected_account,
                        amount,
                        delegation_id_address.decode_object(chain_config)?,
                    )
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .send_to_address_from_delegation(
                        selected_account,
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .create_stake_pool_tx(
                        selected_account,
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                controller
                    .decommission_stake_pool(selected_account, pool_id)
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(Self::tx_submitted_command())
            }

            WalletCommand::ShowSeedPhrase => {
                let phrase =
                    self.controller()?.seed_phrase().map_err(WalletCliError::Controller)?;

                let msg = if let Some(phrase) = phrase {
                    format!("The saved seed phrase is \"{}\"", phrase.join(" "))
                } else {
                    "No saved seed phrase for this wallet. This was your choice when you created the wallet as a security option. Make sure not to lose this wallet file if you don't have the seed-phrase saved elsewhere when you created the wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            WalletCommand::PurgeSeedPhrase => {
                let phrase =
                    self.controller()?.delete_seed_phrase().map_err(WalletCliError::Controller)?;

                let msg = if let Some(phrase) = phrase {
                    format!("The seed phrase has been deleted, you can save it if you haven't do so yet: \"{}\"", phrase.join(" "))
                } else {
                    "No saved seed phrase for this wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            WalletCommand::NodeVersion => {
                let version = rpc_client.node_version().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(version))
            }

            WalletCommand::ListPoolIds => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let pool_ids: Vec<_> = controller
                    .get_pool_ids(chain_config, selected_account)
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
                Ok(ConsoleCommand::Print(format!("[{}]", pool_ids.join(", "))))
            }

            WalletCommand::ListDelegationIds => {
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;
                let pool_ids: Vec<_> = controller
                    .get_delegations(selected_account)
                    .map_err(WalletCliError::Controller)?
                    .map(|(delegation_id, balance)| {
                        format_delegation_info(*delegation_id, balance, chain_config.as_ref())
                    })
                    .collect();
                Ok(ConsoleCommand::Print(format!("[{}]", pool_ids.join(", "))))
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
                let (controller, selected_account) = self.get_controller_and_selected_acc()?;

                let addresses_with_usage =
                    controller.get_addresses_with_usage(selected_account).map_err(|e| {
                        WalletCliError::AddressesRetrievalFailed(selected_account, e.to_string())
                    })?;

                let to_print = addresses_with_usage
                    .into_iter()
                    .map(|(index, (address, is_used))| {
                        let is_used = if is_used { "Yes" } else { "No" };
                        format!("{}\t{}\t;\tused:\t{}", index, address, is_used)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                Ok(ConsoleCommand::Print(to_print))
            }

            WalletCommand::Exit => Ok(ConsoleCommand::Exit),
            WalletCommand::History => Ok(ConsoleCommand::PrintHistory),
            WalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            WalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }
}
