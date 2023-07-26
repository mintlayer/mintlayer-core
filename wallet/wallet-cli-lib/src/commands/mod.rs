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
        Block, ChainConfig, PoolId, SignedTransaction, Transaction,
    },
    primitives::{Amount, BlockHeight, Id, H256},
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use wallet::{account::Currency, wallet_events::WalletEventsNoOp};
use wallet_controller::{NodeInterface, NodeRpcClient, PeerId, DEFAULT_ACCOUNT_INDEX};

use crate::{errors::WalletCliError, CliController};

use self::helper_types::{format_pool_info, CliUtxoState, CliUtxoTypes};

#[derive(Debug, Parser)]
#[clap(rename_all = "lower")]
pub enum WalletCommand {
    /// Create new wallet
    CreateWallet {
        /// File path
        wallet_path: PathBuf,

        /// Mnemonic phrase (12, 15, or 24 words as a single quoted argument). If not specified, a new mnemonic phrase is generated and printed.
        mnemonic: Option<String>,
    },

    /// Open exiting wallet
    OpenWallet {
        /// File path
        wallet_path: PathBuf,
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
        count: u32,
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
        pool_id: HexEncoded<PoolId>,
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
        creator: Option<HexEncoded<PublicKey>>,
        name: String,
        description: String,
        ticker: String,
        icon_uri: Option<String>,
        additional_metadata_uri: Option<String>,
        media_uri: Option<String>,
        media_hash: String,
        destination_address: String,
    },

    /// Rescan
    Rescan,

    SyncWallet,

    GetBalance {
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    ListUtxo {
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    /// List the pending transactions that can be abandoned
    ListPendingTransactions,

    /// List available Pool Ids
    ListPoolIds,

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
        token_id: TokenId,
        address: String,
        amount: String,
    },

    CreateStakePool {
        amount: String,

        decomission_key: Option<HexEncoded<PublicKey>>,
    },

    /// Node version
    NodeVersion,

    /// Node shutdown
    NodeShutdown,

    /// Connect to the remote peer
    Connect {
        address: String,
    },

    /// Disconnected the remote peer
    Disconnect {
        peer_id: PeerId,
    },

    /// Get connected peer count
    PeerCount,

    /// Get connected peers
    ConnectedPeers,

    /// Add reserved peer
    AddReservedPeer {
        address: String,
    },

    /// Remove reserved peer
    RemoveReservedPeer {
        address: String,
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

fn parse_address(chain_config: &ChainConfig, address: &str) -> Result<Address, WalletCliError> {
    Address::from_str(chain_config, address)
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid address '{address}': {e}")))
}

fn parse_coin_amount(chain_config: &ChainConfig, value: &str) -> Result<Amount, WalletCliError> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
        .ok_or_else(|| WalletCliError::InvalidInput(value.to_owned()))
}

fn print_coin_amount(chain_config: &ChainConfig, value: Amount) -> String {
    value.into_fixedpoint_str(chain_config.coin_decimals())
}

struct CLIWalletState {
    selected_account: U31,
    accounts: Vec<Option<String>>,
}

pub struct CommandHandler {
    // the CLIWalletState if there is a loaded wallet
    state: Option<CLIWalletState>,
}

impl CommandHandler {
    pub fn new() -> Self {
        CommandHandler { state: None }
    }

    fn set_accounts(&mut self, new_accounts: Vec<Option<String>>) {
        if let Some(CLIWalletState {
            selected_account: _,
            accounts,
        }) = self.state.as_mut()
        {
            *accounts = new_accounts;
        } else {
            self.state.replace(CLIWalletState {
                selected_account: DEFAULT_ACCOUNT_INDEX,
                accounts: new_accounts,
            });
        }
    }
    fn add_account(&mut self, new_account: Option<String>) {
        if let Some(CLIWalletState {
            selected_account: _,
            accounts,
        }) = self.state.as_mut()
        {
            accounts.push(new_account);
        } else {
            self.state.replace(CLIWalletState {
                selected_account: DEFAULT_ACCOUNT_INDEX,
                accounts: vec![new_account],
            });
        }
    }

    fn set_selected_account(&mut self, account_index: U31) -> Result<(), WalletCliError> {
        let CLIWalletState {
            selected_account,
            accounts,
        } = self.state.as_mut().ok_or(WalletCliError::NoWallet)?;

        if account_index.into_u32() as usize >= accounts.len() {
            return Err(WalletCliError::AccountNotFound(account_index));
        }

        *selected_account = account_index;
        Ok(())
    }

    fn selected_account(&self) -> Option<U31> {
        self.state.as_ref().map(|state| state.selected_account)
    }

    fn repl_status(&mut self) -> String {
        match self.state.as_ref() {
            Some(CLIWalletState {
                selected_account,
                accounts,
            }) if accounts.len() > 1 => match accounts.get(selected_account.into_u32() as usize) {
                Some(Some(name)) => format!("(Account {})", name),
                _ => format!("(Account No. {})", selected_account),
            },
            _ => String::new(),
        }
    }

    pub async fn broadcast_transaction(
        rpc_client: &NodeRpcClient,
        tx: SignedTransaction,
    ) -> Result<ConsoleCommand, WalletCliError> {
        let status = rpc_client.submit_transaction(tx).await.map_err(WalletCliError::RpcError)?;
        let status_text = match status {
            mempool::TxStatus::InMempool => "The transaction was submitted successfully",
            mempool::TxStatus::InOrphanPool => {
                // Mempool should reject the transaction and not return `InOrphanPool`
                "The transaction has been added to the orphan pool"
            }
        };
        Ok(ConsoleCommand::Print(status_text.to_owned()))
    }

    pub async fn handle_wallet_command(
        &mut self,
        chain_config: &Arc<ChainConfig>,
        rpc_client: &NodeRpcClient,
        controller_opt: &mut Option<CliController>,
        command: WalletCommand,
    ) -> Result<ConsoleCommand, WalletCliError> {
        let selected_account = self.selected_account();
        match command {
            WalletCommand::CreateWallet {
                wallet_path,
                mnemonic,
            } => {
                utils::ensure!(
                    controller_opt.is_none(),
                    WalletCliError::WalletFileAlreadyOpen
                );

                // TODO: Support other languages
                let language = wallet::wallet::Language::English;
                let need_mnemonic_backup = mnemonic.is_none();
                let mnemonic = match &mnemonic {
                    Some(mnemonic) => {
                        wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
                            .map_err(WalletCliError::InvalidMnemonic)?
                    }
                    None => wallet_controller::mnemonic::generate_new_mnemonic(language),
                };

                let wallet = CliController::create_wallet(
                    Arc::clone(chain_config),
                    wallet_path,
                    mnemonic.clone(),
                    None,
                )
                .map_err(WalletCliError::Controller)?;

                let account_names = wallet.account_names().cloned().collect();
                *controller_opt = Some(CliController::new(
                    Arc::clone(chain_config),
                    rpc_client.clone(),
                    wallet,
                    WalletEventsNoOp,
                ));

                let msg = if need_mnemonic_backup {
                    format!(
                    "New wallet created successfully\nYour mnemonic: {}\nPlease write it somewhere safe to be able to restore your wallet."
                , mnemonic)
                } else {
                    "New wallet created successfully".to_owned()
                };
                self.set_accounts(account_names);
                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: msg,
                })
            }

            WalletCommand::OpenWallet { wallet_path } => {
                utils::ensure!(
                    controller_opt.is_none(),
                    WalletCliError::WalletFileAlreadyOpen
                );

                let wallet = CliController::open_wallet(Arc::clone(chain_config), wallet_path)
                    .map_err(WalletCliError::Controller)?;

                let account_names = wallet.account_names().cloned().collect();
                *controller_opt = Some(CliController::new(
                    Arc::clone(chain_config),
                    rpc_client.clone(),
                    wallet,
                    WalletEventsNoOp,
                ));

                self.set_accounts(account_names);
                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: "Wallet loaded successfully".to_owned(),
                })
            }

            WalletCommand::CloseWallet => {
                utils::ensure!(controller_opt.is_some(), WalletCliError::NoWallet);

                *controller_opt = None;

                self.state = None;
                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status(),
                    print_message: "Success".to_owned(),
                })
            }

            WalletCommand::EncryptPrivateKeys { password } => {
                match controller_opt.as_mut() {
                    None => {
                        return Err(WalletCliError::NoWallet);
                    }
                    Some(controller) => {
                        controller
                            .encrypt_wallet(&Some(password))
                            .map_err(WalletCliError::Controller)?;
                    }
                }

                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::RemovePrivateKeysEncryption => {
                match controller_opt.as_mut() {
                    None => {
                        return Err(WalletCliError::NoWallet);
                    }
                    Some(controller) => {
                        controller.encrypt_wallet(&None).map_err(WalletCliError::Controller)?;
                    }
                }

                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::UnlockPrivateKeys { password } => {
                match controller_opt.as_mut() {
                    None => {
                        return Err(WalletCliError::NoWallet);
                    }
                    Some(controller) => {
                        controller.unlock_wallet(&password).map_err(WalletCliError::Controller)?;
                    }
                }

                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::LockPrivateKeys => {
                match controller_opt.as_mut() {
                    None => {
                        return Err(WalletCliError::NoWallet);
                    }
                    Some(controller) => {
                        controller.lock_wallet().map_err(WalletCliError::Controller)?;
                    }
                }

                Ok(ConsoleCommand::Print("Success".to_owned()))
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
                let block = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .generate_block(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        transactions_opt,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                rpc_client.submit_block(block).await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GenerateBlocks { count } => {
                controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .generate_blocks(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        count,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::CreateNewAccount { name } => {
                let (new_account_index, name) = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .create_account(name)
                    .map_err(WalletCliError::Controller)?;

                self.add_account(name);
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
                controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .start_staking(
                        self.selected_account().ok_or(WalletCliError::NoSelectedAccount)?,
                    )
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::StopStaking => {
                controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .stop_staking(self.selected_account().ok_or(WalletCliError::NoSelectedAccount)?)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::StakePoolBalance { pool_id } => {
                let balance_opt = rpc_client
                    .get_stake_pool_balance(pool_id.take())
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
                controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .abandon_transaction(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        transaction_id.take(),
                    )
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

                let (token_id, _tx_status) = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .issue_new_token(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
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
                    HexEncode::hex_encode(&token_id),
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

                let (token_id, _tx_status) = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .issue_new_nft(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        destination_address,
                        metadata,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!(
                    "A new NFT has been issued with ID: {}",
                    token_id
                )))
            }

            WalletCommand::Rescan => Ok(ConsoleCommand::Print("Not implemented".to_owned())),

            WalletCommand::SyncWallet => {
                controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .sync_once()
                    .await
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GetBalance { utxo_states } => {
                let mut balances = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .get_balance(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        CliUtxoState::to_wallet_states(utxo_states),
                    )
                    .map_err(WalletCliError::Controller)?;
                let coin_balance = balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);

                let output = std::iter::once((Currency::Coin, coin_balance))
                    .chain(balances.into_iter())
                    .map(|(currency, amount)| match currency {
                        Currency::Token(token_id) => {
                            format!(
                                "Token: {} amount: {}",
                                HexEncode::hex_encode(&token_id),
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
            } => {
                let utxos = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .get_utxos(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                    )
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::ListPendingTransactions => {
                let utxos = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .pending_transactions(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                    )
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::NewAddress => {
                let address = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .new_address(selected_account.ok_or(WalletCliError::NoSelectedAccount)?)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(address.1.get().to_owned()))
            }

            WalletCommand::NewPublicKey => {
                let public_key = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .new_public_key(selected_account.ok_or(WalletCliError::NoSelectedAccount)?)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(public_key.hex_encode()))
            }

            WalletCommand::GetVrfPublicKey => {
                let vrf_public_key = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .get_vrf_public_key(selected_account.ok_or(WalletCliError::NoSelectedAccount)?)
                    .map_err(WalletCliError::Controller)?;
                Ok(ConsoleCommand::Print(vrf_public_key.hex_encode()))
            }

            WalletCommand::SendToAddress { address, amount } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let address = parse_address(chain_config, &address)?;
                let tx = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .send_to_address(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        address,
                        amount,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Self::broadcast_transaction(rpc_client, tx).await
            }

            WalletCommand::SendTokensToAddress {
                token_id,
                address,
                amount,
            } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let address = parse_address(chain_config, &address)?;
                let tx = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .send_tokens_to_address(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        token_id,
                        address,
                        amount,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Self::broadcast_transaction(rpc_client, tx).await
            }

            WalletCommand::CreateStakePool {
                amount,
                decomission_key,
            } => {
                let amount = parse_coin_amount(chain_config, &amount)?;
                let decomission_key = decomission_key.map(HexEncoded::take);
                let tx = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .create_stake_pool_tx(
                        selected_account.ok_or(WalletCliError::NoSelectedAccount)?,
                        amount,
                        decomission_key,
                    )
                    .await
                    .map_err(WalletCliError::Controller)?;
                Self::broadcast_transaction(rpc_client, tx).await
            }

            WalletCommand::NodeVersion => {
                let version = rpc_client.node_version().await.map_err(WalletCliError::RpcError)?;
                Ok(ConsoleCommand::Print(version))
            }

            WalletCommand::ListPoolIds => {
                let pool_ids: Vec<_> = controller_opt
                    .as_mut()
                    .ok_or(WalletCliError::NoWallet)?
                    .get_pool_ids(selected_account.ok_or(WalletCliError::NoSelectedAccount)?)
                    .await
                    .map_err(WalletCliError::Controller)?
                    .into_iter()
                    .map(|(pool_id, block_info, balance)| {
                        format_pool_info(pool_id, balance, block_info.height, block_info.timestamp)
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

            WalletCommand::Exit => Ok(ConsoleCommand::Exit),
            WalletCommand::History => Ok(ConsoleCommand::PrintHistory),
            WalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            WalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }
}
