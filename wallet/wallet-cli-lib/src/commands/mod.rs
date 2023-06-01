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
    chain::{Block, ChainConfig, SignedTransaction},
    primitives::{Amount, BlockHeight, H256},
};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use wallet_controller::{NodeInterface, NodeRpcClient, PeerId, RpcController};

use crate::errors::WalletCliError;

use self::helper_types::CliUtxoTypes;

#[derive(Debug, Parser)]
#[clap(rename_all = "lower")]
pub enum WalletCommand {
    // TODO: Add optional password
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

    /// Returns the node chainstate
    ChainstateInfo,

    /// Returns the current best block hash
    BestBlock,

    /// Returns the current best block height
    BestBlockHeight,

    /// Get a block hash at height
    BlockHash {
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

    /// Rescan
    Rescan,

    SyncWallet,

    GetBalance,

    ListUtxo {
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
    },

    /// Generate a new unused address
    NewAddress,

    /// Generate a new unused public key
    NewPublicKey,

    GetVrfPublicKey,

    SendToAddress {
        address: String,
        amount: String,
    },

    CreateStakePool {
        amount: String,
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

pub async fn handle_wallet_command(
    chain_config: &Arc<ChainConfig>,
    rpc_client: &NodeRpcClient,
    controller_opt: &mut Option<RpcController>,
    command: WalletCommand,
) -> Result<ConsoleCommand, WalletCliError> {
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
                Some(mnemonic) => wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
                    .map_err(WalletCliError::InvalidMnemonic)?,
                None => wallet_controller::mnemonic::generate_new_mnemonic(language),
            };

            let wallet = RpcController::create_wallet(
                Arc::clone(chain_config),
                wallet_path,
                mnemonic.clone(),
                None,
            )
            .map_err(WalletCliError::Controller)?;

            *controller_opt = Some(RpcController::new(
                Arc::clone(chain_config),
                rpc_client.clone(),
                wallet,
            ));

            let msg = if need_mnemonic_backup {
                format!(
                    "New wallet created successfully\nYour mnemonic: {}\nPlease write it somewhere safe to be able to restore your wallet."
                , mnemonic)
            } else {
                "New wallet created successfully".to_owned()
            };
            Ok(ConsoleCommand::Print(msg))
        }

        WalletCommand::OpenWallet { wallet_path } => {
            utils::ensure!(
                controller_opt.is_none(),
                WalletCliError::WalletFileAlreadyOpen
            );

            let wallet = RpcController::open_wallet(Arc::clone(chain_config), wallet_path)
                .map_err(WalletCliError::Controller)?;

            *controller_opt = Some(RpcController::new(
                Arc::clone(chain_config),
                rpc_client.clone(),
                wallet,
            ));

            Ok(ConsoleCommand::Print(
                "Wallet loaded successfully".to_owned(),
            ))
        }

        WalletCommand::CloseWallet => {
            utils::ensure!(controller_opt.is_some(), WalletCliError::NoWallet);

            *controller_opt = None;

            Ok(ConsoleCommand::Print("Success".to_owned()))
        }

        WalletCommand::ChainstateInfo => {
            let info = rpc_client.chainstate_info().await.map_err(WalletCliError::RpcError)?;
            Ok(ConsoleCommand::Print(format!("{info:?}")))
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

        WalletCommand::BlockHash { height } => {
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
            let hash =
                H256::from_str(&hash).map_err(|e| WalletCliError::InvalidInput(e.to_string()))?;
            let hash = rpc_client.get_block(hash.into()).await.map_err(WalletCliError::RpcError)?;
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
                .generate_block(transactions_opt)
                .await
                .map_err(WalletCliError::Controller)?;
            rpc_client.submit_block(block).await.map_err(WalletCliError::RpcError)?;
            Ok(ConsoleCommand::Print("Success".to_owned()))
        }

        WalletCommand::GenerateBlocks { count } => {
            controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .generate_blocks(count)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print("Success".to_owned()))
        }

        WalletCommand::SubmitBlock { block } => {
            rpc_client.submit_block(block.take()).await.map_err(WalletCliError::RpcError)?;
            Ok(ConsoleCommand::Print(
                "The block was submitted successfully".to_owned(),
            ))
        }

        WalletCommand::SubmitTransaction { transaction } => {
            rpc_client
                .submit_transaction(transaction.take())
                .await
                .map_err(WalletCliError::RpcError)?;
            Ok(ConsoleCommand::Print(
                "The transaction was submitted successfully".to_owned(),
            ))
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

        WalletCommand::GetBalance => {
            let (coin_balance, _tokens_balance) = controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .get_balance()
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print(print_coin_amount(
                chain_config,
                coin_balance,
            )))
        }

        WalletCommand::ListUtxo { utxo_type } => {
            let utxos = controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .get_utxos(utxo_type.to_wallet_types())
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print(format!("{utxos:?}")))
        }

        WalletCommand::NewAddress => {
            let address = controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .new_address()
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print(address.get().to_owned()))
        }

        WalletCommand::NewPublicKey => {
            let public_key = controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .new_public_key()
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print(public_key.hex_encode()))
        }

        WalletCommand::GetVrfPublicKey => {
            let vrf_public_key = controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .get_vrf_public_key()
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print(vrf_public_key.hex_encode()))
        }

        WalletCommand::SendToAddress { address, amount } => {
            let amount = parse_coin_amount(chain_config, &amount)?;
            let address = parse_address(chain_config, &address)?;
            controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .send_to_address(address, amount)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print("Success".to_owned()))
        }

        WalletCommand::CreateStakePool { amount } => {
            let amount = parse_coin_amount(chain_config, &amount)?;
            controller_opt
                .as_mut()
                .ok_or(WalletCliError::NoWallet)?
                .create_stake_pool_tx(amount)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(ConsoleCommand::Print("Success".to_owned()))
        }

        WalletCommand::NodeVersion => {
            let version = rpc_client.node_version().await.map_err(WalletCliError::RpcError)?;
            Ok(ConsoleCommand::Print(version))
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
            Ok(ConsoleCommand::Print(format!("{peers:?}")))
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
