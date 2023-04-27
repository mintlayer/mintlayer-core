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

use std::str::FromStr;

use clap::Parser;
use common::primitives::{BlockHeight, H256};
use serialization::hex::HexEncode;
use wallet_controller::{PeerId, RpcController};

use crate::errors::WalletCliError;

#[derive(Debug, Parser)]
#[clap(rename_all = "lower")]
pub enum WalletCommand {
    /// Returns the node chainstate
    Chainstate,

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
        block: String,
    },

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network
    SubmitTransaction {
        /// Hex encoded transaction
        transaction: String,
    },

    /// Rescan
    Rescan,

    /// Node version
    NodeVersion,

    /// Node shutdown
    NodeShutdown,

    /// Connect to the remote peer
    Connect { address: String },

    /// Disconnected the remote peer
    Disconnect { peer_id: PeerId },

    /// Get connected peer count
    PeerCount,

    /// Get connected peers
    ConnectedPeers,

    /// Add reserved peer
    AddReservedPeer { address: String },

    /// Remove reserved peer
    RemoveReservedPeer { address: String },

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
pub enum EditConsole {
    Print(String),
    ClearScreen,
    PrintHistory,
    ClearHistory,
    Exit,
}

pub async fn handle_wallet_command(
    controller: &mut RpcController,
    command: WalletCommand,
) -> Result<EditConsole, WalletCliError> {
    match command {
        WalletCommand::Chainstate => {
            let info = controller.chainstate_info().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(format!("{info:?}")))
        }

        WalletCommand::BestBlock => {
            let id = controller.get_best_block_id().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(id.hex_encode()))
        }

        WalletCommand::BestBlockHeight => {
            let height =
                controller.get_best_block_height().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(height.to_string()))
        }

        WalletCommand::BlockHash { height } => {
            let hash = controller
                .get_block_id_at_height(height)
                .await
                .map_err(WalletCliError::Controller)?;
            match hash {
                Some(id) => Ok(EditConsole::Print(id.hex_encode())),
                None => Ok(EditConsole::Print("Not found".to_owned())),
            }
        }

        WalletCommand::GetBlock { hash } => {
            let hash =
                H256::from_str(&hash).map_err(|e| WalletCliError::InvalidInput(e.to_string()))?;
            let hash =
                controller.get_block(hash.into()).await.map_err(WalletCliError::Controller)?;
            match hash {
                Some(block) => Ok(EditConsole::Print(block.hex_encode())),
                None => Ok(EditConsole::Print("Not found".to_owned())),
            }
        }

        WalletCommand::SubmitBlock { block } => {
            controller.submit_block(block).await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(
                "The block was submitted successfully".to_owned(),
            ))
        }

        WalletCommand::SubmitTransaction { transaction } => {
            controller
                .submit_transaction(transaction)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(
                "The transaction was submitted successfully".to_owned(),
            ))
        }

        WalletCommand::Rescan => Ok(EditConsole::Print("Not implemented".to_owned())),

        WalletCommand::NodeVersion => {
            let version = controller.node_version().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(version))
        }

        WalletCommand::NodeShutdown => {
            controller.node_shutdown().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print("Success".to_owned()))
        }

        WalletCommand::Connect { address } => {
            controller.p2p_connect(address).await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print("Success".to_owned()))
        }
        WalletCommand::Disconnect { peer_id } => {
            controller.p2p_disconnect(peer_id).await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print("Success".to_owned()))
        }
        WalletCommand::PeerCount => {
            let peer_count =
                controller.p2p_get_peer_count().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(peer_count.to_string()))
        }
        WalletCommand::ConnectedPeers => {
            let peers =
                controller.p2p_get_connected_peers().await.map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print(format!("{peers:?}")))
        }
        WalletCommand::AddReservedPeer { address } => {
            controller
                .p2p_add_reserved_node(address)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print("Success".to_owned()))
        }
        WalletCommand::RemoveReservedPeer { address } => {
            controller
                .p2p_remove_reserved_node(address)
                .await
                .map_err(WalletCliError::Controller)?;
            Ok(EditConsole::Print("Success".to_owned()))
        }

        WalletCommand::Exit => Ok(EditConsole::Exit),
        WalletCommand::History => Ok(EditConsole::PrintHistory),
        WalletCommand::ClearScreen => Ok(EditConsole::ClearScreen),
        WalletCommand::ClearHistory => Ok(EditConsole::ClearHistory),
    }
}
