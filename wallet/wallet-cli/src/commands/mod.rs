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
use reedline::Reedline;
use serialization::hex::HexEncode;
use wallet_controller::{PeerId, RpcController};

use crate::{cli_println, console::ConsoleContext, errors::WalletCliError};

#[derive(Debug, Parser)]
#[clap(rename_all = "lower")]
pub enum WalletCommands {
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
    Block {
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

pub async fn handle_wallet_command(
    output: &ConsoleContext,
    controller: &mut RpcController,
    line_editor: &mut Reedline,
    command: WalletCommands,
) -> Result<(), WalletCliError> {
    match command {
        WalletCommands::BestBlock => {
            let id = controller.get_best_block_id().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "{}", id.hex_encode());
            Ok(())
        }

        WalletCommands::BestBlockHeight => {
            let height =
                controller.get_best_block_height().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "{}", height);
            Ok(())
        }

        WalletCommands::BlockHash { height } => {
            let hash = controller
                .get_block_id_at_height(height)
                .await
                .map_err(WalletCliError::Controller)?;
            match hash {
                Some(id) => cli_println!(output, "{}", id.hex_encode()),
                None => cli_println!(output, "Not found"),
            }
            Ok(())
        }

        WalletCommands::Block { hash } => {
            let hash =
                H256::from_str(&hash).map_err(|e| WalletCliError::InvalidInput(e.to_string()))?;
            let hash =
                controller.get_block(hash.into()).await.map_err(WalletCliError::Controller)?;
            match hash {
                Some(block) => println!("{}", block.hex_encode()),
                None => cli_println!(output, "Not found"),
            }
            Ok(())
        }

        WalletCommands::SubmitBlock { block } => {
            controller.submit_block(block).await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "The block was submitted successfully");
            Ok(())
        }

        WalletCommands::SubmitTransaction { transaction } => {
            controller
                .submit_transaction(transaction)
                .await
                .map_err(WalletCliError::Controller)?;
            cli_println!(output, "The transaction was submitted successfully");
            Ok(())
        }

        WalletCommands::Rescan => {
            cli_println!(output, "Not implemented");
            Ok(())
        }

        WalletCommands::NodeVersion => {
            let version = controller.node_version().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "{}", version);
            Ok(())
        }

        WalletCommands::NodeShutdown => {
            controller.node_shutdown().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "Success");
            Ok(())
        }

        WalletCommands::Connect { address } => {
            controller.p2p_connect(address).await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "Success");
            Ok(())
        }
        WalletCommands::Disconnect { peer_id } => {
            controller.p2p_disconnect(peer_id).await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "Success");
            Ok(())
        }
        WalletCommands::PeerCount => {
            let peer_count =
                controller.p2p_get_peer_count().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "{}", peer_count);
            Ok(())
        }
        WalletCommands::ConnectedPeers => {
            let peers =
                controller.p2p_get_connected_peers().await.map_err(WalletCliError::Controller)?;
            cli_println!(output, "{:?}", peers);
            Ok(())
        }
        WalletCommands::AddReservedPeer { address } => {
            controller
                .p2p_add_reserved_node(address)
                .await
                .map_err(WalletCliError::Controller)?;
            cli_println!(output, "Success");
            Ok(())
        }
        WalletCommands::RemoveReservedPeer { address } => {
            controller
                .p2p_remove_reserved_node(address)
                .await
                .map_err(WalletCliError::Controller)?;
            cli_println!(output, "Success");
            Ok(())
        }

        WalletCommands::Exit => Err(WalletCliError::Exit),
        WalletCommands::History => {
            line_editor.print_history().expect("Should not fail normally");
            Ok(())
        }
        WalletCommands::ClearScreen => {
            line_editor.clear_scrollback().expect("Should not fail normally");
            Ok(())
        }
        WalletCommands::ClearHistory => {
            line_editor.history_mut().clear().expect("Should not fail normally");
            Ok(())
        }
    }
}
