// Copyright (c) 2024 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Confirmation prompts for state-changing wallet commands.
//
// The interactive wallet and `--exec` mode ask for confirmation before a
// command that moves funds, changes on-chain state, or destroys secrets.
// `--yes` skips the prompt.

use crate::{
    ColdWalletCommand, ManageableWalletCommand, WalletCommand, WalletManagementCommand,
};

/// Returns the confirmation question for a state-changing command, or `None`
/// when the command can run without asking.
pub fn confirmation_prompt(command: &ManageableWalletCommand) -> Option<String> {
    match command {
        ManageableWalletCommand::WalletCommands(command) => wallet_confirmation(command),
        ManageableWalletCommand::ManagementCommands(WalletManagementCommand::CloseWallet) => {
            None
        }
        ManageableWalletCommand::ManagementCommands(_) => None,
        _ => None,
    }
}

fn wallet_confirmation(command: &WalletCommand) -> Option<String> {
    match command {
        WalletCommand::ConfigBroadcast { broadcast } => Some(format!(
            "Set automatic broadcasting of created transactions to {broadcast}?"
        )),
        WalletCommand::SendToAddress {
            address,
            amount,
            utxos: _,
        } => Some(format!("Send {amount} coins to {address}?")),
        WalletCommand::SendTokensToAddress {
            token_id,
            address,
            amount,
        } => Some(format!("Send {amount} of token {token_id} to {address}?")),
        WalletCommand::SweepFromAddress {
            destination_address,
            addresses,
            all,
        } => {
            let source = if *all {
                "all addresses".to_owned()
            } else {
                addresses.join(", ")
            };
            Some(format!("Sweep {source} to {destination_address}?"))
        }
        WalletCommand::SweepFromDelegation {
            destination_address,
            delegation_id,
        } => Some(format!(
            "Sweep delegation {delegation_id} to {destination_address}?"
        )),
        WalletCommand::DepositData { data } => Some(format!(
            "Store {} bytes of data on the chain?",
            data.len() / 2
        )),
        WalletCommand::IssueNewNft {
            destination: _,
            media_hash: _,
            name,
            ..
        } => Some(format!("Issue the NFT \"{name}\"?")),
        WalletCommand::IssueNewToken { ticker, .. } => {
            Some(format!("Issue the token {ticker}?"))
        }
        WalletCommand::ChangeTokenAuthority { token_id, address } => Some(format!(
            "Change the authority of token {token_id} to {address}?"
        )),
        WalletCommand::ChangeTokenMetadataUri {
            token_id,
            metadata_uri,
        } => Some(format!(
            "Change the metadata URI of token {token_id} to {metadata_uri}?"
        )),
        WalletCommand::MintTokens {
            token_id,
            address,
            amount,
        } => Some(format!("Mint {amount} of token {token_id} to {address}?")),
        WalletCommand::UnmintTokens { token_id, amount } => {
            Some(format!("Unmint {amount} of token {token_id}?"))
        }
        WalletCommand::LockTokenSupply { token_id } => {
            Some(format!("Permanently lock the supply of token {token_id}?"))
        }
        WalletCommand::FreezeToken { token_id, .. } => {
            Some(format!("Freeze token accounts of {token_id}?"))
        }
        WalletCommand::UnfreezeToken { token_id } => {
            Some(format!("Unfreeze token accounts of {token_id}?"))
        }
        WalletCommand::DelegateStaking {
            delegation_id,
            amount,
        } => Some(format!("Delegate {amount} to delegation {delegation_id}?")),
        WalletCommand::WithdrawFromDelegation {
            address,
            amount,
            delegation_id,
        } => Some(format!(
            "Withdraw {amount} from delegation {delegation_id} to {address}?"
        )),
        WalletCommand::StartStaking { .. } => Some("Start staking?".to_owned()),
        WalletCommand::StopStaking { .. } => Some("Stop staking?".to_owned()),
        WalletCommand::CreateStakePool { amount, .. } => {
            Some(format!("Create a stake pool pledging {amount}?"))
        }
        WalletCommand::DecommissionStakePool {
            pool_id,
            output_address,
        } => Some(format!(
            "Decommission stake pool {pool_id}, sending the funds to {output_address}?"
        )),
        WalletCommand::DecommissionStakePoolRequest {
            pool_id,
            output_address,
        } => Some(format!(
            "Produce a decommission request for pool {pool_id} paying to {output_address}?"
        )),
        WalletCommand::CreateOrder {
            ask_currency,
            ask_amount,
            give_currency,
            give_amount,
            conclude_address: _,
        } => Some(format!(
            "Create an order asking {ask_amount} {ask_currency} for {give_amount} {give_currency}?"
        )),
        WalletCommand::FillOrder { order_id, amount, .. } => {
            Some(format!("Fill order {order_id} with {amount}?"))
        }
        WalletCommand::FreezeOrder { order_id } => {
            Some(format!("Freeze order {order_id}?"))
        }
        WalletCommand::ConcludeOrder { order_id, .. } => {
            Some(format!("Conclude order {order_id}?"))
        }
        WalletCommand::CreateHtlcTx {
            currency,
            amount,
            ..
        } => Some(format!("Create an HTLC locking {amount} {currency}?")),
        WalletCommand::TransactionCompose { outputs, .. } => Some(format!(
            "Compose a transaction with {} output(s)?",
            outputs.len()
        )),
        WalletCommand::CreateTxFromColdInput {
            address,
            amount,
            ..
        } => Some(format!(
            "Compose a cold-input transaction sending {amount} to {address}? The result is not broadcast."
        )),
        WalletCommand::AbandonTransaction { transaction_id } => {
            Some(format!("Abandon transaction {transaction_id}?"))
        }
        WalletCommand::SubmitTransaction { transaction: _, do_not_store } => {
            let destination = if *do_not_store {
                "without storing it"
            } else {
                "and store it in the local mempool"
            };
            Some(format!("Submit the given transaction to the node {destination}?"))
        }
        WalletCommand::ColdCommands(command) => cold_wallet_confirmation(command),
        _ => None,
    }
}

fn cold_wallet_confirmation(command: &ColdWalletCommand) -> Option<String> {
    match command {
        ColdWalletCommand::PurgeSeedPhrase => Some(
            "Permanently delete the stored seed phrase from this wallet file? \
             This cannot be undone."
                .to_owned(),
        ),
        ColdWalletCommand::RemovePrivateKeysEncryption => Some(
            "Disable private key encryption? The private keys will be stored in plain text."
                .to_owned(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Client = node_comm::node_traits::MockNodeInterface;

    fn prompt(line: &str) -> Option<String> {
        let command = crate::parse_input::<Client>(
            line,
            &crate::build_repl_command(false, true),
        )
        .expect("grammar parse must not fail");
        confirmation_prompt(&command)
    }

    #[test]
    fn asset_moving_commands_ask_for_confirmation() {
        assert_eq!(
            prompt("address-send addr1 100").as_deref(),
            Some("Send 100 coins to addr1?")
        );
        assert_eq!(
            prompt("token-send 0x11 addr1 7").as_deref(),
            Some("Send 7 of token 0x11 to addr1?")
        );
        assert!(prompt("staking-create-pool 100 0 10 cold").is_some());
        assert!(prompt("delegation-stake 100 0x22").is_some());
        assert!(prompt("order-create coin 1 coin 2 addr").is_some());
    }

    #[test]
    fn read_only_commands_do_not_ask() {
        assert!(prompt("account-balance").is_none());
        assert!(prompt("address-new").is_none());
        assert!(prompt("staking-status").is_none());
    }

    #[test]
    fn destructive_wallet_commands_ask() {
        assert!(prompt("wallet-purge-seed-phrase").is_some());
        assert!(prompt("wallet-disable-private-keys-encryption").is_some());
    }
}
