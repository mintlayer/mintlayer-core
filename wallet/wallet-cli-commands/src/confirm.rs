// Copyright (c) 2024 RBB S.r.l
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

use crate::{
    ColdWalletCommand, ManageableWalletCommand, WalletCommand, WalletGroupSubCommand,
    helper_types::CliCurrency,
};

/// Returns the confirmation question for a state-changing command, or `None`
/// when the command can run without asking.
pub fn confirmation_prompt(command: &ManageableWalletCommand) -> Option<String> {
    match command {
        ManageableWalletCommand::WalletCommands(command) => {
            // The gate must not depend on the spelling: translate the nested
            // groups to their legacy forms first, so `send 1 addr` and
            // `address-send 1 addr` classify identically.
            let normalized =
                crate::command_handler::normalize_nested_wallet_command(command.clone());
            wallet_confirmation(&normalized)
        }
        ManageableWalletCommand::ManagementCommands(_) => None,
    }
}

fn wallet_confirmation(command: &WalletCommand) -> Option<String> {
    match command {
        WalletCommand::ConfigBroadcast { broadcast } => {
            let broadcast = broadcast.to_bool();
            Some(format!(
                "Set automatic broadcasting of created transactions to {broadcast}?"
            ))
        }
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
        WalletCommand::DepositData { hex_data } => Some(format!(
            "Store {} bytes of data on the chain?",
            hex_data.len() / 2
        )),
        WalletCommand::IssueNewNft {
            destination_address: _,
            media_hash: _,
            name,
            ..
        } => Some(format!("Issue the NFT \"{name}\"?")),
        WalletCommand::IssueNewToken { token_ticker, .. } => {
            Some(format!("Issue the token {token_ticker}?"))
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
        WalletCommand::StartStaking => Some("Start staking?".to_owned()),
        WalletCommand::StopStaking => Some("Stop staking?".to_owned()),
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
            "Create an order asking {ask_amount} {} for {give_amount} {}?",
            describe_currency(ask_currency),
            describe_currency(give_currency)
        )),
        WalletCommand::FillOrder {
            order_id, amount, ..
        } => Some(format!("Fill order {order_id} with {amount}?")),
        WalletCommand::FreezeOrder { order_id } => Some(format!("Freeze order {order_id}?")),
        WalletCommand::ConcludeOrder { order_id, .. } => {
            Some(format!("Conclude order {order_id}?"))
        }
        WalletCommand::CreateHtlcTx {
            currency, amount, ..
        } => Some(format!(
            "Create an HTLC locking {amount} {}?",
            describe_currency(currency)
        )),
        WalletCommand::TransactionCompose { outputs, .. } => Some(format!(
            "Compose a transaction with {} output(s)?",
            outputs.len()
        )),
        WalletCommand::CreateTxFromColdInput {
            address, amount, ..
        } => Some(format!(
            "Compose a cold-input transaction sending {amount} to {address}? The result is not broadcast."
        )),
        WalletCommand::AbandonTransaction { transaction_id } => {
            Some(format!("Abandon transaction {transaction_id}?"))
        }
        WalletCommand::SubmitTransaction {
            transaction: _,
            do_not_store,
        } => {
            let destination = if *do_not_store {
                "without storing it"
            } else {
                "and store it in the local mempool"
            };
            Some(format!(
                "Submit the given transaction to the node {destination}?"
            ))
        }
        WalletCommand::Wallet { command } => match command {
            WalletGroupSubCommand::PurgeSeedPhrase => {
                cold_wallet_confirmation(&ColdWalletCommand::PurgeSeedPhrase)
            }
            WalletGroupSubCommand::Decrypt => {
                cold_wallet_confirmation(&ColdWalletCommand::RemovePrivateKeysEncryption)
            }
            WalletGroupSubCommand::Encrypt { password_file: _ } => {
                Some(encrypt_private_keys_question())
            }
            WalletGroupSubCommand::Unlock { password_file: _ } => {
                Some(unlock_private_keys_question())
            }
            WalletGroupSubCommand::SetLookaheadSize { .. } => Some(set_lookahead_size_question()),
            WalletGroupSubCommand::Info
            | WalletGroupSubCommand::Lock
            | WalletGroupSubCommand::ShowSeedPhrase
            | WalletGroupSubCommand::Create { .. }
            | WalletGroupSubCommand::Recover { .. }
            | WalletGroupSubCommand::Open { .. }
            | WalletGroupSubCommand::Close => None,
        },
        WalletCommand::CreateDelegation { owner: _, pool_id } => {
            Some(format!("Delegate to stake pool {pool_id}?"))
        }
        WalletCommand::SpendUtxo {
            utxo,
            address,
            htlc_secret: _,
        } => Some(format!(
            "Spend the outpoint {utxo:?} (source and output index) to {address}?"
        )),
        WalletCommand::ColdCommands(command) => cold_wallet_confirmation(command),
        _ => None,
    }
}

fn describe_currency(currency: &CliCurrency) -> String {
    match currency {
        CliCurrency::Coin => "coins".to_owned(),
        CliCurrency::Token(token_id) => format!("token {token_id}"),
    }
}

fn encrypt_private_keys_question() -> String {
    "Encrypt the private keys stored in this wallet file?".to_owned()
}

fn unlock_private_keys_question() -> String {
    "Decrypt the private keys in memory so they can sign transactions?".to_owned()
}

fn set_lookahead_size_question() -> String {
    "Change the lookahead size? Reducing it can make addresses beyond the new size \
     invisible to this wallet."
        .to_owned()
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
        ColdWalletCommand::EncryptPrivateKeys { password: _ } => {
            Some(encrypt_private_keys_question())
        }
        ColdWalletCommand::UnlockPrivateKeys { password: _ } => {
            Some(unlock_private_keys_question())
        }
        ColdWalletCommand::SetLookaheadSize {
            lookahead_size: _,
            i_know_what_i_am_doing: _,
        } => Some(set_lookahead_size_question()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Client = node_comm::node_traits::MockNodeInterface;

    fn prompt(line: &'static str) -> Option<String> {
        crate::run_with_large_stack(move || {
            let command =
                crate::parse_input::<Client>(line, &crate::build_repl_command(false, true))
                    .expect("grammar parse must not fail")
                    .expect("test lines parse to a command");
            confirmation_prompt(&command)
        })
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

    #[test]
    fn nested_spellings_are_classified_the_same_as_legacy_ones() {
        assert_eq!(
            prompt("send addr1 100").as_deref(),
            prompt("address-send addr1 100").as_deref()
        );
        assert_eq!(
            prompt("wallet purge-seed-phrase").as_deref(),
            prompt("wallet-purge-seed-phrase").as_deref()
        );
        assert_eq!(
            prompt("wallet decrypt").as_deref(),
            prompt("wallet-disable-private-keys-encryption").as_deref()
        );
        assert!(prompt("delegation-create owner1 pool1").is_some());
        assert!(prompt(
            "utxo-spend tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) addr1",
        )
        .is_some());
        assert!(prompt("data deposit deadbeef").is_some());
        assert!(prompt("config broadcast no").is_some());
        assert!(prompt("transaction abandon 1111111111111111111111111111111111111111111111111111111111111111").is_some());
        assert_eq!(
            prompt("wallet encrypt").as_deref(),
            prompt("wallet-encrypt-private-keys secret").as_deref()
        );
        assert_eq!(
            prompt("wallet unlock").as_deref(),
            prompt("wallet-unlock-private-keys secret").as_deref()
        );
        assert_eq!(
            prompt("wallet set-lookahead-size 1000").as_deref(),
            prompt("wallet-set-lookahead-size 1000 i-know-what-i-am-doing").as_deref()
        );
    }
}
