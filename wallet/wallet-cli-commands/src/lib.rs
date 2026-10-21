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

mod command_handler;
pub mod confirm;
mod errors;
mod helper_types;
pub mod output;
pub mod wizard;

use std::{collections::BTreeMap, fmt::Debug, num::NonZeroUsize, path::PathBuf, time::Duration};

use clap::{Command, FromArgMatches, Parser, Subcommand, ValueEnum};
use dyn_clone::DynClone;
use regex::Regex;

use helper_types::CliYesNo;

use common::{
    chain::{Block, SignedTransaction, Transaction},
    primitives::{BlockHeight, DecimalAmount, Id},
};
use crypto::key::{PrivateKey, PublicKey, hdkd::u31::U31};
use p2p_types::{PeerId, bannable_address::BannableAddress};
use rpc::description::{Described, Module};
use serialization::hex_encoded::HexEncoded;
use utils_networking::IpOrSocketAddress;
use wallet_controller::types::WalletTypeArgs;
#[cfg(feature = "trezor")]
use wallet_rpc_lib::types::FoundDevice;
use wallet_rpc_lib::{ColdWalletRpcDescription, WalletRpcDescription, types::NodeInterface};

use crate::helper_types::{
    CliCurrency, CliOutputTimeLock, CliTokenTotalSupply, CliUnspecifiedCurrencyTransfer,
    CliUtxoOutPoint,
};

use self::helper_types::{
    CliEnableOrDisable, CliForceReduceLookaheadSize, CliIsFreezable, CliIsUnfreezable,
    CliStoreSeedPhrase, CliTokenTransfer, CliUtxoState, CliUtxoTypes, CliWithLocked,
};

pub use command_handler::CommandHandler;
pub use errors::WalletCliCommandError;

#[derive(Debug, Subcommand, Clone)]
pub enum CreateWalletSubCommand {
    /// Create a software wallet
    #[command()]
    Software {
        /// File path of the wallet file
        wallet_path: PathBuf,

        /// Specifies whether the seed phrase should be stored in the wallet file or
        /// only printed on the screen.
        ///
        /// Not storing the seed phrase can be seen as a security measure
        /// to ensure sufficient secrecy in case that the seed phrase is reused
        /// elsewhere if this wallet is compromised.
        ///
        /// Note: if you decide to store the seed phrase, consider encrypting the wallet with
        /// the wallet-encrypt-private-keys command, which will also encrypt the seed phrase.
        whether_to_store_seed_phrase: CliStoreSeedPhrase,

        /// Mnemonic (seed) phrase (12, 15, or 24 words as a single quoted argument).
        ///
        /// If not specified, a new mnemonic phrase will be generated and printed.
        mnemonic: Option<String>,

        /// Passphrase along the mnemonic
        #[arg(long = "passphrase")]
        passphrase: Option<String>,
    },
    /// (Beta) Create a wallet using a connected Trezor hardware wallet.
    ///
    /// Only the public keys will be kept in the wallet file.
    ///
    /// Cannot specify a mnemonic or passphrase here, the mnemonic must have been entered on
    /// the device during its initial setup and the passphrase will have to be entered every
    /// time the device is connected to the host machine.
    #[cfg(feature = "trezor")]
    #[command()]
    Trezor {
        /// File path of the wallet file
        wallet_path: PathBuf,

        /// Optionally specify the ID for the Trezor device to connect to in case there
        /// are multiple Trezor devices connected at the same time.
        ///
        /// If not specified and if there are multiple devices connected, a choice will be presented.
        #[arg(long)]
        device_id: Option<String>,
    },
    /// (Beta) Create a wallet using a connected Ledger wallet.
    ///
    /// Only the public keys will be kept in the wallet file.
    ///
    /// Cannot specify a mnemonic or passphrase here, both are managed on the device.
    /// Depending on its configuration, the passphrase may need to be entered manually
    /// each time or may be applied automatically after unlocking with a secondary PIN.
    #[cfg(feature = "ledger")]
    #[command()]
    Ledger {
        /// File path of the wallet file
        wallet_path: PathBuf,
    },
}

impl CreateWalletSubCommand {
    pub fn into_path_and_wallet_args(self) -> (PathBuf, WalletTypeArgs) {
        match self {
            Self::Software {
                wallet_path,
                whether_to_store_seed_phrase,
                mnemonic,
                passphrase,
            } => {
                let store_seed_phrase = whether_to_store_seed_phrase.into();
                (
                    wallet_path,
                    WalletTypeArgs::Software {
                        mnemonic,
                        passphrase,
                        store_seed_phrase,
                    },
                )
            }

            #[cfg(feature = "trezor")]
            Self::Trezor {
                wallet_path,
                device_id,
            } => (wallet_path, WalletTypeArgs::Trezor { device_id }),

            #[cfg(feature = "ledger")]
            Self::Ledger { wallet_path } => (wallet_path, WalletTypeArgs::Ledger),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum RecoverWalletSubCommand {
    /// Recover a software wallet
    #[command()]
    Software {
        /// File path of the wallet file
        wallet_path: PathBuf,

        /// Specifies whether the seed phrase should be stored in the wallet file or
        /// only printed on the screen.
        ///
        /// Not storing the seed phrase can be seen as a security measure
        /// to ensure sufficient secrecy in case that the seed phrase is reused
        /// elsewhere if this wallet is compromised.
        ///
        /// Note: if you decide to store the seed phrase, consider encrypting the wallet with
        /// the wallet-encrypt-private-keys command, which will also encrypt the seed phrase.
        whether_to_store_seed_phrase: CliStoreSeedPhrase,

        /// Mnemonic (seed) phrase (12, 15, or 24 words as a single quoted argument).
        mnemonic: String,

        /// Passphrase along the mnemonic
        #[arg(long = "passphrase")]
        passphrase: Option<String>,
    },
    /// (Beta) Recover a wallet using a connected Trezor hardware wallet.
    ///
    /// Only the public keys will be kept in the wallet file.
    ///
    /// Cannot specify a mnemonic or passphrase here, the mnemonic must have been entered on
    /// the device during its initial setup and the passphrase will have to be entered every
    /// time the device is connected to the host machine.
    #[cfg(feature = "trezor")]
    #[command()]
    Trezor {
        /// File path of the wallet file
        wallet_path: PathBuf,

        /// Optionally specify the ID for the Trezor device to connect to in case there
        /// are multiple Trezor devices connected at the same time.
        ///
        /// If not specified and if there are multiple devices connected, a choice will be presented.
        #[arg(long)]
        device_id: Option<String>,
    },
    /// (Beta) Recover a wallet using a connected Ledger hardware wallet.
    ///
    /// Only the public keys will be kept in the wallet file.
    ///
    /// Cannot specify a mnemonic or passphrase here, both are managed on the device.
    /// Depending on its configuration, the passphrase may need to be entered manually
    /// each time or may be applied automatically after unlocking with a secondary PIN.
    #[cfg(feature = "ledger")]
    #[command()]
    Ledger {
        /// File path of the wallet file
        wallet_path: PathBuf,
    },
}

impl RecoverWalletSubCommand {
    pub fn into_path_and_wallet_args(self) -> (PathBuf, WalletTypeArgs) {
        match self {
            Self::Software {
                wallet_path,
                whether_to_store_seed_phrase,
                mnemonic,
                passphrase,
            } => {
                let store_seed_phrase = whether_to_store_seed_phrase.into();
                (
                    wallet_path,
                    WalletTypeArgs::Software {
                        mnemonic: Some(mnemonic),
                        passphrase,
                        store_seed_phrase,
                    },
                )
            }

            #[cfg(feature = "trezor")]
            Self::Trezor {
                wallet_path,
                device_id,
            } => (wallet_path, WalletTypeArgs::Trezor { device_id }),

            #[cfg(feature = "ledger")]
            Self::Ledger { wallet_path } => (wallet_path, WalletTypeArgs::Ledger),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum OpenWalletSubCommand {
    /// Open a software wallet
    #[command()]
    Software {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,
        /// Force change the wallet type from hot to cold or from cold to hot
        #[arg(long)]
        force_change_wallet_type: bool,
    },
    /// (Beta) Open a wallet file that is connected to a Trezor hardware wallet.
    #[cfg(feature = "trezor")]
    #[command()]
    Trezor {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,

        /// Optionally specify the ID for the Trezor device to connect to in case there
        /// are multiple Trezor devices connected at the same time.
        ///
        /// If not specified and if there are multiple devices connected, a choice will be presented.
        #[arg(long)]
        device_id: Option<String>,
    },

    /// (Beta) Open a wallet file that is connected to a Ledger hardware wallet.
    #[cfg(feature = "ledger")]
    #[command()]
    Ledger {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,
    },
}

/// The nested wallet management grammar: `wallet create|recover|open|close`.
/// Each subcommand delegates to the same implementation as its flat legacy
/// counterpart (`wallet-create`, `wallet-recover`, ...).
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum WalletGroupSubCommand {
    /// Create a new wallet. This will create a new file without scanning the blockchain.
    Create {
        #[command(subcommand)]
        wallet: CreateWalletSubCommand,
    },
    /// Recover a wallet. This will create a new wallet file and scan the blockchain for
    /// associated transactions.
    Recover {
        #[command(subcommand)]
        wallet: RecoverWalletSubCommand,
    },
    /// Open an existing wallet file.
    Open {
        #[command(subcommand)]
        wallet: OpenWalletSubCommand,
    },
    /// Close the wallet.
    Close,
    /// Show info about the currently open wallet.
    Info,
    /// Encrypt the private keys of the wallet with a password.
    ///
    /// The password is read from the file given by `--password-file` (`-` for
    /// standard input); it is never passed as a command line argument. When
    /// the option is omitted on a terminal, the password is read with a
    /// hidden prompt and must be entered twice.
    Encrypt {
        /// File containing the new encryption password, or `-` for standard input.
        #[arg(long = "password-file")]
        password_file: Option<String>,
    },
    /// Unlock the encrypted private keys of the wallet with the encryption password.
    ///
    /// The password is read from the file given by `--password-file` (`-` for
    /// standard input); it is never passed as a command line argument. When
    /// the option is omitted on a terminal, the password is read with a
    /// hidden prompt.
    Unlock {
        /// File containing the current encryption password, or `-` for standard input.
        #[arg(long = "password-file")]
        password_file: Option<String>,
    },
    /// Remove the encryption from the private keys of the wallet.
    Decrypt,
    /// Lock the encrypted private keys of the wallet again.
    Lock,
    /// Show the seed phrase of the wallet.
    ShowSeedPhrase,
    /// Remove the seed phrase from the wallet permanently.
    PurgeSeedPhrase,
    /// Set the lookahead size of the wallet.
    SetLookaheadSize {
        /// The new lookahead size
        lookahead_size: u32,
        /// Force the reduction of the lookahead size even below the last used address;
        /// this may cause the wallet to lose track of used addresses and its actual balance.
        #[arg(long = "force")]
        force: bool,
    },
}

/// The nested account grammar: `account create|rename|select|utxos|balance|show-xpub`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum AccountGroupSubCommand {
    /// Create a new account.
    Create { name: Option<String> },
    /// Rename the selected account.
    Rename { name: Option<String> },
    /// Switch to a given wallet account.
    Select { account_index: U31 },
    /// List the utxos of the selected account.
    Utxos {
        /// The type of utxos to be listed.
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        /// Whether to include locked outputs.
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of the utxos.
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },
    /// Show the balance of the selected account.
    Balance {
        /// Whether to include locked outputs (outputs that cannot be spend and need time to
        /// mature)
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of utxos to be included (confirmed, unconfirmed, etc)
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },
    /// Show the extended public key of the selected account as hex.
    ShowXpub,
}

/// The encoding of a revealed public key.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum CliPublicKeyFormat {
    Hex,
    Address,
}

/// The nested standalone address grammar:
/// `address standalone rename-label|add|add-private-key|add-multisig|list|details|utxos`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum StandaloneGroupSubCommand {
    /// Rename the label of an existing standalone address; omitting --label removes it.
    RenameLabel {
        /// The existing standalone address
        address: String,
        /// Optionally specify a new label, not specifying a label will remove the existing one
        #[arg(long = "label")]
        label: Option<String>,
    },
    /// Add a new standalone watch only address to the selected account.
    Add {
        /// The new standalone watch only address to be added to the selected account
        address: String,
        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,
        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },
    /// Add a new hex-encoded standalone private key to the selected account.
    AddPrivateKey {
        /// The new hex-encoded standalone private key to be added to the selected account
        hex_private_key: HexEncoded<PrivateKey>,
        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,
        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },
    /// Create a new standalone multisig address.
    AddMultisig {
        /// The minimum required signatures out of the specified public keys
        min_required_signatures: u8,
        /// Public keys from which to create the multisig challenge
        public_keys: Vec<String>,
        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,
        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },
    /// List the standalone addresses of the selected account.
    List,
    /// Show the details of a standalone address.
    Details {
        /// The standalone address to inspect
        address: String,
    },
    /// List the utxos owned by the standalone multisig addresses.
    Utxos {
        /// The type of utxos to be listed.
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        /// Whether to include locked outputs.
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of the utxos.
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },
}

/// The nested address grammar:
/// `address new|list|qr|reveal-public-key|sweep|standalone`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum AddressGroupSubCommand {
    /// Generate a new address.
    New,
    /// List the wallet addresses.
    List {
        /// Include the change addresses along with the receiving addresses
        #[arg(long = "include-change")]
        include_change: bool,
    },
    /// Show a QR code of the provided address.
    Qr { address: String },
    /// Reveal the public key behind the specified "public key hash" address.
    RevealPublicKey {
        public_key_hash: String,
        /// The encoding of the revealed key (default: address).
        /// Note that the address encoding isn't a normal address to be used in transactions.
        /// It's preferred to take the address from `address list`.
        #[arg(long = "format", value_enum, default_value_t = CliPublicKeyFormat::Address)]
        format: CliPublicKeyFormat,
    },
    /// Sweep all spendable coins or tokens from the specified (or all) addresses to the
    /// given destination address.
    Sweep {
        /// The receiving address of the coins or tokens
        destination_address: String,
        /// The addresses to be swept. Mutually exclusive with --all.
        ///
        /// If --all is not specified, this has to contain at least one address.
        #[arg(required_unless_present("all"))]
        addresses: Vec<String>,
        /// Sweep all addresses
        #[arg(long = "all", conflicts_with_all(["addresses"]))]
        all: bool,
    },
    /// Manage standalone (non-account) addresses.
    Standalone {
        #[command(subcommand)]
        command: StandaloneGroupSubCommand,
    },
}

/// The nested data carrier grammar: `data deposit`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum DataGroupSubCommand {
    /// Deposit arbitrary data on the blockchain.
    Deposit {
        /// The data to be deposited on the blockchain as hex. DO NOT start the data with 0x.
        hex_data: String,
    },
}

/// The nested staking grammar: `staking create-pool|decommission-pool|...`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum StakingGroupSubCommand {
    /// Generate a new VRF public key for staking
    NewVrfPublicKey,
    /// Show the VRF public keys of the selected account
    ShowVrfPublicKeys,
    /// Show the legacy VRF key of the selected account
    ShowLegacyVrfKey,
    /// Create a new staking pool
    CreatePool {
        /// The amount to be pledged to the pool. There is a minimum to be accepted.
        amount: DecimalAmount,
        /// An amount in coins to be subtracted from the total rewards in a block and
        /// handed to the staker as a constant/fixed cost for running the pool.
        cost_per_block: DecimalAmount,
        /// After subtracting "cost per block" from the reward, this ratio is taken from
        /// the rewards and handed to the staker, written as a percentage with per-mille
        /// accuracy (0.1% is valid and equivalent to 0.001).
        margin_ratio_per_thousand: String,
        /// The key that can decommission the pool. It's recommended to keep the
        /// decommission key in cold storage.
        decommission_address: String,
        /// The key that will sign new blocks; leave it empty if the current wallet
        /// will be the staking wallet.
        staker_address: Option<String>,
        /// The VRF key used to produce PoS hashes during staking; leave it empty if
        /// the current wallet will be the staking wallet.
        vrf_public_key: Option<String>,
    },
    /// Decommission a staking pool owned by the selected account
    DecommissionPool {
        /// The pool id of the pool to be decommissioned.
        pool_id: String,
        /// The address that will receive the staker's balance.
        output_address: String,
    },
    /// Create a decommission request transaction without broadcasting it
    DecommissionPoolRequest {
        /// The pool id of the pool to be decommissioned.
        pool_id: String,
        /// The address that will receive the staker's balance.
        output_address: String,
    },
    /// Start staking with the selected account
    Start,
    /// Stop staking with the selected account
    Stop,
    /// Show the staking status of the selected account
    Status,
    /// List all staking pools
    ListPools,
    /// List the pools owned by the selected account that can be decommissioned
    ListOwnedPoolsForDecommission,
    /// List the block ids created by the selected account
    ListCreatedBlocks,
    /// Show the balance of a staking pool
    PoolBalance { pool_id: String },
}

/// The nested delegation grammar: `delegation create|list|stake|withdraw|sweep`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum DelegationGroupSubCommand {
    /// Create a delegation to a staking pool
    Create {
        /// The address, that will have the authority to sign withdrawals from the delegation.
        owner: String,
        /// The pool id of the pool that will get the delegation and stake the coins.
        pool_id: String,
    },
    /// List the delegation ids of the selected account
    List,
    /// Add coins to a delegation
    Stake {
        /// The amount to be delegated for staking.
        amount: DecimalAmount,
        /// The delegation id.
        delegation_id: String,
    },
    /// Withdraw coins from a delegation
    Withdraw {
        /// The address that will be receiving the coins
        address: String,
        /// The amount that will be taken away from the delegation
        amount: DecimalAmount,
        /// The delegation id, from which the delegated coins will be taken
        delegation_id: String,
    },
    /// Move all spendable delegation coins to an address
    Sweep {
        /// The receiving address of the coins
        destination_address: String,
        /// The delegation to be swept
        delegation_id: String,
    },
}

/// The nested NFT grammar: `token nft issue`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum NftGroupSubCommand {
    /// Issue a new NFT
    Issue {
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
        /// The owner, represented by a public key (hex-encoded)
        creator: Option<HexEncoded<PublicKey>>,
        /// URI for the icon of the NFT
        icon_uri: Option<String>,
        /// URI of the media
        media_uri: Option<String>,
        /// URI of the additional metadata
        additional_metadata_uri: Option<String>,
    },
}

/// The nested token grammar: `token issue|nft|change-authority|mint|...`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum TokenGroupSubCommand {
    /// Issue a new token
    Issue {
        token_ticker: String,
        number_of_decimals: u8,
        metadata_uri: String,
        authority_address: String,
        token_supply: CliTokenTotalSupply,
        is_freezable: CliIsFreezable,
    },
    /// NFT operations
    Nft {
        #[command(subcommand)]
        command: NftGroupSubCommand,
    },
    /// Change the authority of a token
    ChangeAuthority {
        /// The token id of the token.
        token_id: String,
        /// The address of the new authority.
        address: String,
    },
    /// Change the metadata uri of a token
    ChangeMetadataUri {
        /// The token id of the token.
        token_id: String,
        /// The new metadata uri.
        metadata_uri: String,
    },
    /// Mint tokens
    Mint {
        /// The token id of the tokens to be minted.
        token_id: String,
        /// The receiving address of the minted tokens.
        address: String,
        /// The amount to be minted.
        amount: DecimalAmount,
    },
    /// Unmint tokens
    Unmint {
        /// The token id of the tokens to be unminted.
        token_id: String,
        /// The amount to be unminted.
        amount: DecimalAmount,
    },
    /// Lock the supply of a token
    LockSupply {
        /// The token id of the token whose supply will be locked.
        token_id: String,
    },
    /// Freeze a token
    Freeze {
        /// The token id of the token to be frozen.
        token_id: String,
        /// Whether these tokens can be unfrozen again, or permanently frozen.
        is_unfreezable: CliIsUnfreezable,
    },
    /// Unfreeze a token
    Unfreeze {
        /// The token id of the token to be unfrozen.
        token_id: String,
    },
    /// Send tokens to an address
    Send {
        token_id: String,
        address: String,
        amount: DecimalAmount,
    },
}

/// The nested order grammar: `order create|fill|freeze|conclude|list-own|list-all-active`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum OrderGroupSubCommand {
    /// Create an order for exchanging currencies
    Create {
        /// The currency you are asking for - a token id or "coin" for coins.
        ask_currency: CliCurrency,
        /// The asked amount.
        ask_amount: DecimalAmount,
        /// The currency you will be giving - a token id or "coin" for coins.
        give_currency: CliCurrency,
        /// The given amount.
        give_amount: DecimalAmount,
        /// The address that can authorize the conclusion and freezing of the order.
        conclude_address: String,
    },
    /// Fill an order
    Fill {
        /// The id of the order to fill.
        order_id: String,
        /// The amount of the "asked" currency to fill the order with.
        amount: DecimalAmount,
        /// The address that receives the "given" currency; a new receive address is
        /// generated if not specified.
        output_address: Option<String>,
    },
    /// Freeze an order
    Freeze {
        /// The id of the order to freeze.
        order_id: String,
    },
    /// Conclude an order
    Conclude {
        /// The id of the order to conclude.
        order_id: String,
        /// The address that receives the accumulated amounts; a new receive address
        /// is generated if not specified.
        output_address: Option<String>,
    },
    /// List orders owned by the selected account
    ListOwn,
    /// List all active orders
    ListAllActive {
        /// Filter orders by the specified "asked" currency.
        #[arg(long = "ask-currency")]
        ask_currency: Option<CliCurrency>,
        /// Filter orders by the specified "given" currency.
        #[arg(long = "give-currency")]
        give_currency: Option<CliCurrency>,
    },
}

/// The nested htlc grammar: `htlc create|generate-secret|calc-secret-hash`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum HtlcGroupSubCommand {
    /// Create a transaction with an HTLC output without broadcasting it
    Create {
        /// The currency to lock inside the HTLC - a token id or "coin" for coins.
        currency: CliCurrency,
        /// The amount to lock inside the HTLC.
        amount: DecimalAmount,
        /// Hex-encoded hash of the HTLC secret.
        secret_hash: String,
        /// The address that can spend the HTLC providing the secret.
        spend_address: String,
        /// The refund timelock, e.g. block_count(720) or until_time(RFC 3339).
        refund_timelock: CliOutputTimeLock,
        /// The address that can refund the HTLC after the refund timelock expires.
        refund_address: String,
    },
    /// Generate a new HTLC secret
    GenerateSecret,
    /// Calculate the hash of an HTLC secret
    CalcSecretHash { secret: String },
}

/// The nested transaction grammar: `transaction compose|abandon|get|...`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum TransactionGroupSubCommand {
    /// Compose a transaction from outputs without broadcasting it
    Compose {
        /// The transaction outputs, in the format `transfer(address,amount)`.
        outputs: Vec<CliUnspecifiedCurrencyTransfer>,
        /// Choose what utxos to spend (e.g. tx(<id>,1) or block(<id>,2)).
        #[arg(long = "utxos")]
        utxos: Vec<CliUtxoOutPoint>,
        /// Produce a "simple" transaction hex instead of a PartiallySignedTransaction.
        #[arg(long = "only-transaction")]
        only_transaction: bool,
    },
    /// Create a transaction from a cold wallet input
    CreateFromColdInput {
        /// The receiving address of the coins.
        address: String,
        /// The amount to be sent, in decimal format.
        amount: DecimalAmount,
        /// The utxo to spend, e.g. tx(<id>,1) or block(<id>,2).
        utxo: CliUtxoOutPoint,
        /// The change address; if not specified, the change returns to the input
        /// address.
        #[arg(long = "change")]
        change_address: Option<String>,
    },
    /// Sign a raw transaction or partially signed transaction with the wallet's keys.
    ///
    /// Intended for cold wallets; on a hot wallet this maps onto the cold wallet
    /// sign command and is rejected by the mode check.
    Sign {
        /// Hex-encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },
    /// Inspect a hex-encoded transaction
    Inspect {
        /// Hex-encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },
    /// Abandon a pending transaction
    Abandon {
        /// The id of the transaction to abandon, in hex.
        transaction_id: HexEncoded<Id<Transaction>>,
    },
    /// List pending transactions
    ListPending,
    /// List transactions by address
    ListByAddress {
        /// Address to filter by.
        address: Option<String>,
        /// Limit the number of printed transactions.
        #[arg(long = "limit", default_value_t = 100)]
        limit: usize,
    },
    /// Get a transaction by id
    Get {
        transaction_id: HexEncoded<Id<Transaction>>,
    },
    /// Get the raw hex of a transaction
    GetRaw {
        transaction_id: HexEncoded<Id<Transaction>>,
    },
    /// Get the raw hex of a signed transaction
    GetSignedRaw {
        transaction_id: HexEncoded<Id<Transaction>>,
    },
}

/// Commands for operating the node
#[derive(Subcommand, Clone, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum NodeGroupSubCommand {
    /// Show the version of the running node
    Version,
    /// Shut down the running node
    Shutdown,
    /// Enable or disable p2p networking in the node
    P2p {
        /// Whether to enable or disable p2p networking.
        enable: CliEnableOrDisable,
    },
    /// Submit a hex-encoded block to the node
    SubmitBlock {
        /// Hex-encoded block
        block: HexEncoded<Block>,
    },
    /// Submit a hex-encoded transaction to the node
    SubmitTransaction {
        /// Hex-encoded transaction.
        transaction: HexEncoded<SignedTransaction>,
        /// Do not store the transaction in the wallet
        #[arg(long = "do-not-store")]
        do_not_store: bool,
    },
    /// Show chainstate information of the running node
    ChainstateInfo,
    /// Show the best block id, height, and timestamp; pass flags to show a subset
    BestBlock {
        /// Show the best block id
        #[arg(long = "id")]
        id: bool,
        /// Show the best block height
        #[arg(long = "height")]
        height: bool,
        /// Show the best block timestamp
        #[arg(long = "timestamp")]
        timestamp: bool,
    },
    /// Show the block id at a given height
    BlockId {
        /// Block height
        height: BlockHeight,
    },
    /// Show a block by its id
    Block {
        /// Block id
        id: String,
    },
    /// Generate a block with the given transactions (regtest)
    GenerateBlock {
        /// Hex-encoded transactions to include in the block
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },
}

/// Commands for managing peers
#[derive(Subcommand, Clone, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum PeerGroupSubCommand {
    /// Connect to a peer
    Connect {
        /// The address of the peer to connect to
        address: IpOrSocketAddress,
    },
    /// Disconnect from a peer
    Disconnect {
        /// The id of the peer to disconnect from
        peer_id: PeerId,
    },
    /// Ban a peer address
    Ban {
        /// IP address to ban.
        address: BannableAddress,
        /// Duration of the ban, e.g. 1M (1 month) or "1y 3M 10d 6h 30m 45s"
        /// (1 year 3 months 10 days 6 hours 30 minutes 45 seconds).
        #[arg(value_parser(humantime::parse_duration))]
        duration: Duration,
    },
    /// Unban a peer address
    Unban {
        /// The address to unban
        address: BannableAddress,
    },
    /// List banned peer addresses
    Banned,
    /// List discouraged peer addresses
    Discouraged,
    /// Undiscourage a peer address
    Undiscourage {
        /// The address to undiscourage
        address: BannableAddress,
    },
    /// Show the number of connected peers
    Count,
    /// List connected peers
    List,
    /// Manage reserved peers
    Reserved {
        #[command(subcommand)]
        command: ReservedPeerGroupSubCommand,
    },
}

/// Commands for managing the reserved peer list
#[derive(Subcommand, Clone, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum ReservedPeerGroupSubCommand {
    /// List reserved peers
    List,
    /// Add a reserved peer
    Add {
        /// The address of the peer to reserve
        address: IpOrSocketAddress,
    },
    /// Remove a reserved peer
    Remove {
        /// The address of the peer to remove from the reserved list
        address: IpOrSocketAddress,
    },
}

/// The challenge grammar: `challenge sign|verify`, merging the hex and plain legacy
/// spellings behind a `--hex` flag.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum ChallengeGroupSubCommand {
    /// Sign a message with the private key of an address.
    Sign {
        /// The message to be signed (hex-encoded with `--hex`)
        message: String,
        /// Address with whose private key to sign the challenge
        address: String,
        /// Treat the message as hex-encoded instead of plain text
        #[arg(long = "hex")]
        hex: bool,
    },
    /// Verify a signed challenge against an address.
    Verify {
        /// The message that was signed (hex-encoded with `--hex`)
        message: String,
        /// Hex-encoded signed challenge
        signed_challenge: String,
        /// Address with whose private key the challenge was signed with
        address: String,
        /// Treat the message as hex-encoded instead of plain text
        #[arg(long = "hex")]
        hex: bool,
    },
}

/// The history grammar: `history print|clear`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum HistoryGroupSubCommand {
    /// Print command history for this execution.
    Print,
    /// Clear command history for this execution.
    Clear,
}

/// The configuration grammar: `config broadcast`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum ConfigGroupSubCommand {
    /// Configure broadcasting to Mempool to yes or no.
    ///
    /// If set to no, any command that creates a transaction will return it to the user
    /// and not submit it automatically. The transaction will need to be submitted
    /// manually with the command `node-submit-transaction`. The effect of this is not
    /// preserved when the CLI wallet is closed.
    Broadcast {
        #[arg(value_enum)]
        broadcast: CliYesNo,
    },
}

/// The commands that offer interactive argument collection through `wizard`.
#[derive(Debug, Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum WizardGroupSubCommand {
    /// Interactively create the `token issue` command line.
    TokenIssue,
    /// Interactively create the `token nft issue` command line.
    NftIssue,
    /// Interactively create the `staking create-pool` command line.
    PoolCreate,
    /// Interactively create the `order create` command line.
    OrderCreate,
    /// Interactively create the `htlc create` command line.
    HtlcCreate,
}

/// Mapping between the legacy flat command names and their nested equivalents.
/// The flat names remain first-class commands; this manifest documents the
/// correspondence and drives the grammar compatibility test.
pub const LEGACY_ALIASES: &[(&str, &str)] = &[
    ("wallet-create", "wallet create"),
    ("wallet-recover", "wallet recover"),
    ("wallet-open", "wallet open"),
    ("wallet-close", "wallet close"),
    ("account-create", "account create"),
    ("account-rename", "account rename"),
    ("account-select", "account select"),
    ("account-utxos", "account utxos"),
    ("account-balance", "account balance"),
    ("account-extended-public-key-as-hex", "account show-xpub"),
    ("address-new", "address new"),
    ("address-show", "address list"),
    ("address-qrcode", "address qr"),
    (
        "address-reveal-public-key-as-hex",
        "address reveal-public-key --format hex",
    ),
    (
        "address-reveal-public-key-as-address",
        "address reveal-public-key",
    ),
    ("address-send", "send"),
    ("address-sweep-spendable", "address sweep"),
    ("address-deposit-data", "data deposit"),
    (
        "standalone-address-label-rename",
        "address standalone rename-label",
    ),
    (
        "standalone-add-watch-only-address",
        "address standalone add",
    ),
    (
        "standalone-add-private-key-from-hex",
        "address standalone add-private-key",
    ),
    ("standalone-add-multisig", "address standalone add-multisig"),
    ("standalone-address-show", "address standalone list"),
    ("standalone-address-details", "address standalone details"),
    ("standalone-multisig-utxos", "address standalone utxos"),
    ("staking-new-vrf-public-key", "staking new-vrf-public-key"),
    (
        "staking-show-vrf-public-keys",
        "staking show-vrf-public-keys",
    ),
    ("staking-show-legacy-vrf-key", "staking show-legacy-vrf-key"),
    ("staking-create-pool", "staking create-pool"),
    ("staking-decommission-pool", "staking decommission-pool"),
    (
        "staking-decommission-pool-request",
        "staking decommission-pool-request",
    ),
    ("staking-start", "staking start"),
    ("staking-stop", "staking stop"),
    ("staking-status", "staking status"),
    ("staking-list-pools", "staking list-pools"),
    (
        "staking-list-owned-pools-for-decommission",
        "staking list-owned-pools-for-decommission",
    ),
    (
        "staking-list-created-block-ids",
        "staking list-created-blocks",
    ),
    ("staking-pool-balance", "staking pool-balance"),
    ("delegation-create", "delegation create"),
    ("delegation-list-ids", "delegation list"),
    ("delegation-stake", "delegation stake"),
    ("delegation-withdraw", "delegation withdraw"),
    ("staking-sweep-delegation", "delegation sweep"),
    ("token-issue-new", "token issue"),
    ("token-nft-issue-new", "token nft issue"),
    ("token-change-authority", "token change-authority"),
    ("token-change-metadata-uri", "token change-metadata-uri"),
    ("token-mint", "token mint"),
    ("token-unmint", "token unmint"),
    ("token-lock-supply", "token lock-supply"),
    ("token-freeze", "token freeze"),
    ("token-unfreeze", "token unfreeze"),
    ("token-send", "token send"),
    ("order-create", "order create"),
    ("order-fill", "order fill"),
    ("order-freeze", "order freeze"),
    ("order-conclude", "order conclude"),
    ("order-list-own", "order list-own"),
    ("order-list-all-active", "order list-all-active"),
    ("htlc-create-transaction", "htlc create"),
    ("htlc-generate-secret", "htlc generate-secret"),
    ("htlc-calc-secret-hash", "htlc calc-secret-hash"),
    ("transaction-compose", "transaction compose"),
    (
        "transaction-create-from-cold-input",
        "transaction create-from-cold-input",
    ),
    ("transaction-inspect", "transaction inspect"),
    ("transaction-abandon", "transaction abandon"),
    ("transaction-list-pending", "transaction list-pending"),
    ("transaction-list-by-address", "transaction list-by-address"),
    ("transaction-get", "transaction get"),
    ("transaction-get-raw", "transaction get-raw"),
    ("transaction-get-signed-raw", "transaction get-signed-raw"),
    ("node-version", "node version"),
    ("node-shutdown", "node shutdown"),
    ("node-enable-p2p-networking", "node p2p"),
    ("node-submit-block", "node submit-block"),
    ("node-submit-transaction", "node submit-transaction"),
    ("node-chainstate-info", "node chainstate-info"),
    ("node-best-block", "node best-block"),
    ("node-best-block-id", "node best-block --id"),
    ("node-best-block-height", "node best-block --height"),
    ("node-best-block-timestamp", "node best-block --timestamp"),
    ("wallet-info", "wallet info"),
    // wallet encrypt / unlock read the password from --password-file or stdin; the
    // legacy spellings keep the positional password (legacy parse shape).
    ("wallet-encrypt-private-keys", "wallet encrypt"),
    ("wallet-unlock-private-keys", "wallet unlock"),
    ("wallet-disable-private-keys-encryption", "wallet decrypt"),
    ("wallet-lock-private-keys", "wallet lock"),
    ("wallet-show-seed-phrase", "wallet show-seed-phrase"),
    ("wallet-purge-seed-phrase", "wallet purge-seed-phrase"),
    // The legacy set-lookahead-size consent enum maps to the --force flag.
    ("wallet-set-lookahead-size", "wallet set-lookahead-size"),
    ("account-sign-raw-transaction", "transaction sign"),
    ("challenge-sign-plain", "challenge sign"),
    ("challenge-sign-hex", "challenge sign --hex"),
    ("challenge-verify-plain", "challenge verify"),
    ("challenge-verify-hex", "challenge verify --hex"),
    ("history-print", "history print"),
    ("history-clear", "history clear"),
    ("screen-clear", "clear"),
    ("config-broadcast", "config broadcast"),
    ("node-block-id", "node block-id"),
    ("node-get-block", "node block"),
    ("node-generate-block", "node generate-block"),
    ("node-connect-to-peer", "peer connect"),
    ("node-disconnect-peer", "peer disconnect"),
    ("node-peer-count", "peer count"),
    ("node-list-connected-peers", "peer list"),
    ("node-list-banned-peers", "peer banned"),
    ("node-list-discouraged-peers", "peer discouraged"),
    ("node-ban-peer-address", "peer ban"),
    ("node-unban-peer-address", "peer unban"),
    ("node-undiscourage-peer-address", "peer undiscourage"),
    ("node-list-reserved-peers", "peer reserved list"),
    ("node-add-reserved-peer", "peer reserved add"),
    ("node-remove-reserved-peer", "peer reserved remove"),
];

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum WalletManagementCommand {
    /// Create a new wallet. This will create a new file without scanning the blockchain.
    ///
    /// Use this command if the seed phrase is brand new and has no associated transactions.
    ///
    /// If, on the other hand, the seed phrase has been used in the past and may have
    /// associated transactions, use wallet-recover instead.
    #[clap(name = "wallet-create")]
    CreateWallet {
        #[command(subcommand)]
        wallet: CreateWalletSubCommand,
    },

    /// Recover a wallet. This will create a new wallet file and scan the blockchain for associated
    /// transactions.
    ///
    /// Use this command if the seed phrase has been used in the past.
    ///
    /// If, on the other hand, the seed phrase is brand new, consider using wallet-create,
    /// which will save you some time (as scanning the entire blockchain is a lengthy process).
    #[clap(name = "wallet-recover")]
    RecoverWallet {
        #[command(subcommand)]
        wallet: RecoverWalletSubCommand,
    },

    /// Open an exiting wallet file.
    #[clap(name = "wallet-open")]
    OpenWallet {
        #[command(subcommand)]
        wallet: OpenWalletSubCommand,
    },

    #[clap(name = "wallet-close")]
    CloseWallet,

    /// Shutdown the RPC interface or the remote wallet it is connected to
    /// and exit the wallet
    RpcShutdownAndExit,

    /// Exit the wallet
    #[clap(visible_alias = "shutdown")]
    Exit,
}

#[derive(Debug, Clone, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum ColdWalletCommand {
    #[clap(name = "wallet-info")]
    WalletInfo,

    #[clap(name = "wallet-encrypt-private-keys")]
    EncryptPrivateKeys {
        /// The new encryption password
        ///
        /// Passing the password on the command line is insecure; the nested
        /// `wallet encrypt --password-file <file>` spelling reads it from a file
        /// instead.
        password: String,
    },

    #[clap(name = "wallet-disable-private-keys-encryption")]
    RemovePrivateKeysEncryption,

    #[clap(name = "wallet-unlock-private-keys")]
    UnlockPrivateKeys {
        /// The current encryption password.
        ///
        /// Passing the password on the command line is insecure; the nested
        /// `wallet unlock --password-file <file>` spelling reads it from a file
        /// instead.
        password: String,
    },

    #[clap(name = "wallet-lock-private-keys")]
    LockPrivateKeys,

    #[clap(name = "wallet-show-seed-phrase")]
    ShowSeedPhrase,

    #[clap(name = "wallet-purge-seed-phrase")]
    PurgeSeedPhrase,

    #[clap(name = "wallet-set-lookahead-size")]
    SetLookaheadSize {
        /// The new lookahead size
        lookahead_size: u32,

        /// Forces the reduction of lookahead size even below the last used address;
        /// this may cause the wallet to lose track of used addresses and its actual balance.
        i_know_what_i_am_doing: Option<CliForceReduceLookaheadSize>,
    },

    /// Creates a QR code of the provided address
    #[clap(name = "address-qrcode")]
    AddressQRCode {
        address: String,
    },

    #[clap(name = "address-new")]
    NewAddress,

    /// Reveal the public key behind the specified "public key hash" address as a hex-encoded string.
    #[clap(name = "address-reveal-public-key-as-hex")]
    RevealPublicKeyHex {
        public_key_hash: String,
    },

    /// Reveal the public key behind the specified "public key hash" address in address encoding.
    ///
    /// Note that this isn't a normal address to be used in transactions.
    /// It's preferred to take the address from address-show command
    #[clap(name = "address-reveal-public-key-as-address")]
    RevealPublicKey {
        public_key_hash: String,
    },

    #[clap(name = "address-show")]
    ShowAddresses {
        /// Include the change addresses along with the receiving addresses
        #[arg(long = "include-change")]
        include_change: bool,
    },

    #[clap(name = "standalone-address-show")]
    ShowStandaloneAddresses,

    #[clap(name = "standalone-address-details")]
    ShowStandaloneAddressDetails {
        address: String,
    },

    #[clap(name = "staking-new-vrf-public-key")]
    NewVrfPublicKey,

    #[clap(name = "staking-show-vrf-public-keys")]
    GetVrfPublicKey,

    #[clap(name = "staking-show-legacy-vrf-key")]
    GetLegacyVrfPublicKey,

    #[clap(name = "account-extended-public-key-as-hex")]
    AccountExtendedPublicKey,

    #[clap(name = "account-sign-raw-transaction")]
    SignRawTransaction {
        /// Hex-encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },

    #[clap(name = "challenge-sign-hex")]
    #[clap(hide = true)]
    SignChallegeHex {
        /// Hex-encoded message to be signed
        message: String,
        /// Address with whose private key to sign the challenge
        address: String,
    },

    #[clap(name = "challenge-sign-plain")]
    SignChallege {
        /// The message to be signed
        message: String,
        /// Address with whose private key to sign the challenge
        address: String,
    },

    #[clap(name = "challenge-verify-hex")]
    #[clap(hide = true)]
    VerifyChallengeHex {
        /// The hex-encoded message that was signed
        message: String,
        /// Hex-encoded signed challenge
        signed_challenge: String,
        /// Address with whose private key the challenge was signed with
        address: String,
    },

    #[clap(name = "challenge-verify-plain")]
    VerifyChallenge {
        /// The message that was signed
        message: String,
        /// Hex-encoded signed challenge
        signed_challenge: String,
        /// Address with whose private key the challenge was signed with
        address: String,
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

    /// Challenge signing and verification.
    #[clap(name = "challenge")]
    Challenge {
        #[command(subcommand)]
        command: ChallengeGroupSubCommand,
    },

    /// Command history.
    #[clap(name = "history")]
    History {
        #[command(subcommand)]
        command: HistoryGroupSubCommand,
    },

    /// Clear screen.
    #[clap(name = "clear")]
    Clear,

    Version,
}

#[derive(Debug, Clone, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum WalletCommand {
    #[command(flatten)]
    ColdCommands(ColdWalletCommand),

    /// Configure broadcasting to Mempool to yes or no.
    ///
    /// If set to no, any command that creates a transaction will return it to the user and not submit it automatically.
    /// The transaction will need to be submitted manually with the command `node-submit-transaction`.
    ///
    /// The effect of this is not preserved when the CLI wallet is closed.
    #[clap(name = "config-broadcast")]
    ConfigBroadcast {
        #[arg(value_enum)]
        broadcast: CliYesNo,
    },

    /// Configuration commands (broadcast).
    #[clap(name = "config")]
    Config {
        #[command(subcommand)]
        command: ConfigGroupSubCommand,
    },

    /// Collect the arguments of a complex command interactively.
    #[clap(name = "wizard")]
    Wizard {
        #[command(subcommand)]
        command: WizardGroupSubCommand,
    },

    /// Wallet management commands (create, recover, open, close).
    /// The flat commands (`wallet-create`, `wallet-recover`, ...) remain available.
    #[clap(name = "wallet")]
    Wallet {
        #[command(subcommand)]
        command: WalletGroupSubCommand,
    },

    /// Account commands (create, rename, select, utxos, balance, show-xpub).
    /// The flat commands (`account-create`, `account-utxos`, ...) remain available.
    #[clap(name = "account")]
    Account {
        #[command(subcommand)]
        command: AccountGroupSubCommand,
    },

    /// Address commands (new, list, qr, reveal-public-key, sweep, standalone).
    /// The flat commands (`address-new`, `address-show`, ...) remain available.
    #[clap(name = "address")]
    Address {
        #[command(subcommand)]
        command: AddressGroupSubCommand,
    },

    /// Send coins to an address (same as `address-send`).
    #[clap(name = "send")]
    Send {
        /// The receiving address of the coins
        address: String,
        /// The amount to be sent, in decimal format
        amount: DecimalAmount,
        /// You can choose what utxos to spend (space separated as additional arguments).
        /// A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        utxos: Vec<CliUtxoOutPoint>,
    },

    /// Data carrier commands (deposit).
    #[clap(name = "data")]
    Data {
        #[command(subcommand)]
        command: DataGroupSubCommand,
    },
    /// Staking pool operations
    #[clap(name = "staking")]
    Staking {
        #[command(subcommand)]
        command: StakingGroupSubCommand,
    },
    /// Delegation operations
    #[clap(name = "delegation")]
    Delegation {
        #[command(subcommand)]
        command: DelegationGroupSubCommand,
    },
    /// Token operations
    #[clap(name = "token")]
    Token {
        #[command(subcommand)]
        command: TokenGroupSubCommand,
    },
    /// Order operations
    #[clap(name = "order")]
    Order {
        #[command(subcommand)]
        command: OrderGroupSubCommand,
    },
    /// HTLC operations
    #[clap(name = "htlc")]
    Htlc {
        #[command(subcommand)]
        command: HtlcGroupSubCommand,
    },
    /// Node management commands
    #[clap(name = "node")]
    Node {
        #[command(subcommand)]
        command: NodeGroupSubCommand,
    },
    /// Peer management commands
    #[clap(name = "peer")]
    Peer {
        #[command(subcommand)]
        command: PeerGroupSubCommand,
    },
    /// Transaction operations
    #[clap(name = "transaction")]
    Transaction {
        #[command(subcommand)]
        command: TransactionGroupSubCommand,
    },

    /// Create a new account in the wallet.
    ///
    /// When no name is given the account stays unnamed; listings show it as
    /// `Account index: <n>, Name: None` and the status line as
    /// `(Account No. <n>)` until it is renamed.
    #[clap(name = "account-create")]
    CreateNewAccount { name: Option<String> },

    #[clap(name = "account-rename")]
    RenameAccount { name: Option<String> },

    /// Switch to a given wallet account.
    #[clap(name = "account-select")]
    SelectAccount { account_index: U31 },

    #[clap(name = "account-utxos")]
    ListUtxo {
        /// The type of utxos to be listed.
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        /// Whether to include locked outputs.
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of the utxos.
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    #[clap(name = "account-balance")]
    GetBalance {
        /// Whether to include locked outputs (outputs that cannot be spend and need time to mature)
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of utxos to be included (confirmed, unconfirmed, etc)
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    #[clap(name = "standalone-address-label-rename")]
    StandaloneAddressLabelRename {
        /// The existing standalone address
        address: String,

        /// Optionally specify a new label, not specifying a label will remove the existing one
        #[arg(long = "label")]
        label: Option<String>,
    },

    #[clap(name = "standalone-add-watch-only-address")]
    AddStandaloneKey {
        /// The new standalone watch only address to be added to the selected account
        address: String,

        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,

        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },

    #[clap(name = "standalone-add-private-key-from-hex")]
    AddStandalonePrivateKey {
        /// The new hex-encoded standalone private key to be added to the selected account
        hex_private_key: HexEncoded<PrivateKey>,

        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,

        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },

    #[clap(name = "standalone-add-multisig")]
    AddStandaloneMultisig {
        /// The minimum required signatures out of the specified public keys
        min_required_signatures: u8,

        /// Public keys from which to create the multisig challenge
        public_keys: Vec<String>,

        /// Optionally specify a label to the new address
        #[arg(long = "label")]
        label: Option<String>,

        /// Skip the rescanning of the blockchain
        #[arg(long = "no-rescan")]
        no_rescan: Option<bool>,
    },

    #[clap(name = "standalone-multisig-utxos")]
    ListMultisigUtxo {
        /// The type of utxos to be listed.
        #[arg(value_enum, default_value_t = CliUtxoTypes::All)]
        utxo_type: CliUtxoTypes,
        /// Whether to include locked outputs.
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of the utxos.
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

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
        /// The owner, represented by a public key (hex-encoded)
        creator: Option<HexEncoded<PublicKey>>,
        /// URI for the icon of the NFT
        icon_uri: Option<String>,
        /// URI of the media
        media_uri: Option<String>,
        /// URI of the additional metadata
        additional_metadata_uri: Option<String>,
    },

    #[clap(name = "token-issue-new")]
    IssueNewToken {
        /// The ticker/symbol of the token created
        token_ticker: String,

        /// The maximum number of digits after the decimal points
        number_of_decimals: u8,

        /// URI for data related to the token (website, media, etc)
        metadata_uri: String,

        /// The address of the authority who will be able to manage this token
        authority_address: String,

        /// The total supply of this token
        ///
        /// Valid values are "unlimited", "lockable" and "fixed(amount)"
        token_supply: CliTokenTotalSupply,

        /// Whether it's possible to centrally freeze this token for all users (due to migration requirements, for example)
        is_freezable: CliIsFreezable,
    },

    #[clap(name = "token-change-authority")]
    ChangeTokenAuthority { token_id: String, address: String },

    #[clap(name = "token-change-metadata-uri")]
    ChangeTokenMetadataUri {
        token_id: String,
        metadata_uri: String,
    },

    #[clap(name = "token-mint")]
    MintTokens {
        /// The token id of the tokens to be minted
        token_id: String,
        /// The receiving address of the minted tokens
        address: String,
        /// The amount to be minted
        amount: DecimalAmount,
    },

    #[clap(name = "token-unmint")]
    UnmintTokens {
        /// The token id of the tokens to be unminted
        token_id: String,
        /// The amount to be unminted
        amount: DecimalAmount,
    },

    #[clap(name = "token-lock-supply")]
    LockTokenSupply {
        /// The token id of the token, whose supply will be locked
        token_id: String,
    },

    #[clap(name = "token-freeze")]
    FreezeToken {
        /// The token id of the token to be frozen.
        token_id: String,
        /// Whether these tokens can be unfrozen again, or permanently freeze them.
        is_unfreezable: CliIsUnfreezable,
    },

    #[clap(name = "token-unfreeze")]
    UnfreezeToken {
        /// The token id of the token to be unfrozen.
        token_id: String,
    },

    #[clap(name = "token-send")]
    SendTokensToAddress {
        /// The token id of the tokens to be sent.
        token_id: String,
        /// The destination address receiving the tokens.
        address: String,
        /// The amount of tokens to be sent.
        amount: DecimalAmount,
    },

    #[clap(name = "token-make-tx-to-send-with-intent")]
    #[clap(hide = true)]
    MakeTxToSendTokensToAddressWithIntent {
        /// The token id of the tokens to be sent.
        token_id: String,
        /// The destination address receiving the tokens.
        address: String,
        /// The amount of tokens to be sent.
        amount: DecimalAmount,
        /// The message declaring the intent of the transaction.
        ///
        /// The signed intent will be printed separately, it's not a part of the transaction itself.
        intent: String,
    },

    /// Create a transaction for sending tokens from a multisig address to other addresses, returning the change to
    /// the original multisig address.
    ///
    /// The utxos to pay fees from will be selected automatically; these will be normal, single-sig utxos.
    /// The optional "fee change address" specifies the destination for the change for the fee payment;
    /// If it's unset, the destination will be taken from one of existing single-sig utxos.
    // TODO: as mentioned in another TODO for `TransactionCompose` below, we should have a more general
    // `CliCurrencyTransfer`, which would allow to specify either token or coin transfers. Once it's implemented,
    // it's better to generalize this command, so that it can perform coin transfers as well.
    #[clap(name = "token-make-tx-to-send-from-multisig-address")]
    #[clap(hide = true)]
    MakeTxToSendTokensFromMultisigAddress {
        /// The source multisig address; the change will be sent to it as well.
        from_address: String,

        /// An optional address to which the change for the fee payment should be sent to.
        #[arg(long = "fee-change-address")]
        fee_change_address: Option<String>,

        /// The transaction outputs, in the format `transfer(token_id,address,amount)`
        /// e.g. transfer(tmltk1e7egscactagl7e3met67658hpl4vf9ux0ralaculjvnzhtc4qmsqv9y857,tmt1q8lhgxhycm8e6yk9zpnetdwtn03h73z70c3ha4l7,0.9)
        outputs: Vec<CliTokenTransfer>,
    },

    #[clap(name = "address-send")]
    SendToAddress {
        /// The receiving address of the coins
        address: String,
        /// The amount to be sent, in decimal format
        amount: DecimalAmount,
        /// You can choose what utxos to spend (space separated as additional arguments).
        /// A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        utxos: Vec<CliUtxoOutPoint>,
    },

    /// Sweep all spendable coins or tokens from the specified (or all) addresses to the given destination address.
    ///
    /// Spendable coins are any coins that are not locked, and tokens that are not frozen or locked.
    /// The wallet will automatically calculate the required fees.
    #[clap(name = "address-sweep-spendable")]
    SweepFromAddress {
        /// The receiving address of the coins or tokens
        destination_address: String,
        /// The addresses to be swept. Mutually exclusive with --all.
        ///
        /// If --all is not specified, this has to contain at least one address.
        #[arg(required_unless_present("all"))]
        addresses: Vec<String>,
        /// Sweep all addresses
        #[arg(long = "all", conflicts_with_all(["addresses"]))]
        all: bool,
    },

    #[clap(name = "staking-sweep-delegation")]
    SweepFromDelegation {
        /// The receiving address of the coins
        destination_address: String,
        /// The delegation to be swept
        delegation_id: String,
    },

    #[clap(name = "transaction-create-from-cold-input")]
    CreateTxFromColdInput {
        /// The receiving address of the coins
        address: String,
        /// The amount to be sent, in decimal format
        amount: DecimalAmount,
        /// You can choose what utxo to spend. A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        utxo: CliUtxoOutPoint,
        /// Optional change address; if not specified, it returns the change to the same address from the input.
        #[arg(long = "change")]
        change_address: Option<String>,
    },

    #[clap(name = "transaction-inspect")]
    InspectTransaction {
        /// Hex-encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },

    #[clap(name = "address-deposit-data")]
    DepositData {
        /// The data to be deposited on the blockchain as hex. DO NOT start the data with 0x.
        hex_data: String,
    },

    #[clap(name = "delegation-create")]
    CreateDelegation {
        /// The address, that will have the authority to sign withdrawals from the delegation.
        owner: String,
        /// The pool id of the pool that will get the delegation and stake the coins.
        pool_id: String,
    },

    #[clap(name = "delegation-list-ids")]
    ListDelegationIds,

    #[clap(name = "delegation-stake")]
    DelegateStaking {
        /// The amount to be delegated for staking.
        amount: DecimalAmount,
        /// The delegation id.
        delegation_id: String,
    },

    #[clap(name = "delegation-withdraw")]
    WithdrawFromDelegation {
        /// The address that will be receiving the coins
        address: String,
        /// The amount that will be taken away from the delegation
        amount: DecimalAmount,
        /// The delegation id, from which the delegated coins will be taken
        delegation_id: String,
    },

    #[clap(name = "staking-list-pools")]
    ListPools,

    #[clap(name = "staking-list-owned-pools-for-decommission")]
    ListOwnedPoolsForDecommission,

    #[clap(name = "staking-start")]
    StartStaking,

    #[clap(name = "staking-stop")]
    StopStaking,

    #[clap(name = "staking-status")]
    StakingStatus,

    #[clap(name = "staking-pool-balance")]
    StakePoolBalance { pool_id: String },

    #[clap(name = "staking-list-created-block-ids")]
    ListCreatedBlocksIds,

    #[clap(name = "staking-create-pool")]
    CreateStakePool {
        /// The amount to be pledged to the pool. There is a minimum to be accepted.
        /// This amount, and the rewards gained by the pool, CANNOT be taken out without decommissioning the pool.
        /// If you'd like to withdraw rewards, consider creating a pool and delegating to yourself.
        /// Delegators have no restrictions on withdrawals.
        /// The likelihood to win block rewards, by creating blocks while staking, is proportional to how much the pool owns,
        /// up to a maximum, to discourage heavy centralization of power.
        amount: DecimalAmount,

        /// An amount in coins to be subtracted from the total rewards in a block and handed to the staker
        /// as a constant/fixed cost for running the pool.
        cost_per_block: DecimalAmount,

        /// After subtracting "cost per block" from the reward, this ratio is taken from the rewards and is handed to the staker.
        /// What is left is distributed among delegators, pro-rata, based on their delegation amounts.
        /// The amount here is written as a percentage with per-mille accuracy. For example, 0.1% is valid,
        /// and is equivalent to 0.001. Also 5% is valid and is equivalent to 0.05.
        margin_ratio_per_thousand: String,

        /// The key that can decommission the pool. It's recommended to keep the decommission key in cold storage.
        decommission_address: String,

        /// This specifies the key that will sign new blocks.
        ///
        /// The key must be owned by the wallet that will do the actual staking. Leave it empty if the current
        /// wallet will be the staking wallet.
        ///
        /// Note that this must be a "public key address" and not a "public key hash address", which would normally be used
        /// in a transaction. Use the address-reveal-public-key-as-address command to convert the latter to the former
        /// (run it in the wallet that owns the key).
        staker_address: Option<String>,

        /// This specifies the VRF key that will be used to produce PoS hashes during staking.
        ///
        /// The key must be owned by the wallet that will do the actual staking. Leave it empty if the current
        /// wallet will be the staking wallet.
        vrf_public_key: Option<String>,
    },

    #[clap(name = "staking-decommission-pool")]
    DecommissionStakePool {
        /// The pool id of the pool to be decommissioned.
        /// Notice that this only works if the selected account in this wallet owns the decommission key.
        pool_id: String,
        /// The address that will be receiving the staker's balance (both pledge and proceeds from staking).
        output_address: String,
    },

    #[clap(name = "staking-decommission-pool-request")]
    DecommissionStakePoolRequest {
        /// The pool id of the pool to be decommissioned.
        pool_id: String,
        /// The address that will be receiving the staker's balance (both pledge and proceeds from staking).
        output_address: String,
    },

    #[clap(name = "wallet-rescan")]
    Rescan,

    #[clap(name = "wallet-sync")]
    SyncWallet,

    #[clap(name = "node-version")]
    NodeVersion,

    #[clap(name = "node-shutdown")]
    NodeShutdown,

    /// Enable or disable p2p networking in the node
    #[clap(name = "node-enable-p2p-networking")]
    NodeEnableNetworking { enable: CliEnableOrDisable },

    #[clap(name = "node-connect-to-peer")]
    Connect { address: IpOrSocketAddress },

    #[clap(name = "node-disconnect-peer")]
    Disconnect { peer_id: PeerId },

    #[clap(name = "node-list-banned-peers")]
    ListBanned,

    #[clap(name = "node-ban-peer-address")]
    Ban {
        /// IP address to ban.
        address: BannableAddress,
        /// Duration of the ban, e.g. 1M (1 month) or "1y 3M 10d 6h 30m 45s"
        /// (1 year 3 months 10 days 6 hours 30 minutes 45 seconds).
        #[arg(value_parser(humantime::parse_duration))]
        duration: Duration,
    },

    #[clap(name = "node-unban-peer-address")]
    Unban { address: BannableAddress },

    #[clap(name = "node-list-discouraged-peers")]
    ListDiscouraged,

    #[clap(name = "node-undiscourage-peer-address")]
    Undiscourage { address: BannableAddress },

    #[clap(name = "node-peer-count")]
    PeerCount,

    #[clap(name = "node-list-connected-peers")]
    ConnectedPeers,

    /// Get connected peers in JSON format
    #[clap(name = "node-list-connected-peers-json")]
    #[clap(hide = true)]
    ConnectedPeersJson,

    #[clap(name = "node-list-reserved-peers")]
    ReservedPeers,

    #[clap(name = "node-add-reserved-peer")]
    AddReservedPeer { address: IpOrSocketAddress },

    #[clap(name = "node-remove-reserved-peer")]
    RemoveReservedPeer { address: IpOrSocketAddress },

    #[clap(name = "node-submit-block")]
    SubmitBlock {
        /// Hex-encoded block
        block: HexEncoded<Block>,
    },

    #[clap(name = "node-submit-transaction")]
    SubmitTransaction {
        /// Hex-encoded transaction.
        transaction: HexEncoded<SignedTransaction>,
        /// Do not store the transaction in the wallet
        #[arg(long = "do-not-store")]
        do_not_store: bool,
    },

    #[clap(name = "node-chainstate-info")]
    ChainstateInfo,

    #[clap(name = "node-best-block-id")]
    BestBlock,

    /// Show the best block id, height, and timestamp; pass flags to show a subset
    #[clap(name = "node-best-block")]
    #[clap(hide = true)]
    NodeBestBlock {
        /// Show the best block id
        #[arg(long = "id")]
        id: bool,
        /// Show the best block height
        #[arg(long = "height")]
        height: bool,
        /// Show the best block timestamp
        #[arg(long = "timestamp")]
        timestamp: bool,
    },

    #[clap(name = "node-best-block-height")]
    BestBlockHeight,

    /// Returns the current best block timestamp
    #[clap(name = "node-best-block-timestamp")]
    BestBlockTimestamp,

    #[clap(name = "node-block-id")]
    BlockId {
        /// Block height
        height: BlockHeight,
    },

    #[clap(name = "node-get-block")]
    GetBlock {
        /// Block id
        id: String,
    },

    #[clap(name = "node-generate-block")]
    GenerateBlock {
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },

    #[clap(name = "node-generate-blocks")]
    #[clap(hide = true)]
    GenerateBlocks { block_count: u32 },

    /// For each block height in the specified range, find timestamps where staking is/was possible
    /// for the given pool.
    #[clap(name = "node-find-timestamps-for-staking")]
    #[clap(hide = true)]
    FindTimestampsForStaking {
        /// The pool in question
        pool_id: String,
        /// The minimum block height to consider; must not be zero
        min_height: BlockHeight,
        /// The maximum block height to consider; must not exceed the best block height plus one
        max_height: BlockHeight,
        /// If "check_all_timestamps_between_blocks" is "no", this value plus one is the number
        /// of seconds that will be checked at each height in the range.
        ///
        /// If "check_all_timestamps_between_blocks" is "yes", this value only applies to the
        /// last height in the range; for all other heights the maximum timestamp is the timestamp
        /// of the next block.
        seconds_to_check_for_height: u64,
        /// This determines how "seconds_to_check_for_height" will be interpreted
        check_all_timestamps_between_blocks: CliYesNo,
    },

    /// Return mainchain block ids with heights in the given range using the given step.
    ///
    /// The purpose of this is to populate CHECKPOINTS_DATA arrays located in
    /// `common/src/chain/config/checkpoints_data/` in `mainnet.rs` and `testnet.rs`.
    #[clap(name = "node-get-block-ids-as-checkpoints")]
    #[clap(hide = true)]
    GetBlockIdsAsCheckpoints {
        /// The starting height; normally, this will be the last height mentioned in
        /// the corresponding CHECKPOINTS_DATA array.
        start_height: BlockHeight,
        /// The end (exclusive) height. For simplicity, you can set it to some large number
        /// that is bigger than the current best block height, e.g. a million, in which case
        /// the command will print checkpoints until the maximum possible height.
        /// Note however that the last checkpoint that you put into CHECKPOINTS_DATA should
        /// be at least 1000 below the current tip, to ensure that reorgs below that checkpoint
        /// are no longer possible.
        end_height: BlockHeight,
        /// The step; in our current CHECKPOINTS_DATA arrays we use 500 as the step.
        step: NonZeroUsize,
    },

    // TODO: rework `CliUnspecifiedCurrencyTransfer` into a more general `CliCurrencyTransfer`,
    // which would allow the user to say "transfer(token_id,addr,amount)" and "transfer(coin,addr,amount)"
    // (while also supporting "transfer(addr,amount)" for backward compatibility).
    // Then make `transaction-compose` support token transfers as well.
    #[clap(name = "transaction-compose")]
    TransactionCompose {
        /// The transaction outputs, in the format `transfer(address,amount)`
        /// e.g. transfer(tmt1q8lhgxhycm8e6yk9zpnetdwtn03h73z70c3ha4l7,0.9)
        outputs: Vec<CliUnspecifiedCurrencyTransfer>,
        /// You can choose what utxos to spend (space separated as additional arguments).
        ///
        /// A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        #[arg(long = "utxos")]
        utxos: Vec<CliUtxoOutPoint>,

        /// This specifies that instead of a (hex-encoded) PartiallySignedTransaction
        /// the result should be a (hex-encoded) "simple" transaction.
        ///
        /// Producing a "simple" transaction will result in a shorter hex string, but you won't
        /// be able to use it with account-sign-raw-transaction in the cold wallet mode, which
        /// relies on some additional information contained inside PartiallySignedTransaction.
        ///
        /// In general, there is no reason in specifying this option unless you care about the size
        /// of the resulting hex string.
        #[arg(long = "only-transaction")]
        only_transaction: bool,
    },

    #[clap(name = "transaction-abandon")]
    AbandonTransaction {
        /// The id of the transaction that will be abandoned, in hex.
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    #[clap(name = "transaction-list-pending")]
    ListPendingTransactions,

    #[clap(name = "transaction-list-by-address")]
    ListMainchainTransactions {
        /// Address to filter by
        address: Option<String>,
        /// Limit the number of printed transactions.
        #[arg(long = "limit", default_value_t = 100)]
        limit: usize,
    },

    #[clap(name = "transaction-get")]
    GetTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    #[clap(name = "transaction-get-raw")]
    GetRawTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    #[clap(name = "transaction-get-signed-raw")]
    GetRawSignedTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Create an order for exchanging an amount of one ("given") currency for a certain amount of
    /// another ("asked") currency.
    ///
    /// Either of the currencies can be coins or tokens.
    /// The ratio between the asked and given amounts determines the exchange rate.
    ///
    /// The entire given amount of the "given" currency will be locked inside the order, so that
    /// it can be given away when the order is filled.
    ///
    /// The accumulated "ask" and the remaining "give" amounts can be withdrawn by concluding
    /// the order.
    #[clap(name = "order-create")]
    CreateOrder {
        /// The currency you are asking for - a token id or "coin" for coins.
        ask_currency: CliCurrency,

        /// The asked amount.
        ask_amount: DecimalAmount,

        /// The currency you will be giving - a token id or "coin" for coins.
        give_currency: CliCurrency,

        /// The given amount.
        give_amount: DecimalAmount,

        /// The address (key) that can authorize the conclusion and freezing of the order.
        conclude_address: String,
    },

    /// Fill the specified order with the specified amount of the order's "asked" currency,
    /// receiving the corresponding amount of the "given" currency.
    #[clap(name = "order-fill")]
    FillOrder {
        /// The id of the order to fill.
        order_id: String,

        /// The amount of the "asked" currency to fill the order with.
        amount: DecimalAmount,

        /// The address where the corresponding amount of the order's "given" currency should be
        /// transferred to.
        /// If not specified, a new receive address will be generated for this purpose.
        output_address: Option<String>,
    },

    /// Freeze the order.
    ///
    /// Once an order is frozen, it can no longer be filled. The only possible operation for
    /// a frozen order is conclusion.
    ///
    /// Note that freezing an order is optional, you can conclude a non-frozen order too.
    /// However it may not succeed if the order is still being actively filled. In such a case
    /// you may want to freeze the order first, wait for the corresponding transaction to be
    /// included in a block and then conclude the order.
    ///
    /// To be able to freeze an order, the order's conclude key must be owned by the selected
    /// account.
    #[clap(name = "order-freeze")]
    FreezeOrder {
        /// The id of the order to freeze.
        order_id: String,
    },

    /// Conclude the order, withdrawing the accumulated "asked" and the remaining "given"
    /// amounts.
    ///
    /// To be able to conclude an order, the order's conclude key must be owned by the selected
    /// account.
    #[clap(name = "order-conclude")]
    ConcludeOrder {
        /// The id of the order to conclude.
        order_id: String,

        /// The address where the accumulated "asked" amount and the remaining "given" amount
        /// should be transferred to. If not specified, a new receive address will be generated
        /// for this purpose.
        output_address: Option<String>,
    },

    /// List orders whose conclude key is owned by the selected account.
    #[clap(name = "order-list-own")]
    ListOwnOrders,

    /// List all active (i.e. not concluded and not frozen) orders, optionally filtering them
    /// by the "asked" or "given" currency.
    #[clap(name = "order-list-all-active")]
    ListActiveOrders {
        /// Filter orders by the specified "asked" currency - pass a token id or "coin" for coins.
        #[arg(long = "ask-currency")]
        ask_currency: Option<CliCurrency>,

        /// Filter orders by the specified "given" currency - pass a token id or "coin" for coins.
        #[arg(long = "give-currency")]
        give_currency: Option<CliCurrency>,
    },

    /// Create a transaction with an HTLC (Hashed TimeLock Contract) output without broadcasting it.
    #[clap(name = "htlc-create-transaction")]
    CreateHtlcTx {
        /// The currency to lock inside the HTLC - a token id or "coin" for coins.
        currency: CliCurrency,

        /// The amount to lock inside the HTLC.
        ///
        /// If the currency is an NFT, specify 1 here.
        amount: DecimalAmount,

        /// Hex-encoded hash of the HTLC secret.
        secret_hash: String,

        /// The address (key) that can spend the HTLC providing the secret.
        spend_address: String,

        /// The refund timelock.
        ///
        /// The format is one of: block_count(num), seconds(num), until_height(num) and until_time(RFC 3339 datetime),
        /// e.g. block_count(720), seconds(86400), until_height(500000), until_time(2026-02-26T12:30:00Z).
        refund_timelock: CliOutputTimeLock,

        /// The address (key) that can refund the HTLC after the refund timelock expires.
        refund_address: String,
    },

    /// Generate a new HTLC secret and print it to the console.
    #[clap(name = "htlc-generate-secret")]
    GenerateHtlcSecret,

    /// Calculate the hash of the provided HTLC secret.
    #[clap(name = "htlc-calc-secret-hash")]
    CalcHtlcSecretHash { secret: String },

    /// Spend the specified utxo, moving the corresponding funds (coins or tokens) to the specified
    /// address.
    ///
    /// Note that when moving coins, the command will use the same utxo to pays the fees, so the resulting transaction
    /// will have exactly one input and one output. When moving tokens, on the other hand, extra coin inputs will
    /// be selected to pay the fees, and extra coin outputs will be added to pay back the change, with the change being
    /// sent to a newly generated change address.
    ///
    /// Also note that though pool decommissioning is technically a spending of a utxo, you can't decommission a pool
    /// using this command. Use `staking-decommission-pool` for that purpose instead.
    #[clap(name = "utxo-spend")]
    SpendUtxo {
        /// The utxo to spend, e.g. tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1).
        utxo: CliUtxoOutPoint,

        /// The destination address that will receive the funds from the spent utxo.
        address: String,

        /// (For HTLC utxos only) optional hex-encoded HTLC secret.
        ///
        /// Specifying the HTLC secret for an HTLC utxo means that you are spending the HTLC,
        /// in which case HTLC's spend address must be owned by the current account.
        /// Omitting the secret means that you are refunding the HTLC, in which case HTLC's
        /// refund address must be owned by the current account.
        htlc_secret: Option<String>,
    },
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum ManageableWalletCommand {
    #[command(flatten)]
    ManagementCommands(WalletManagementCommand),

    #[command(flatten)]
    WalletCommands(WalletCommand),
}

pub trait ChoiceMenu: DynClone + Debug {
    fn header(&self) -> &str;

    fn choice_list(&self) -> Vec<String>;

    fn choose(&self, choice: usize) -> Option<ManageableWalletCommand>;
}
dyn_clone::clone_trait_object!(ChoiceMenu);

// TODO: this is Trezor-specific, so it should be either renamed or generalized.
#[cfg(feature = "trezor")]
#[derive(Debug, Clone)]
pub struct CreateWalletDeviceSelectMenu {
    available_devices: Vec<FoundDevice>,

    wallet_path: PathBuf,
    recover: bool,
}

#[cfg(feature = "trezor")]
impl CreateWalletDeviceSelectMenu {
    pub fn new(available_devices: Vec<FoundDevice>, wallet_path: PathBuf, recover: bool) -> Self {
        Self {
            available_devices,
            wallet_path,
            recover,
        }
    }
}

#[cfg(feature = "trezor")]
impl ChoiceMenu for CreateWalletDeviceSelectMenu {
    fn header(&self) -> &str {
        "Please choose one of the available Trezor devices:"
    }

    fn choice_list(&self) -> Vec<String> {
        self.available_devices
            .iter()
            .map(|d| format!("{} (device id: {})", d.device_name, d.device_id))
            .collect()
    }

    fn choose(&self, choice: usize) -> Option<ManageableWalletCommand> {
        self.available_devices.get(choice).map(|d| {
            if self.recover {
                ManageableWalletCommand::ManagementCommands(
                    WalletManagementCommand::RecoverWallet {
                        wallet: RecoverWalletSubCommand::Trezor {
                            wallet_path: self.wallet_path.clone(),
                            device_id: Some(d.device_id.clone()),
                        },
                    },
                )
            } else {
                ManageableWalletCommand::ManagementCommands(WalletManagementCommand::CreateWallet {
                    wallet: CreateWalletSubCommand::Trezor {
                        wallet_path: self.wallet_path.clone(),
                        device_id: Some(d.device_id.clone()),
                    },
                })
            }
        })
    }
}

// TODO: this is Trezor-specific, so it should be either renamed or generalized.
#[cfg(feature = "trezor")]
#[derive(Debug, Clone)]
pub struct OpenWalletDeviceSelectMenu {
    available_devices: Vec<FoundDevice>,

    wallet_path: PathBuf,
    encryption_password: Option<String>,
}

#[cfg(feature = "trezor")]
impl OpenWalletDeviceSelectMenu {
    pub fn new(
        available_devices: Vec<FoundDevice>,
        wallet_path: PathBuf,
        encryption_password: Option<String>,
    ) -> Self {
        Self {
            available_devices,
            wallet_path,
            encryption_password,
        }
    }
}

#[cfg(feature = "trezor")]
impl ChoiceMenu for OpenWalletDeviceSelectMenu {
    fn header(&self) -> &str {
        "Please choose one of the available Trezor devices:"
    }

    fn choice_list(&self) -> Vec<String> {
        self.available_devices
            .iter()
            .map(|d| format!("{} (device id: {})", d.device_name, d.device_id))
            .collect()
    }

    fn choose(&self, choice: usize) -> Option<ManageableWalletCommand> {
        self.available_devices.get(choice).map(|d| {
            ManageableWalletCommand::ManagementCommands(WalletManagementCommand::OpenWallet {
                wallet: OpenWalletSubCommand::Trezor {
                    wallet_path: self.wallet_path.clone(),
                    encryption_password: self.encryption_password.clone(),
                    device_id: Some(d.device_id.clone()),
                },
            })
        })
    }
}

#[derive(Debug, Clone)]
pub enum ConsoleCommand {
    Print(String),
    /// A structured result: optional human-readable text plus the machine-readable form
    /// of the same data. Both the interactive REPL and the non-interactive runner print
    /// the text when present, falling back to a pretty print of the value.
    Json {
        text: Option<String>,
        value: serde_json::Value,
    },
    /// A non-fatal condition, printed through the regular output channel for now;
    /// consumers that render to a separate warning stream may route it to stderr.
    Warn(String),
    PaginatedPrint {
        // TODO: add support for more structured data like table pagination
        header: String,
        body: String,
    },
    ClearScreen,
    PrintHistory,
    ClearHistory,
    SetStatus {
        status: String,
        print_message: String,
    },
    ChoiceMenu(Box<dyn ChoiceMenu + Sync + Send>),
    Exit,
}

// Strip out usage
const MAIN_HELP_TEMPLATE: &str = "\
    {all-args}
";

// Strip out name/version.
// Note: here we expect "about" to have a trailing EOL, see the comments inside get_repl_command.
const COMMAND_HELP_TEMPLATE: &str = "\
    {about}\n\
    {usage-heading}\n    {usage}\n\
    \n\
    {all-args}{after-help}\
";

pub fn get_repl_command(cold_wallet: bool, mutable_wallet: bool) -> Command {
    run_with_large_stack(move || build_repl_command(cold_wallet, mutable_wallet))
}

/// Stack size for threads that build or parse against the REPL grammar; the
/// clap-generated `augment_subcommands` frames the nested grammar produces are
/// large and overflow default 2 MiB thread stacks in debug builds.
pub const LARGE_STACK_SIZE: usize = 64 * 1024 * 1024;

/// Run `task` on a dedicated thread whose stack is large enough for the
/// clap-generated grammar construction.
///
/// The `augment_subcommands` frames the nested grammar produces are large; on
/// the default 2 MiB thread stacks used by the CLI REPL thread, GUI workers,
/// and test threads, building or parsing against the grammar can overflow the
/// stack in debug builds.
pub fn run_with_large_stack<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(LARGE_STACK_SIZE)
        .spawn(task)
        .expect("failed to spawn the grammar thread")
        .join()
        // Resume the original panic so its payload, location, and backtrace
        // are preserved instead of being flattened into a new panic here.
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// Build the REPL command tree on the calling thread.
///
/// Prefer [`get_repl_command`], which runs this on a large-stack thread; call
/// this directly only when already running on one.
pub fn build_repl_command(cold_wallet: bool, mutable_wallet: bool) -> Command {
    const COLD_WALLET_DESC: &Module = &ColdWalletRpcDescription::DESCRIPTION;
    const WALLET_DESC: &Module = &WalletRpcDescription::DESCRIPTION;

    let repl_command = Command::new("repl")
        .multicall(true)
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand_value_name("Command")
        .subcommand_help_heading("Commands")
        .help_template(MAIN_HELP_TEMPLATE);

    // Add commands from generated by clap-derive
    let mut repl_command = if cold_wallet {
        ColdWalletCommand::augment_subcommands(repl_command)
    } else {
        WalletCommand::augment_subcommands(repl_command)
    };

    // The nested `wallet` group carries the management commands, so for
    // non-mutable wallets the group is rebuilt without `create`, `recover`,
    // `open` and `close`; the remaining spellings stay available and match the
    // flat commands, which are gated the same way below.
    if !cold_wallet && !mutable_wallet {
        repl_command = repl_command.mut_subcommand("wallet", |wallet| {
            const MANAGEMENT_COMMANDS: [&str; 4] = ["create", "recover", "open", "close"];
            let mut group = Command::new(wallet.get_name().to_owned());
            if let Some(about) = wallet.get_about() {
                group = group.about(about.clone());
            }
            for subcommand in wallet.get_subcommands() {
                if !MANAGEMENT_COMMANDS.contains(&subcommand.get_name()) {
                    group = group.subcommand(subcommand.clone());
                }
            }
            group
        });
    }

    let mut repl_command = if mutable_wallet {
        WalletManagementCommand::augment_subcommands(repl_command)
    } else {
        repl_command
    };

    lazy_static::lazy_static! {
        static ref CUSTOM_RPC_TO_CLI_NAME_MAPPINGS: BTreeMap<&'static str, &'static str> =
            BTreeMap::from([("account_extended_public_key", "account-extended-public-key-as-hex")]);
    }

    let method_desc_from_rpc = COLD_WALLET_DESC
        .methods
        .iter()
        .chain(WALLET_DESC.methods)
        .map(|method| {
            let expected_cmd_name =
                if let Some(cmd_name) = CUSTOM_RPC_TO_CLI_NAME_MAPPINGS.get(&method.name) {
                    cmd_name.to_string()
                } else {
                    method.name.replace("_", "-")
                };
            (expected_cmd_name, method)
        })
        .collect::<BTreeMap<_, _>>();

    // Postprocess the commands:
    // 1) Customize the help template to make it more REPL friendly.
    // 2) Set display_order of all commands to the same value, so that they get sorted
    // in the alphabetical order (except "help", which will be added automatically by clap
    // later, so it will always be at the end).
    // 3) If the command's "about" is empty, re-use the description of the corresponding RPC
    // method.
    for subcommand in repl_command.get_subcommands_mut() {
        let mut new_subcommand =
            subcommand.clone().help_template(COMMAND_HELP_TEMPLATE).display_order(0);

        if new_subcommand.get_about().is_none()
            && let Some(rpc_method) = method_desc_from_rpc.get(subcommand.get_name())
        {
            let (about, long_about) = clapify_and_split_rpc_description(rpc_method.description);

            new_subcommand = new_subcommand.about(about);

            if let Some(long_about) = long_about {
                new_subcommand = new_subcommand.long_about(long_about);
            }
        }

        // Force-append a single EOL to all "about"s, to make the output of the "help" command nicer.
        if let Some(about) = new_subcommand.get_about() {
            let new_about = format!("{about}\n");
            new_subcommand = new_subcommand.about(new_about);
        }

        // For consistency, we also have to append an EOL to long_about.
        // (because "about" is printed by "some_command -h" and "long_about" by "some_command --help").
        if let Some(long_about) = new_subcommand.get_long_about() {
            let new_long_about = format!("{long_about}\n");
            new_subcommand = new_subcommand.long_about(new_long_about);
        }

        *subcommand = new_subcommand;
    }

    // This will add the "help" subcommand.
    // (note: if this is not called here, the "help" subcommand will still be added, but later,
    // during the `try_get_matches_from` call in `parse_input`).
    repl_command.build();

    repl_command
}

/// Clap-ify the provided RPC method description and split it into the "about" and "long_about"
/// parts.
///
/// Note: the generated RPC descriptions look different from those generated by clap:
/// 1) The RPC ones always have at least one trailing EOL, the clap ones don't.
/// 2) The RPC ones preserve all EOLs of the original doc string; in the clap ones all EOLs
///    within each paragraph are removed and empty lines between paragraphs are squashed into one.
/// 3) In the clap ones, if there are more than 1 paragraph, the first paragraph goes into "about"
///    and the whole text goes into "long_about".
///    Also, if the "about" part ends in exactly one period, the period is removed.
fn clapify_and_split_rpc_description(descr: &str) -> (String, Option<String>) {
    let descr = descr.trim();

    lazy_static::lazy_static! {
        static ref PARA_SEPARATOR_REGEX:Regex = Regex::new(r"(?m)\n{3,}").expect("regex construction must succeed");
        static ref EXTRA_EOL_REGEX:Regex = Regex::new(r"(?m)([^\n])\n([^\n])").expect("regex construction must succeed");
    }

    let descr = PARA_SEPARATOR_REGEX.replace_all(descr, "\n\n");
    let descr = EXTRA_EOL_REGEX.replace_all(&descr, "$1 $2");

    let (mut about, long_about) = if let Some(first_double_eol_pos) = descr.find("\n\n") {
        (
            // We know that the position is at a char boundary.
            #[allow(clippy::string_slice)]
            descr[..first_double_eol_pos].to_owned(),
            Some(descr.into_owned()),
        )
    } else {
        (descr.into_owned(), None)
    };

    let mut about_chars = about.chars();
    if about_chars.next_back() == Some('.') && about_chars.next_back() != Some('.') {
        about.pop();
    }

    (about, long_about)
}

/// Try to parse REPL input string as a [WalletCommands]
pub fn parse_input<N: NodeInterface>(
    line: &str,
    repl_command: &Command,
) -> Result<Option<ManageableWalletCommand>, WalletCliCommandError<N>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    // Split arguments as a normal shell would do
    let args = shlex::split(line).ok_or(WalletCliCommandError::InvalidQuoting)?;
    let mut matches = repl_command
        .clone()
        .try_get_matches_from(args)
        .map_err(WalletCliCommandError::InvalidCommandInput)?;
    let command = ManageableWalletCommand::from_arg_matches_mut(&mut matches)
        .map_err(WalletCliCommandError::InvalidCommandInput)?;
    Ok(Some(command))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[ctor::ctor]
    fn init() {
        logging::init_logging();
    }

    // Everything before the first `--option` must be a chain of subcommand names;
    // options inside a nested path are not part of the structural check.
    fn resolve_structural_path<'a>(repl: &'a Command, nested: &str) -> &'a Command {
        let (structural_path, _) = nested.split_once(" --").unwrap_or((nested, ""));
        let mut level = repl;
        for name in structural_path.split_whitespace() {
            level = level.find_subcommand(name).unwrap_or_else(|| {
                panic!("nested path `{nested}` breaks at `{name}` in the repl command tree")
            });
        }
        level
    }

    // The clap-generated `augment_subcommands` frames of the nested grammar are large;
    // test threads default to a 2 MiB stack, so grammar construction runs on a dedicated
    // thread with a bigger one.
    // `get_repl_command` builds the grammar on a large-stack thread internally,
    // so the tests can call it directly.
    fn grammar_with_large_stack(cold_wallet: bool, mutable_wallet: bool) -> Command {
        get_repl_command(cold_wallet, mutable_wallet)
    }

    #[test]
    fn legacy_command_names_and_group_grammar_coexist() {
        let repl = grammar_with_large_stack(false, true);

        // Every legacy flat command must still exist at the top level.
        for (legacy, _nested) in LEGACY_ALIASES {
            assert!(
                repl.find_subcommand(legacy).is_some(),
                "legacy command `{legacy}` is missing from the repl command tree"
            );
        }

        // Every nested path must exist under its groups. Options inside a nested path
        // are not part of the structural check, so everything from the first option on
        // is dropped before the walk.
        for (_legacy, nested) in LEGACY_ALIASES {
            resolve_structural_path(&repl, nested);
        }

        // Arguments shared between a legacy spelling and its nested leaf must agree on
        // defaults and requiredness, so one spelling cannot silently drift from the
        // other. Arguments unique to one spelling (such as the merged `--format` of the
        // nested `reveal-public-key`) are skipped.
        for (legacy, nested) in LEGACY_ALIASES {
            let legacy_cmd = repl
                .find_subcommand(legacy)
                .unwrap_or_else(|| panic!("legacy command `{legacy}` is missing"));
            let nested_cmd = resolve_structural_path(&repl, nested);
            for legacy_arg in legacy_cmd.get_arguments() {
                let Some(nested_arg) =
                    nested_cmd.get_arguments().find(|arg| arg.get_id() == legacy_arg.get_id())
                else {
                    continue;
                };
                assert_eq!(
                    legacy_arg.get_default_values(),
                    nested_arg.get_default_values(),
                    "default values of `{}` diverge between `{legacy}` and `{nested}`",
                    legacy_arg.get_id(),
                );
                assert_eq!(
                    legacy_arg.is_required_set(),
                    nested_arg.is_required_set(),
                    "requiredness of `{}` diverges between `{legacy}` and `{nested}`",
                    legacy_arg.get_id(),
                );
            }
        }
    }

    #[test]
    fn non_mutable_grammar_excludes_wallet_management() {
        // Hot wallet without management: neither the flat management commands nor the
        // nested `wallet` group may be available.
        let repl = grammar_with_large_stack(false, false);
        assert!(repl.find_subcommand("wallet-create").is_none());
        let wallet_group = repl
            .find_subcommand("wallet")
            .expect("the wallet group is part of the hot wallet grammar");
        assert!(wallet_group.find_subcommand("create").is_none());
        assert!(wallet_group.find_subcommand("close").is_none());
    }

    #[test]
    fn mutable_grammar_includes_the_wallet_group() {
        let repl = grammar_with_large_stack(false, true);
        let wallet_group = repl
            .find_subcommand("wallet")
            .expect("the wallet group is part of the hot wallet grammar");
        assert!(wallet_group.find_subcommand("create").is_some());
        assert!(wallet_group.find_subcommand("close").is_some());
    }

    #[rstest]
    fn ensure_commands_have_description(
        #[values(false, true)] cold_wallet: bool,
        #[values(false, true)] mutable_wallet: bool,
    ) {
        let repl_command = grammar_with_large_stack(cold_wallet, mutable_wallet);

        let command_names_without_descr = repl_command
            .get_subcommands()
            .filter(|command| command.get_about().is_none())
            .map(|command| command.get_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(command_names_without_descr, Vec::<String>::new());
    }

    mod clapify_rpc_descr_test {
        use super::*;

        #[test]
        fn test() {
            let expected_descrs = BTreeMap::from([
                ("func1", ("This is a test description. It has some EOLs. Also, it ends with a period".to_owned(), None)),
                ("func2", ("This is a test description. It has some EOLs. Also, it ends with a double period..".to_owned(), None)),
                ("func3", (
                    "This is a test description. It has some EOLs. Also, it ends with a period".to_owned(),
                    Some(concat!(
                        "This is a test description. It has some EOLs. Also, it ends with a period.\n\n",
                        "And it has an extra paragraph with extra EOL.").to_owned()
                    ))
                ),
                ("func4", (
                    "This is a test description. It has some EOLs. Also, it ends with a double period..".to_owned(),
                    Some(concat!("This is a test description. It has some EOLs. Also, it ends with a double period..\n\n",
                        "And it has an extra paragraph with extra EOL.\n\n",
                        "And one more paragraph.").to_owned()
                    ))
                ),
            ]);

            let command = TestCommand::augment_subcommands(Command::new("test_cmd"));

            let descrs_from_command = command
                .get_subcommands()
                .map(|sub_cmd| {
                    (
                        sub_cmd.get_name(),
                        (
                            sub_cmd.get_about().unwrap().to_string(),
                            sub_cmd.get_long_about().map(|s| s.to_string()),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(descrs_from_command, expected_descrs);

            let descrs_from_rpc = TestRpcDescription::DESCRIPTION
                .methods
                .iter()
                .map(|method| {
                    let (about, long_about) = clapify_and_split_rpc_description(method.description);

                    (method.name, (about, long_about))
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(descrs_from_rpc, expected_descrs);
        }

        #[rpc::describe]
        #[rpc::rpc(server, client)]
        trait TestRpc {
            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a period.
            #[method(name = "func1")]
            fn func1(&self) -> rpc::RpcResult<()>;

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a double period..
            #[method(name = "func2")]
            fn func2(&self) -> rpc::RpcResult<()>;

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a period.
            ///
            /// And it has an extra paragraph
            /// with extra EOL.
            #[method(name = "func3")]
            fn func3(&self) -> rpc::RpcResult<()>;

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a double period..
            ///
            /// And it has an extra paragraph
            /// with extra EOL.
            ///
            /// And one more paragraph.
            #[method(name = "func4")]
            fn func4(&self) -> rpc::RpcResult<()>;
        }

        #[derive(Debug, Parser)]
        pub enum TestCommand {
            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a period.
            #[clap(name = "func1")]
            Func1,

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a double period..
            #[clap(name = "func2")]
            Func2,

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a period.
            ///
            /// And it has an extra paragraph
            /// with extra EOL.
            #[clap(name = "func3")]
            Func3,

            /// This is a test description.
            /// It has some EOLs.
            /// Also, it ends with a double period..
            ///
            /// And it has an extra paragraph
            /// with extra EOL.
            ///
            /// And one more paragraph.
            #[clap(name = "func4")]
            Func4,
        }
    }
}
