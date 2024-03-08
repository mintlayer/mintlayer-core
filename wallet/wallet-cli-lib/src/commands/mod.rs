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

mod command_handler;
mod helper_types;

pub use command_handler::CommandHandler;

use std::{fmt::Debug, path::PathBuf, time::Duration};

use clap::Parser;

use common::{
    chain::{Block, SignedTransaction, Transaction},
    primitives::{BlockHeight, DecimalAmount, Id},
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use p2p_types::{bannable_address::BannableAddress, PeerId};
use serialization::hex_encoded::HexEncoded;
use utils_networking::IpOrSocketAddress;

use self::helper_types::{
    CliForceReduce, CliIsFreezable, CliIsUnfreezable, CliStoreSeedPhrase, CliUtxoState,
    CliUtxoTypes, CliWithLocked,
};

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum ColdWalletCommand {
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

        /// Passphrase along the mnemonic
        #[arg(long = "passphrase")]
        passphrase: Option<String>,
    },

    #[clap(name = "wallet-open")]
    OpenWallet {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,
    },

    #[clap(name = "wallet-close")]
    CloseWallet,

    #[clap(name = "wallet-info")]
    WalletInfo,

    #[clap(name = "wallet-encrypt-private-keys")]
    EncryptPrivateKeys {
        /// The new encryption password
        password: String,
    },

    #[clap(name = "wallet-disable-private-keys-encryption")]
    RemovePrivateKeysEncryption,

    #[clap(name = "wallet-unlock-private-keys")]
    UnlockPrivateKeys {
        /// The current encryption password.
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

        /// Forces the reduction of lookahead size even below the known last used address
        /// the new wallet can lose track of known addresses and balance
        i_know_what_i_am_doing: Option<CliForceReduce>,
    },

    /// Creates a QR code of the provided address
    #[clap(name = "address-qrcode")]
    AddressQRCode {
        /// A Destination address
        address: String,
    },

    #[clap(name = "address-new")]
    NewAddress,

    /// Reveal the public key behind this address in hex encoding
    #[clap(name = "address-reveal-public-key-as-hex")]
    RevealPublicKeyHex {
        public_key_hash: String,
    },

    /// Reveal the public key behind this address in address encoding.
    /// Note that this isn't a normal address to be used in transactions.
    /// It's preferred to take the address from address-show command
    #[clap(name = "address-reveal-public-key-as-address")]
    RevealPublicKey {
        public_key_hash: String,
    },

    #[clap(name = "address-show")]
    ShowReceiveAddresses,

    #[clap(name = "staking-new-vrf-public-key")]
    NewVrfPublicKey,

    #[clap(name = "staking-show-vrf-public-keys")]
    GetVrfPublicKey,

    #[clap(name = "staking-show-legacy-vrf-key")]
    GetLegacyVrfPublicKey,

    #[clap(name = "account-sign-raw-transaction")]
    SignRawTransaction {
        /// Hex encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },

    #[clap(name = "challenge-sign-hex")]
    #[clap(hide = true)]
    SignChallegeHex {
        /// Hex encoded message to be signed
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
        /// The hex encoded message that was signed
        message: String,
        /// Hex encoded signed challenge
        signed_challenge: String,
        /// Address with whose private key the challenge was signed with
        address: String,
    },

    #[clap(name = "challenge-verify-plain")]
    VerifyChallenge {
        /// The message that was signed
        message: String,
        /// Hex encoded signed challenge
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

    Version,

    /// Shutdown the RPC interface or the remote wallet it is connected to
    /// and exit the wallet
    RpcShutdownAndExit,

    /// Exit the wallet
    Exit,
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum WalletCommand {
    #[command(flatten)]
    ColdCommands(ColdWalletCommand),

    #[clap(name = "account-create")]
    CreateNewAccount { name: Option<String> },

    #[clap(name = "account-rename")]
    RenameAccount { name: Option<String> },

    /// Switch to a given wallet account.
    #[clap(name = "account-select")]
    SelectAccount { account_index: U31 },

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

    #[clap(name = "account-balance")]
    GetBalance {
        /// Whether to include locked outputs (outputs that cannot be spend and need time to mature)
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of utxos to be included (confirmed, unconfirmed, etc)
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
        /// The owner, represented by a public key (hex encoded)
        creator: Option<HexEncoded<PublicKey>>,
        /// URI for the icon of the NFT
        icon_uri: Option<String>,
        /// URI of the media
        media_uri: Option<String>,
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
        /// The address of the receiver of this token
        destination_address: String,
        /// The total supply of this token
        token_supply: String,
        /// Whether it's possible to centrally freeze this token for all users (due to migration requirements, for example)
        is_freezable: CliIsFreezable,
    },

    #[clap(name = "token-change-authority")]
    ChangeTokenAuthority { token_id: String, address: String },

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
        /// The token id of the tokens to be sent
        token_id: String,
        /// The destination address receiving the tokens
        address: String,
        /// The amount of tokens to be sent
        amount: DecimalAmount,
    },

    #[clap(name = "address-send")]
    SendToAddress {
        /// The receiving address of the coins
        address: String,
        /// The amount to be sent, in decimal format
        amount: DecimalAmount,
        /// You can choose what utxos to spend (space separated as additional arguments). A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        #[arg(default_values_t = Vec::<String>::new())]
        utxos: Vec<String>,
    },

    #[clap(name = "address-sweep-spendable")]
    SweepFromAddress {
        /// The receiving address of the coins or tokens
        destination_address: String,
        /// The addresses to be swept
        addresses: Vec<String>,
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
        utxo: String,
        /// Optional change address, if not specified it returns the change to the same address from the input
        #[arg(long = "change")]
        change_address: Option<String>,
    },

    #[clap(name = "transaction-inspect")]
    InspectTransaction {
        /// Hex encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },

    #[clap(name = "address-deposit-data")]
    DepositData {
        /// The data to be deposited on the blockchain as hex. DO NOT start the data with 0x.
        hex_data: String,
    },

    #[clap(name = "delegation-create")]
    CreateDelegation {
        /// The address, that will have the authority to sign withdrawals from a pool.
        owner: String,
        /// The pool id of the pool that will get the delegation and stake the coins.
        pool_id: String,
    },

    #[clap(name = "delegation-list-ids")]
    ListDelegationIds,

    #[clap(name = "delegation-stake")]
    DelegateStaking {
        /// The amount to be delegated for staking
        amount: DecimalAmount,
        /// The delegation id that was created. Every pool you want to delegate to must have a delegation id.
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
        /// The amount here is written as a percentage with per-mill accuracy. For example, 0.1% is valid,
        /// and is equivalent to 0.001. Also 5% is valid and is equivalent to 0.05.
        margin_ratio_per_thousand: String,

        /// The key that can decommission the pool. It's recommended to keep the decommission key in a cold storage.
        decommission_address: String,
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

    #[clap(name = "node-peer-count")]
    PeerCount,

    #[clap(name = "node-list-connected-peers")]
    ConnectedPeers,

    /// Get connected peers in JSON format
    #[clap(name = "node-list-connected-peers-json")]
    ConnectedPeersJson,

    #[clap(name = "node-list-reserved-peers")]
    ReservedPeers,

    #[clap(name = "node-add-reserved-peer")]
    AddReservedPeer { address: IpOrSocketAddress },

    #[clap(name = "node-remove-reserved-peer")]
    RemoveReservedPeer { address: IpOrSocketAddress },

    #[clap(name = "node-submit-block")]
    SubmitBlock {
        /// Hex encoded block
        block: HexEncoded<Block>,
    },

    #[clap(name = "node-submit-transaction")]
    SubmitTransaction {
        /// Hex encoded transaction.
        transaction: HexEncoded<SignedTransaction>,
        /// Do not store the transaction in the wallet
        #[arg(long = "do-not-store", default_value_t = false)]
        do_not_store: bool,
    },

    #[clap(name = "node-chainstate-info")]
    ChainstateInfo,

    #[clap(name = "node-best-block-id")]
    BestBlock,

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
        /// Block hash
        hash: String,
    },

    #[clap(name = "node-generate-block")]
    GenerateBlock {
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },

    #[clap(name = "node-generate-blocks")]
    #[clap(hide = true)]
    GenerateBlocks { block_count: u32 },

    #[clap(name = "transaction-compose")]
    TransactionCompose {
        /// The transaction outputs, in the format `transfer(address,amount)`
        /// e.g. transfer(tmt1q8lhgxhycm8e6yk9zpnetdwtn03h73z70c3ha4l7,0.9)
        outputs: Vec<String>,
        /// You can choose what utxos to spend (space separated as additional arguments). A utxo can be from a transaction output or a block reward output:
        /// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) or
        /// block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
        #[arg(long="utxos", default_values_t = Vec::<String>::new())]
        utxos: Vec<String>,

        #[arg(long = "only-transaction", default_value_t = false)]
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
        /// limit the number of printed transactions, default is 100
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
