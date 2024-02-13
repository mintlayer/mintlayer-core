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

use std::{
    fmt::{Debug, Write},
    path::PathBuf,
    str::FromStr,
};

use clap::Parser;
use itertools::Itertools;

use common::{
    address::Address,
    chain::{
        Block, ChainConfig, Destination, SignedTransaction, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, DecimalAmount, Id, H256},
    text_summary::TextSummary,
};
use crypto::key::{hdkd::u31::U31, PublicKey};
use mempool::tx_options::TxOptionsOverrides;
use p2p_types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use utils::qrcode::{QrCode, QrCodeError};
use wallet::{account::PartiallySignedTransaction, version::get_version};
use wallet_controller::{
    types::Balances, ControllerConfig, NodeInterface, PeerId, DEFAULT_ACCOUNT_INDEX,
};
use wallet_rpc_client::wallet_rpc_traits::{PartialOrSignedTx, WalletInterface};
use wallet_rpc_lib::types::{
    ComposedTransaction, CreatedWallet, NewTransaction, NftMetadata, TokenMetadata,
};

use crate::{
    commands::helper_types::{parse_output, parse_token_supply},
    errors::WalletCliError,
};

use self::helper_types::{
    format_delegation_info, format_pool_info, parse_utxo_outpoint, CliForceReduce, CliIsFreezable,
    CliIsUnfreezable, CliStoreSeedPhrase, CliUtxoState, CliUtxoTypes, CliWithLocked,
};

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum ColdWalletCommand {
    /// Create new wallet
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
    },

    /// Open an exiting wallet by specifying the file location of the wallet file
    #[clap(name = "wallet-open")]
    OpenWallet {
        /// File path of the wallet file
        wallet_path: PathBuf,
        /// The existing password, if the wallet is encrypted.
        encryption_password: Option<String>,
    },

    /// Close the currently open wallet file
    #[clap(name = "wallet-close")]
    CloseWallet,

    /// Encrypts the private keys with a new password, expects the wallet to be unlocked
    #[clap(name = "wallet-encrypt-private-keys")]
    EncryptPrivateKeys {
        /// The new encryption password
        password: String,
    },

    /// Completely and totally remove any existing encryption, expects the wallet to be unlocked.
    /// WARNING: After this, your wallet file will be USABLE BY ANYONE without a password.
    #[clap(name = "wallet-disable-private-keys-encryption")]
    RemovePrivateKeysEncryption,

    /// Unlocks the private keys for usage.
    #[clap(name = "wallet-unlock-private-keys")]
    UnlockPrivateKeys {
        /// The current encryption password.
        password: String,
    },

    /// Locks the private keys so they can't be used until they are unlocked again
    #[clap(name = "wallet-lock-private-keys")]
    LockPrivateKeys,

    /// Show the seed phrase for the loaded wallet if it has been s
    #[clap(name = "wallet-show-seed-phrase")]
    ShowSeedPhrase,

    /// Delete the seed phrase from the loaded wallet's database, if it has been stored.
    #[clap(name = "wallet-purge-seed-phrase")]
    PurgeSeedPhrase,

    /// Set the lookahead size for key generation.
    ///
    /// Lookahead size (or called gap) is the number of addresses to generate and the blockchain for incoming transactions to them
    /// after the last address that was seen to contain a transaction on the blockchain.
    /// Do not attempt to reduce the size of this value unless you're sure there are no incoming transactions in these addresses.
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

    /// Generate a new unused address
    #[clap(name = "address-new")]
    NewAddress,

    /// Reveal the public key behind this address in hex encoding
    #[clap(name = "address-reveal-public-key-as-hex")]
    RevealPublicKeyHex { public_key_hash: String },

    /// Reveal the public key behind this address in address encoding.
    /// Note that this isn't a normal address to be used in transactions.
    /// It's preferred to take the address from address-show command
    #[clap(name = "address-reveal-public-key-as-address")]
    RevealPublicKey { public_key_hash: String },

    /// Show receive-addresses with their usage state.
    /// Note that whether an address is used isn't based on the wallet,
    /// but on the blockchain. So if an address is used in a transaction,
    /// it will be marked as used only when the transaction is included
    /// in a block.
    #[clap(name = "address-show")]
    ShowReceiveAddresses,

    /// Issue a new staking VRF (Verifiable Random Function) key for this account.
    /// VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
    /// where no one can control the possible outcomes, to ensure decentralization.
    /// NOTE: Under normal circumstances you don't need to generate VRF keys manually.
    /// Creating a new staking pool will do it for you. This is available for specialized use-cases.
    #[clap(name = "staking-new-vrf-public-key")]
    NewVrfPublicKey,

    /// Show the issued staking VRF (Verifiable Random Function) keys for this account.
    /// These keys are generated when pools are created.
    /// VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
    /// where no one can control the possible outcomes, to ensure decentralization.
    #[clap(name = "staking-show-vrf-public-keys")]
    GetVrfPublicKey,

    /// Shows the legacy VRF key that uses an abandoned derivation mechanism.
    /// This will not be used for new pools and should be avoided
    #[clap(name = "staking-show-legacy-vrf-key")]
    GetLegacyVrfPublicKey,

    /// Signs the inputs that are not yet signed.
    /// The input is a special format of the transaction serialized to hex. This format is automatically used in this wallet
    /// in functions such as staking-decommission-pool-request. Once all signatures are complete, the result can be broadcast
    /// to the network.
    #[clap(name = "account-sign-raw-transaction")]
    SignRawTransaction {
        /// Hex encoded transaction or PartiallySignedTransaction.
        transaction: String,
    },

    /// Signs a challenge with a private key corresponding to the provided address destination.
    #[clap(name = "challenge-sign-hex")]
    #[clap(hide = true)]
    SignChallegeHex {
        /// Hex encoded message to be signed
        message: String,
        /// Address with whose private key to sign the challenge
        address: String,
    },

    /// Signs a challenge with a private key corresponding to the provided address destination.
    #[clap(name = "challenge-sign-plain")]
    SignChallege {
        /// The message to be signed
        message: String,
        /// Address with whose private key to sign the challenge
        address: String,
    },

    /// Verifies a signed challenge against an address destination
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

    /// Verifies a signed challenge against an address destination
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

    /// Print the version of the wallet software and possibly the git commit hash, if found
    Version,

    /// Exit the wallet
    Exit,
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
pub enum WalletCommand {
    #[command(flatten)]
    ColdCommands(ColdWalletCommand),

    /// Creates a new account with an optional name.
    /// Returns an error if the last created account does not have a transaction history.
    #[clap(name = "account-create")]
    CreateNewAccount { name: Option<String> },

    /// Switch to a given wallet account.
    #[clap(name = "account-select")]
    SelectAccount { account_index: U31 },

    /// Lists all the utxos owned by this account
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

    /// Get the total balance in the selected account in this wallet. See available options to include more categories, like locked coins.
    #[clap(name = "account-balance")]
    GetBalance {
        /// Whether to include locked outputs (outputs that cannot be spend and need time to mature)
        #[arg(value_enum, default_value_t = CliWithLocked::Unlocked)]
        with_locked: CliWithLocked,
        /// The state of utxos to be included (confirmed, unconfirmed, etc)
        #[arg(default_values_t = vec![CliUtxoState::Confirmed])]
        utxo_states: Vec<CliUtxoState>,
    },

    /// Issue a new non-fungible token (NFT) from scratch
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

    /// Issue a new fungible token from scratch.
    /// Notice that issuing a token fills an issuers supply. To have tokens that are spendable,
    /// the issuer must "mint" tokens to take from the supply
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

    /// Change the authority of a token; i.e., the cryptographic authority that can do all authority token operations
    #[clap(name = "token-change-authority")]
    ChangeTokenAuthority { token_id: String, address: String },

    /// Given a token that is already issued, mint new tokens and increase the total supply
    #[clap(name = "token-mint")]
    MintTokens {
        /// The token id of the tokens to be minted
        token_id: String,
        /// The receiving address of the minted tokens
        address: String,
        /// The amount to be minted
        amount: DecimalAmount,
    },

    /// Unmint existing tokens and reduce the total supply
    /// Unminting reduces the total supply and puts the unminted tokens back at the issuer's control.
    /// The wallet must own the tokens that are being unminted.
    #[clap(name = "token-unmint")]
    UnmintTokens {
        /// The token id of the tokens to be unminted
        token_id: String,
        /// The amount to be unminted
        amount: DecimalAmount,
    },

    /// Lock the circulating supply for the token. THIS IS IRREVERSIBLE.
    /// Tokens that can be locked will lose the ability to mint/unmint them
    #[clap(name = "token-lock-supply")]
    LockTokenSupply {
        /// The token id of the token, whose supply will be locked
        token_id: String,
    },

    /// Freezing the token (by token authority) forbids any operation with all the tokens (except for the optional unfreeze).
    ///
    /// After a token is frozen, no transfers, spends, or any other operation can be done.
    /// This wallet (and selected account) must own the authority keys to be able to freeze.
    #[clap(name = "token-freeze")]
    FreezeToken {
        /// The token id of the token to be frozen.
        token_id: String,
        /// Whether these tokens can be unfrozen again, or permanently freeze them.
        is_unfreezable: CliIsUnfreezable,
    },

    /// By unfreezing the token all operations are available for the tokens again.
    ///
    /// Notice that this is only possible if the tokens were made to be unfreezable during freezing.
    /// This wallet (and selected account) must own the authority keys to be able to unfreeze.
    #[clap(name = "token-unfreeze")]
    UnfreezeToken {
        /// The token id of the token to be unfrozen.
        token_id: String,
    },

    /// Send a given token amount to a given address. The wallet will automatically calculate the required information
    #[clap(name = "token-send")]
    SendTokensToAddress {
        /// The token id of the tokens to be sent
        token_id: String,
        /// The destination address receiving the tokens
        address: String,
        /// The amount of tokens to be sent
        amount: DecimalAmount,
    },

    /// Send a given coin amount to a given address. The wallet will automatically calculate the required information
    /// Optionally, one can also mention the utxos to be used.
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

    /// Creates a transaction that spends from a specific address,
    /// and returns the change to the same address (unless one is specified), without signature.
    /// This transaction is used for "withdrawing" small amounts from a cold storage
    /// without changing the ownership address. Once this is created,
    /// it can be signed using account-sign-raw-transaction in the cold wallet
    /// and then broadcast through any hot wallet.
    /// In summary, this creates a transaction with one input and two outputs,
    /// with one of the outputs being change returned to the same owner of the input.
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

    /// Store data on the blockchain, the data is provided as hex encoded string.
    /// Note that there is a high fee for storing data on the blockchain.
    #[clap(name = "address-deposit-data")]
    DepositData {
        /// The data to be deposited on the blockchain as hex. DO NOT start the data with 0x.
        hex_data: String,
    },

    /// Create a delegation to a given pool id and the owner address/destination.
    /// The owner of a delegation is the key authorized to withdraw from the delegation.
    /// The delegation creation will result in creating a delegation id, where coins sent to that id will be staked by the pool id provided, automatically.
    /// The pool, to which the delegation is made, doesn't have the authority to spend the coins.
    #[clap(name = "delegation-create")]
    CreateDelegation {
        /// The address, that will have the authority to sign withdrawals from a pool.
        owner: String,
        /// The pool id of the pool that will get the delegation and stake the coins.
        pool_id: String,
    },

    /// List delegation ids controlled by the selected account in this wallet with their balances
    #[clap(name = "delegation-list-ids")]
    ListDelegationIds,

    /// Send coins to a delegation id to be staked
    #[clap(name = "delegation-stake")]
    DelegateStaking {
        /// The amount to be delegated for staking
        amount: DecimalAmount,
        /// The delegation id that was created. Every pool you want to delegate to must have a delegation id.
        delegation_id: String,
    },

    /// Send coins from a delegation id (that you own) to stop staking them.
    /// Note that stopping the delegation requires a lock period.
    #[clap(name = "delegation-withdraw")]
    WithdrawFromDelegation {
        /// The address that will be receiving the coins
        address: String,
        /// The amount that will be taken away from the delegation
        amount: DecimalAmount,
        /// The delegation id, from which the delegated coins will be taken
        delegation_id: String,
    },

    /// List ids of pools that are controlled by the selected account in this wallet
    #[clap(name = "staking-list-pool-ids")]
    ListPoolIds,

    /// Start staking, assuming there are staking pools in the selected account in this wallet.
    #[clap(name = "staking-start")]
    StartStaking,

    /// Stop staking, assuming there are staking pools staking currently in the selected account in this wallet.
    #[clap(name = "staking-stop")]
    StopStaking,

    /// Show the staking status for the currently selected account in this wallet.
    #[clap(name = "staking-status")]
    StakingStatus,

    /// Print the balance of available staking pools
    #[clap(name = "staking-pool-balance")]
    StakePoolBalance { pool_id: String },

    /// List the blocks created by the selected account in this wallet through staking/mining/etc
    #[clap(name = "staking-list-created-block-ids")]
    ListCreatedBlocksIds,

    /// Create a staking pool. The pool will be capable of creating blocks and gaining rewards,
    /// and will be capable of taking delegations from other users and staking.
    /// The decommission key is the key that can decommission the pool.
    /// Cost per block, and margin ratio are parameters that control how delegators receive rewards.
    /// The cost per block is an amount in coins to be subtracted from the total rewards in a block first,
    /// and handed to the staking pool. After subtracting the cost per block, a fraction equal to
    /// margin ratio is taken from what is left, and given to the staking pool. Finally, what is left
    /// is distributed among delegators, pro-rata, based on their delegation amounts.
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

    /// Decommission a staking pool, given its id. This assumes that the decommission key is owned
    /// by the selected account in this wallet.
    #[clap(name = "staking-decommission-pool")]
    DecommissionStakePool {
        /// The pool id of the pool to be decommissioned.
        /// Notice that this only works if the selected account in this wallet owns the decommission key.
        pool_id: String,
        /// The address that will be receiving the staker's balance (both pledge and proceeds from staking).
        output_address: String,
    },

    /// Create a request to decommission a pool. This assumes that the decommission key is owned
    /// by another wallet. The output of this command should be passed to account-sign-raw-transaction
    /// in the wallet that owns the decommission key. The result from signing, assuming success, can
    /// then be broadcast to network to commence with decommissioning.
    #[clap(name = "staking-decommission-pool-request")]
    DecommissionStakePoolRequest {
        /// The pool id of the pool to be decommissioned.
        pool_id: String,
        /// The address that will be receiving the staker's balance (both pledge and proceeds from staking).
        output_address: String,
    },

    /// Rescan the blockchain and re-detect all operations related to the selected account in this wallet
    #[clap(name = "wallet-rescan")]
    Rescan,

    /// Force the wallet to scan the remaining blocks from node until the tip is reached
    #[clap(name = "wallet-sync")]
    SyncWallet,

    /// Node version
    #[clap(name = "node-version")]
    NodeVersion,

    /// Node shutdown
    #[clap(name = "node-shutdown")]
    NodeShutdown,

    /// Connect to a remote peer in the node
    #[clap(name = "node-connect-to-peer")]
    Connect { address: IpOrSocketAddress },

    /// Disconnected a remote peer in the node
    #[clap(name = "node-disconnect-peer")]
    Disconnect { peer_id: PeerId },

    /// List banned addresses/peers in the node
    #[clap(name = "node-list-banned-peers")]
    ListBanned,

    /// Ban an address in the node for the specified duration
    #[clap(name = "node-ban-peer-address")]
    Ban {
        /// IP address to ban.
        address: BannableAddress,
        /// Duration of the ban, e.g. 1M (1 month) or "1y 3M 10d 6h 30m 45s"
        /// (1 year 3 months 10 days 6 hours 30 minutes 45 seconds).
        #[arg(value_parser = clap::value_parser!(helper_types::Duration))]
        duration: helper_types::Duration,
    },

    /// Unban address in the node
    #[clap(name = "node-unban-peer-address")]
    Unban { address: BannableAddress },

    /// List discouraged addresses/peers in the node
    #[clap(name = "node-list-discouraged-peers")]
    ListDiscouraged,

    /// Get the number of connected peer in the node
    #[clap(name = "node-peer-count")]
    PeerCount,

    /// Get connected peers in the node
    #[clap(name = "node-list-connected-peers")]
    ConnectedPeers,

    /// Get connected peers in JSON format
    #[clap(name = "node-list-connected-peers-json")]
    ConnectedPeersJson,

    /// Get reserved peers in the node
    #[clap(name = "node-list-reserved-peers")]
    ReservedPeers,

    /// Add a reserved peer in the node
    #[clap(name = "node-add-reserved-peer")]
    AddReservedPeer { address: IpOrSocketAddress },

    /// Remove a reserved peer from the node
    #[clap(name = "node-remove-reserved-peer")]
    RemoveReservedPeer { address: IpOrSocketAddress },

    /// Submit a block to be included in the chain
    #[clap(name = "node-submit-block")]
    SubmitBlock {
        /// Hex encoded block
        block: HexEncoded<Block>,
    },

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network
    #[clap(name = "node-submit-transaction")]
    SubmitTransaction {
        /// Hex encoded transaction.
        transaction: HexEncoded<SignedTransaction>,
        /// Do not store the transaction in the wallet
        #[arg(long = "do-not-store", default_value_t = false)]
        do_not_store: bool,
    },

    /// Returns the current node's chainstate (block height information and more)
    #[clap(name = "node-chainstate-info")]
    ChainstateInfo,

    /// Returns the current best block hash
    #[clap(name = "node-best-block-id")]
    BestBlock,

    /// Returns the current best block height
    #[clap(name = "node-best-block-height")]
    BestBlockHeight,

    /// Returns the current best block timestamp
    #[clap(name = "node-best-block-timestamp")]
    BestBlockTimestamp,

    /// Get the block ID of the block at a given height
    #[clap(name = "node-block-id")]
    BlockId {
        /// Block height
        height: BlockHeight,
    },

    /// Get a block by its hash, represented with hex encoded bytes
    #[clap(name = "node-get-block")]
    GetBlock {
        /// Block hash
        hash: String,
    },

    /// Generate a block with the given transactions to the specified
    /// reward destination. If transactions are None, the block will be
    /// generated with available transactions in the mempool
    #[clap(name = "node-generate-block")]
    GenerateBlock {
        transactions: Vec<HexEncoded<SignedTransaction>>,
    },

    #[clap(name = "node-generate-blocks")]
    #[clap(hide = true)]
    GenerateBlocks { block_count: u32 },

    /// Compose a new transaction from the specified outputs and selected utxos
    /// The transaction is returned in a hex encoded form that can be passed to account-sign-raw-transaction
    /// and also prints the fees that will be paid by the transaction
    /// example usage:
    /// transaction-compose transfer(tmt1q8lhgxhycm8e6yk9zpnetdwtn03h73z70c3ha4l7,0.9) transfer(tmt1q8lhgxhycm8e6yk9zpnetdwtn03h73z70c3ha4l7,50)
    ///  --utxos tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1) tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,0)
    /// which creates a transaction with 2 outputs and 2 input
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

    /// Abandon an unconfirmed transaction in the wallet database, and make the consumed inputs available to be used again
    /// Note that this doesn't necessarily mean that the network will agree. This assumes the transaction is either still
    /// not confirmed in the network or somehow invalid.
    #[clap(name = "transaction-abandon")]
    AbandonTransaction {
        /// The id of the transaction that will be abandoned, in hex.
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// List the pending transactions that can be abandoned
    #[clap(name = "transaction-list-pending")]
    ListPendingTransactions,

    /// List mainchain transactions with optional address filter
    #[clap(name = "transaction-list-by-address")]
    ListMainchainTransactions {
        /// Address to filter by
        address: Option<String>,
        /// limit the number of printed transactions, default is 100
        #[arg(long = "limit", default_value_t = 100)]
        limit: usize,
    },

    /// Get a transaction from the wallet, if present
    #[clap(name = "transaction-get")]
    GetTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get a transaction from the wallet, if present, as hex encoded raw transaction
    #[clap(name = "transaction-get-raw")]
    GetRawTransaction {
        /// Transaction id, encoded in hex
        transaction_id: HexEncoded<Id<Transaction>>,
    },

    /// Get a signed transaction from the wallet, if present, as hex encoded raw transaction
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

struct CliWalletState {
    selected_account: U31,
}

pub struct CommandHandler<W> {
    // the CliController if there is a loaded wallet
    state: Option<CliWalletState>,
    config: ControllerConfig,

    wallet: W,
}

impl<W, E> CommandHandler<W>
where
    W: WalletInterface<Error = E> + Send + Sync + 'static,
{
    pub async fn new(config: ControllerConfig, wallet: W) -> Self {
        let state = match wallet.account_names().await {
            Ok(_) => Some(CliWalletState {
                selected_account: DEFAULT_ACCOUNT_INDEX,
            }),
            Err(_) => None,
        };

        CommandHandler {
            state,
            config,
            wallet,
        }
    }

    pub async fn rpc_completed(&self) {
        self.wallet.rpc_completed().await
    }

    async fn set_selected_account<N: NodeInterface>(
        &mut self,
        account_index: U31,
    ) -> Result<(), WalletCliError<N>>
    where
        WalletCliError<N>: From<E>,
    {
        let CliWalletState { selected_account } =
            self.state.as_mut().ok_or(WalletCliError::NoWallet)?;

        if account_index.into_u32() as usize >= self.wallet.account_names().await?.len() {
            return Err(WalletCliError::AccountNotFound(account_index));
        }

        *selected_account = account_index;
        Ok(())
    }

    async fn repl_status<N: NodeInterface>(&mut self) -> Result<String, WalletCliError<N>>
    where
        WalletCliError<N>: From<E>,
    {
        let status = match self.state.as_ref() {
            Some(CliWalletState { selected_account }) => {
                let accounts = self.wallet.account_names().await?;
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
        };

        Ok(status)
    }

    fn get_selected_acc<N: NodeInterface>(&mut self) -> Result<U31, WalletCliError<N>>
    where
        WalletCliError<N>: From<E>,
    {
        self.state
            .as_mut()
            .map(|state| state.selected_account)
            .ok_or(WalletCliError::NoWallet)
    }

    pub fn new_tx_submitted_command(new_tx: NewTransaction) -> ConsoleCommand {
        let status_text = format!(
            "The transaction was submitted successfully with ID:\n{}",
            id_to_hex_string(*new_tx.tx_id.as_hash())
        );
        ConsoleCommand::Print(status_text)
    }

    async fn handle_cold_wallet_command<N: NodeInterface>(
        &mut self,
        command: ColdWalletCommand,
        chain_config: &ChainConfig,
    ) -> Result<ConsoleCommand, WalletCliError<N>>
    where
        WalletCliError<N>: From<E>,
    {
        match command {
            ColdWalletCommand::CreateWallet {
                wallet_path,
                mnemonic,
                whether_to_store_seed_phrase,
            } => {
                utils::ensure!(self.state.is_none(), WalletCliError::WalletFileAlreadyOpen);
                let newly_generated_mnemonic = self
                    .wallet
                    .create_wallet(
                        wallet_path,
                        whether_to_store_seed_phrase.to_bool(),
                        mnemonic,
                    )
                    .await?;

                self.state = Some(CliWalletState {
                    selected_account: DEFAULT_ACCOUNT_INDEX,
                });

                let msg = match newly_generated_mnemonic {
                    CreatedWallet::NewlyGeneratedMnemonic(mnemonic) => format!(
                    "New wallet created successfully\nYour mnemonic: {}\nPlease write it somewhere safe to be able to restore your wallet."
                , mnemonic),
                    CreatedWallet::UserProvidedMenmonic => {
                        "New wallet created successfully".to_owned()
                    }
                };

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: msg,
                })
            }

            ColdWalletCommand::OpenWallet {
                wallet_path,
                encryption_password,
            } => {
                utils::ensure!(self.state.is_none(), WalletCliError::WalletFileAlreadyOpen);

                self.wallet.open_wallet(wallet_path, encryption_password).await?;
                self.state = Some(CliWalletState {
                    selected_account: DEFAULT_ACCOUNT_INDEX,
                });

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Wallet loaded successfully".to_owned(),
                })
            }

            ColdWalletCommand::CloseWallet => {
                utils::ensure!(self.state.is_some(), WalletCliError::NoWallet);

                self.wallet.close_wallet().await?;

                self.state = None;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Successfully closed the wallet.".to_owned(),
                })
            }

            ColdWalletCommand::EncryptPrivateKeys { password } => {
                self.wallet.encrypt_private_keys(password).await?;

                Ok(ConsoleCommand::Print(
                    "Successfully encrypted the private keys of the wallet.".to_owned(),
                ))
            }

            ColdWalletCommand::RemovePrivateKeysEncryption => {
                self.wallet.remove_private_key_encryption().await?;

                Ok(ConsoleCommand::Print(
                    "Successfully removed the encryption from the private keys.".to_owned(),
                ))
            }

            ColdWalletCommand::UnlockPrivateKeys { password } => {
                self.wallet.unlock_private_keys(password).await?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now unlocked.".to_owned(),
                ))
            }

            ColdWalletCommand::LockPrivateKeys => {
                self.wallet.lock_private_key_encryption().await?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now locked.".to_owned(),
                ))
            }

            ColdWalletCommand::ShowSeedPhrase => {
                let phrase = self.wallet.get_seed_phrase().await?;

                let msg = if let Some(phrase) = phrase.seed_phrase {
                    format!("The stored seed phrase is \"{}\"", phrase.join(" "))
                } else {
                    "No stored seed phrase for this wallet. This was your choice when you created the wallet as a security option. Make sure not to lose this wallet file if you don't have the seed-phrase stored elsewhere when you created the wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            ColdWalletCommand::PurgeSeedPhrase => {
                let phrase = self.wallet.purge_seed_phrase().await?;

                let msg = if let Some(phrase) = phrase.seed_phrase {
                    format!("The seed phrase has been deleted, you can store it if you haven't do so yet: \"{}\"", phrase.join(" "))
                } else {
                    "No stored seed phrase for this wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            ColdWalletCommand::SetLookaheadSize {
                lookahead_size,
                i_know_what_i_am_doing,
            } => {
                let force_reduce = match i_know_what_i_am_doing {
                    Some(CliForceReduce::IKnowWhatIAmDoing) => true,
                    None => false,
                };

                self.wallet.set_lookahead_size(lookahead_size, force_reduce).await?;

                Ok(ConsoleCommand::Print(
                    "Success. Lookahead size has been updated, will rescan the blockchain."
                        .to_owned(),
                ))
            }

            ColdWalletCommand::AddressQRCode { address } => {
                let addr: Address<Destination> = Address::from_str(chain_config, &address)
                    .map_err(|_| WalletCliError::InvalidInput("Invalid address".to_string()))?;

                let qr_code_string = qrcode_or_error_string(&addr.to_string());
                Ok(ConsoleCommand::Print(qr_code_string))
            }

            ColdWalletCommand::NewAddress => {
                let selected_account = self.get_selected_acc()?;
                let address = self.wallet.issue_address(selected_account).await?;
                Ok(ConsoleCommand::Print(address.address))
            }

            ColdWalletCommand::RevealPublicKey { public_key_hash } => {
                let selected_account = self.get_selected_acc()?;
                let public_key =
                    self.wallet.reveal_public_key(selected_account, public_key_hash).await?;
                Ok(ConsoleCommand::Print(public_key.public_key_address))
            }

            ColdWalletCommand::RevealPublicKeyHex { public_key_hash } => {
                let selected_account = self.get_selected_acc()?;
                let public_key =
                    self.wallet.reveal_public_key(selected_account, public_key_hash).await?;
                Ok(ConsoleCommand::Print(public_key.public_key_hex))
            }

            ColdWalletCommand::ShowReceiveAddresses => {
                let selected_account = self.get_selected_acc()?;
                let addresses_with_usage =
                    self.wallet.get_issued_addresses(selected_account).await?;

                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row![
                        "Index",
                        "Address",
                        "Is used in transaction history",
                    ]);

                    addresses_table.extend(addresses_with_usage.into_iter().map(|info| {
                        let is_used = if info.used { "Yes" } else { "No" };
                        prettytable::row![info.index, info.address, is_used]
                    }));

                    addresses_table
                };

                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            ColdWalletCommand::NewVrfPublicKey => {
                let selected_account = self.get_selected_acc()?;
                let vrf_public_key = self.wallet.new_vrf_public_key(selected_account).await?;
                Ok(ConsoleCommand::Print(format!(
                    "New VRF public key: {} with index {}",
                    vrf_public_key.vrf_public_key, vrf_public_key.child_number
                )))
            }

            ColdWalletCommand::GetVrfPublicKey => {
                let selected_account = self.get_selected_acc()?;
                let addresses_with_usage = self.wallet.get_vrf_public_key(selected_account).await?;
                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row![
                        "Index",
                        "Address",
                        "Is used in transaction history",
                    ]);

                    addresses_table.extend(addresses_with_usage.into_iter().map(|info| {
                        let is_used = if info.used { "Yes" } else { "No" };
                        prettytable::row![info.child_number, info.vrf_public_key, is_used]
                    }));

                    addresses_table
                };
                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            ColdWalletCommand::GetLegacyVrfPublicKey => {
                let selected_account = self.get_selected_acc()?;
                let legacy_pubkey = self.wallet.get_legacy_vrf_public_key(selected_account).await?;
                Ok(ConsoleCommand::Print(legacy_pubkey.vrf_public_key))
            }

            ColdWalletCommand::SignRawTransaction { transaction } => {
                let selected_account = self.get_selected_acc()?;
                let result = self
                    .wallet
                    .sign_raw_transaction(selected_account, transaction, self.config)
                    .await?;

                let output_str = match result {
                    PartialOrSignedTx::Signed(signed_tx) => {
                        let summary = signed_tx.transaction().text_summary(chain_config);
                        let result_hex: HexEncoded<SignedTransaction> = signed_tx.into();

                        let qr_code_string = qrcode_or_error_string(&result_hex.to_string());

                        format!(
                            "The transaction has been fully signed and is ready to be broadcast to network. \
                             You can use the command `node-submit-transaction` in a wallet connected to the internet (this one or elsewhere). \
                             Pass the following data to the wallet to broadcast:\n\n{result_hex}\n\n\
                             Or scan the Qr code with it:\n\n{qr_code_string}\n\n{summary}")
                    }
                    PartialOrSignedTx::Partial(partially_signed_tx) => {
                        let result_hex: HexEncoded<PartiallySignedTransaction> =
                            partially_signed_tx.into();

                        let qr_code_string = qrcode_or_error_string(&result_hex.to_string());

                        format!(
                            "Not all transaction inputs have been signed. This wallet does not have all the keys for that.\
                             Pass the following string into the wallet that has appropriate keys for the inputs to sign what is left:\n\n{result_hex}\n\n\
                             Or scan the Qr code with it:\n\n{qr_code_string}"
                        )
                    }
                };

                Ok(ConsoleCommand::Print(output_str))
            }

            ColdWalletCommand::SignChallegeHex {
                message: challenge,
                address,
            } => {
                let selected_account = self.get_selected_acc()?;
                let result =
                    self.wallet.sign_challenge_hex(selected_account, challenge, address).await?;

                let qr_code_string = qrcode_or_error_string(&result);

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex encoded signature is\n\n{result}
                    \n\n\
                    The following qr code also contains the signature for easy transport:\n{qr_code_string}",
                )))
            }

            ColdWalletCommand::SignChallege {
                message: challenge,
                address,
            } => {
                let selected_account = self.get_selected_acc()?;
                let result =
                    self.wallet.sign_challenge(selected_account, challenge, address).await?;

                let qr_code_string = qrcode_or_error_string(&result);

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex encoded signature is\n\n{result}
                    \n\n\
                    The following qr code also contains the signature for easy transport:\n{qr_code_string}",
                )))
            }

            ColdWalletCommand::VerifyChallengeHex {
                message,
                signed_challenge,
                address,
            } => {
                self.wallet.verify_challenge_hex(message, signed_challenge, address).await?;

                Ok(ConsoleCommand::Print(
                    "The provided signature is correct".to_string(),
                ))
            }

            ColdWalletCommand::VerifyChallenge {
                message,
                signed_challenge,
                address,
            } => {
                self.wallet.verify_challenge(message, signed_challenge, address).await?;

                Ok(ConsoleCommand::Print(
                    "The provided signature is correct".to_string(),
                ))
            }

            ColdWalletCommand::Version => Ok(ConsoleCommand::Print(get_version())),
            ColdWalletCommand::Exit => {
                self.wallet.shutdown().await?;
                Ok(ConsoleCommand::Exit)
            }
            ColdWalletCommand::PrintHistory => Ok(ConsoleCommand::PrintHistory),
            ColdWalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            ColdWalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }

    pub async fn handle_wallet_command<N: NodeInterface>(
        &mut self,
        chain_config: &ChainConfig,
        command: WalletCommand,
    ) -> Result<ConsoleCommand, WalletCliError<N>>
    where
        WalletCliError<N>: From<E>,
    {
        match command {
            WalletCommand::ColdCommands(command) => {
                self.handle_cold_wallet_command(command, chain_config).await
            }

            WalletCommand::ChainstateInfo => {
                let info = self.wallet.chainstate_info().await?;
                Ok(ConsoleCommand::Print(format!("{info:#?}")))
            }

            WalletCommand::BestBlock => {
                let id = self.wallet.node_best_block_id().await?;
                Ok(ConsoleCommand::Print(id.hex_encode()))
            }

            WalletCommand::BestBlockHeight => {
                let height = self.wallet.node_best_block_height().await?;
                Ok(ConsoleCommand::Print(height.to_string()))
            }

            WalletCommand::BestBlockTimestamp => {
                let timestamp = self.wallet.chainstate_info().await?.best_block_timestamp;
                Ok(ConsoleCommand::Print(format!(
                    "{} ({})",
                    timestamp,
                    timestamp.into_time()
                )))
            }

            WalletCommand::BlockId { height } => {
                let hash = self.wallet.node_block_id(height).await?;
                match hash {
                    Some(id) => Ok(ConsoleCommand::Print(id.hex_encode())),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GetBlock { hash } => {
                let hash = self.wallet.node_block(hash).await?;
                match hash {
                    Some(block) => Ok(ConsoleCommand::Print(block)),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GenerateBlock { transactions } => {
                let selected_account = self.get_selected_acc()?;
                self.wallet.node_generate_block(selected_account, transactions).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GenerateBlocks { block_count } => {
                let selected_account = self.get_selected_acc()?;
                self.wallet.node_generate_blocks(selected_account, block_count).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::CreateNewAccount { name } => {
                let new_acc = self.wallet.create_account(name).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: format!(
                        "Success, the new account index is: {}",
                        new_acc.account,
                    ),
                })
            }

            WalletCommand::SelectAccount { account_index } => {
                self.set_selected_account(account_index).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Success".into(),
                })
            }

            WalletCommand::StartStaking => {
                let selected_account = self.get_selected_acc()?;
                self.wallet.start_staking(selected_account).await?;
                Ok(ConsoleCommand::Print(
                    "Staking started successfully".to_owned(),
                ))
            }

            WalletCommand::StopStaking => {
                let selected_account = self.get_selected_acc()?;
                self.wallet.stop_staking(selected_account).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::StakingStatus => {
                let selected_account = self.get_selected_acc()?;
                let status = self.wallet.staking_status(selected_account).await?;
                let status = match status {
                    wallet_rpc_lib::types::StakingStatus::Staking => "Staking",
                    wallet_rpc_lib::types::StakingStatus::NotStaking => "Not staking",
                };
                Ok(ConsoleCommand::Print(status.to_string()))
            }

            WalletCommand::StakePoolBalance { pool_id } => {
                let balance_opt = self.wallet.stake_pool_balance(pool_id).await?;
                match balance_opt.balance {
                    Some(balance) => Ok(ConsoleCommand::Print(balance)),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::SubmitBlock { block } => {
                self.wallet.submit_block(block).await?;
                Ok(ConsoleCommand::Print(
                    "The block was submitted successfully".to_owned(),
                ))
            }

            WalletCommand::SubmitTransaction {
                transaction,
                do_not_store,
            } => {
                let new_tx = self
                    .wallet
                    .submit_raw_transaction(
                        transaction,
                        do_not_store,
                        TxOptionsOverrides::default(),
                    )
                    .await?;
                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::TransactionCompose {
                outputs,
                utxos,
                only_transaction,
            } => {
                let outputs: Vec<TxOutput> = outputs
                    .into_iter()
                    .map(|input| parse_output(input, chain_config))
                    .collect::<Result<Vec<_>, WalletCliError<N>>>()?;

                let input_utxos: Vec<UtxoOutPoint> = utxos
                    .into_iter()
                    .map(parse_utxo_outpoint)
                    .collect::<Result<Vec<_>, WalletCliError<N>>>(
                )?;

                let ComposedTransaction { hex, fees } =
                    self.wallet.compose_transaction(input_utxos, outputs, only_transaction).await?;
                let mut output = format!("The hex encoded transaction is:\n{hex}\n");

                format_fees(&mut output, fees, chain_config);

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::AbandonTransaction { transaction_id } => {
                let selected_account = self.get_selected_acc()?;
                self.wallet.abandon_transaction(selected_account, transaction_id.take()).await?;
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
                let token_supply = parse_token_supply(&token_supply, number_of_decimals)?;

                let account_index = self.get_selected_acc()?;
                let new_token = self
                    .wallet
                    .issue_new_token(
                        account_index,
                        destination_address,
                        TokenMetadata {
                            token_ticker,
                            number_of_decimals,
                            metadata_uri,
                            token_supply,
                            is_freezable: is_freezable.to_bool(),
                        },
                        self.config,
                    )
                    .await?;

                Ok(ConsoleCommand::Print(format!(
                    "A new token has been issued with ID: {} in tx: {}",
                    new_token.token_id,
                    id_to_hex_string(*new_token.tx_id.as_hash())
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
                let metadata = NftMetadata {
                    creator,
                    name,
                    description,
                    ticker,
                    icon_uri,
                    additional_metadata_uri,
                    media_uri,
                    media_hash,
                };

                let selected_account = self.get_selected_acc()?;
                let new_token = self
                    .wallet
                    .issue_new_nft(selected_account, destination_address, metadata, self.config)
                    .await?;

                Ok(ConsoleCommand::Print(format!(
                    "A new NFT has been issued with ID: {} in tx: {}",
                    new_token.token_id,
                    id_to_hex_string(*new_token.tx_id.as_hash())
                )))
            }

            WalletCommand::MintTokens {
                token_id,
                address,
                amount,
            } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .mint_tokens(selected_account, token_id, address, amount, self.config)
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::UnmintTokens { token_id, amount } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .unmint_tokens(selected_account, token_id, amount, self.config)
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::LockTokenSupply { token_id } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx =
                    self.wallet.lock_token_supply(selected_account, token_id, self.config).await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::FreezeToken {
                token_id,
                is_unfreezable,
            } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .freeze_token(
                        selected_account,
                        token_id,
                        is_unfreezable.to_bool(),
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::UnfreezeToken { token_id } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx =
                    self.wallet.unfreeze_token(selected_account, token_id, self.config).await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::ChangeTokenAuthority { token_id, address } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .change_token_authority(selected_account, token_id, address, self.config)
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::Rescan => {
                self.wallet.rescan().await?;
                Ok(ConsoleCommand::Print(
                    "Successfully rescanned the blockchain".to_owned(),
                ))
            }

            WalletCommand::SyncWallet => {
                self.wallet.sync().await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GetBalance {
                utxo_states,
                with_locked,
            } => {
                let selected_account = self.get_selected_acc()?;
                let (coins, tokens) = self
                    .wallet
                    .get_balance(
                        selected_account,
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await?
                    .into_coins_and_tokens();

                let mut output = format!("Coins amount: {coins}\n");

                for (token_id, amount) in tokens {
                    let token_id = Address::new(chain_config, &token_id)
                        .expect("Encoding token id should never fail");
                    writeln!(&mut output, "Token: {token_id} amount: {amount}")
                        .expect("Writing to a memory buffer should not fail");
                }
                output.pop();

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::ListUtxo {
                utxo_type,
                utxo_states,
                with_locked,
            } => {
                let selected_account = self.get_selected_acc()?;
                let utxos = self
                    .wallet
                    .get_utxos(
                        selected_account,
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await
                    .map(serde_json::Value::Array)?;
                Ok(ConsoleCommand::Print(
                    serde_json::to_string(&utxos).expect("ok"),
                ))
            }

            WalletCommand::ListPendingTransactions => {
                let selected_account = self.get_selected_acc()?;
                let utxos = self.wallet.list_pending_transactions(selected_account).await?;
                Ok(ConsoleCommand::Print(format!("{utxos:#?}")))
            }

            WalletCommand::ListMainchainTransactions { address, limit } => {
                let selected_account = self.get_selected_acc()?;
                let txs = self
                    .wallet
                    .list_transactions_by_address(selected_account, address, limit)
                    .await?;

                let table = {
                    let mut table = prettytable::Table::new();
                    table.set_titles(prettytable::row!["Id", "BlockHeight", "BlockTimestamp",]);

                    table.extend(txs.into_iter().map(|info| {
                        prettytable::row![
                            id_to_hex_string(*info.id.as_hash()),
                            info.height,
                            info.timestamp
                        ]
                    }));

                    table
                };

                Ok(ConsoleCommand::Print(table.to_string()))
            }

            WalletCommand::GetTransaction { transaction_id } => {
                let selected_account = self.get_selected_acc()?;
                let tx = self
                    .wallet
                    .get_transaction(selected_account, transaction_id.take())
                    .await
                    .map(|tx| serde_json::to_string(&tx).expect("ok"))?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawTransaction { transaction_id } => {
                let selected_account = self.get_selected_acc()?;
                let tx = self
                    .wallet
                    .get_raw_transaction(selected_account, transaction_id.take())
                    .await?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawSignedTransaction { transaction_id } => {
                let selected_account = self.get_selected_acc()?;
                let tx = self
                    .wallet
                    .get_raw_signed_transaction(selected_account, transaction_id.take())
                    .await?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::SendToAddress {
                address,
                amount,
                utxos,
            } => {
                let input_utxos: Vec<UtxoOutPoint> = utxos
                    .into_iter()
                    .map(parse_utxo_outpoint)
                    .collect::<Result<Vec<_>, WalletCliError<N>>>(
                )?;
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .send_coins(selected_account, address, amount, input_utxos, self.config)
                    .await?;
                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::CreateTxFromColdInput {
                address,
                amount,
                utxo,
                change_address,
            } => {
                let selected_input = parse_utxo_outpoint(utxo)?;
                let selected_account = self.get_selected_acc()?;
                let ComposedTransaction { hex, fees } = self
                    .wallet
                    .transaction_from_cold_input(
                        selected_account,
                        address,
                        amount,
                        selected_input,
                        change_address,
                        self.config,
                    )
                    .await?;

                let tx =
                    HexEncoded::<PartiallySignedTransaction>::from_str(&hex).expect("ok").take();

                let summary = tx.tx().text_summary(chain_config);

                let qr_code_string = qrcode_or_error_string(&hex);

                let mut output_str = format!(
                    "Send transaction created. \
                    Pass the following string into the cold wallet with private key to sign:\n\n{hex}\n\n\
                    Or scan the Qr code with it:\n\n{qr_code_string}\n\n{summary}\n"
                );
                format_fees(&mut output_str, fees, chain_config);

                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::SendTokensToAddress {
                token_id,
                address,
                amount,
            } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .send_tokens(selected_account, token_id, address, amount, self.config)
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::CreateDelegation { owner, pool_id } => {
                let selected_account = self.get_selected_acc()?;
                let delegation_id = self
                    .wallet
                    .create_delegation(selected_account, owner, pool_id, self.config)
                    .await?
                    .delegation_id;

                Ok(ConsoleCommand::Print(format!(
                    "Success, the creation of delegation transaction was broadcast to the network. Delegation id: {}",
                    delegation_id
                )))
            }

            WalletCommand::DelegateStaking {
                amount,
                delegation_id,
            } => {
                let selected_account = self.get_selected_acc()?;
                self.wallet
                    .delegate_staking(selected_account, amount, delegation_id, self.config)
                    .await?;

                Ok(ConsoleCommand::Print(
                    "Success, the delegation staking transaction was broadcast to the network"
                        .to_owned(),
                ))
            }

            WalletCommand::WithdrawFromDelegation {
                address,
                amount,
                delegation_id,
            } => {
                let selected_account = self.get_selected_acc()?;
                self.wallet
                    .withdraw_from_delegation(
                        selected_account,
                        address,
                        amount,
                        delegation_id,
                        self.config,
                    )
                    .await?;
                Ok(ConsoleCommand::Print(
                    "Success. The transaction was broadcast to the network".to_owned(),
                ))
            }

            WalletCommand::CreateStakePool {
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
            } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .create_stake_pool(
                        selected_account,
                        amount,
                        cost_per_block,
                        margin_ratio_per_thousand,
                        decommission_address,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::DecommissionStakePool {
                pool_id,
                output_address,
            } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx = self
                    .wallet
                    .decommission_stake_pool(
                        selected_account,
                        pool_id,
                        Some(output_address),
                        self.config,
                    )
                    .await?;
                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::DecommissionStakePoolRequest {
                pool_id,
                output_address,
            } => {
                let selected_account = self.get_selected_acc()?;
                let result_hex = self
                    .wallet
                    .decommission_stake_pool_request(
                        selected_account,
                        pool_id,
                        Some(output_address),
                        self.config,
                    )
                    .await?;

                let qr_code_string = qrcode_or_error_string(&result_hex.to_string());

                let output_str = format!(
                    "Decommission transaction created. \
                    Pass the following string into the wallet with private key to sign:\n\n{result_hex}\n\n\
                    Or scan the Qr code with it:\n\n{qr_code_string}"
                );
                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::DepositData { hex_data } => {
                let selected_account = self.get_selected_acc()?;
                let new_tx =
                    self.wallet.deposit_data(selected_account, hex_data, self.config).await?;
                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::NodeVersion => {
                let version = self.wallet.node_version().await?;
                Ok(ConsoleCommand::Print(version.version))
            }

            WalletCommand::ListPoolIds => {
                let selected_account = self.get_selected_acc()?;
                let pool_ids: Vec<_> = self
                    .wallet
                    .list_pool_ids(selected_account)
                    .await?
                    .into_iter()
                    .map(format_pool_info)
                    .collect();
                Ok(ConsoleCommand::Print(format!("{}\n", pool_ids.join("\n"))))
            }

            WalletCommand::ListDelegationIds => {
                let selected_account = self.get_selected_acc()?;
                let delegations: Vec<_> = self
                    .wallet
                    .list_delegation_ids(selected_account)
                    .await?
                    .into_iter()
                    .map(|info| {
                        format_delegation_info(info.delegation_id, info.balance.to_string())
                    })
                    .collect();
                Ok(ConsoleCommand::Print(delegations.join("\n").to_string()))
            }

            WalletCommand::ListCreatedBlocksIds => {
                let selected_account = self.get_selected_acc()?;
                let mut block_ids = self
                    .wallet
                    .list_created_blocks_ids(selected_account)
                    .await?
                    .into_iter()
                    .map(|block_info| (block_info.height.into_int(), *block_info.id.as_hash()))
                    .collect::<Vec<_>>();
                block_ids.sort_by(|(a0, _), (a1, _)| a0.cmp(a1));
                let result = block_ids
                    .into_iter()
                    .map(|(h, id)| {
                        let id = id_to_hex_string(id);
                        format!("({h}, {id})")
                    })
                    .fold("".to_string(), |curr, v| curr + &v + "\n");
                Ok(ConsoleCommand::Print(result))
            }

            WalletCommand::NodeShutdown => {
                self.wallet.node_shutdown().await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::Connect { address } => {
                self.wallet.connect_to_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Disconnect { peer_id } => {
                self.wallet.disconnect_peer(peer_id).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::ListBanned => {
                let list = self.wallet.list_banned().await?;

                let msg = list
                    .iter()
                    .map(|(addr, banned_until)| format!("{addr} (banned until {banned_until})"))
                    .join("\n");

                Ok(ConsoleCommand::Print(msg))
            }
            WalletCommand::Ban { address, duration } => {
                self.wallet.ban_address(address, duration.into()).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Unban { address } => {
                self.wallet.unban_address(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::ListDiscouraged => {
                let list = self.wallet.list_discouraged().await?;

                let msg = list
                    .iter()
                    .map(|(addr, discouraged_until)| {
                        format!("{addr} (discouraged until {discouraged_until})")
                    })
                    .join("\n");

                Ok(ConsoleCommand::Print(msg))
            }

            WalletCommand::PeerCount => {
                let peer_count = self.wallet.peer_count().await?;
                Ok(ConsoleCommand::Print(peer_count.to_string()))
            }
            WalletCommand::ConnectedPeers => {
                let peers = self.wallet.connected_peers().await?;
                Ok(ConsoleCommand::Print(format!("{peers:#?}")))
            }
            WalletCommand::ConnectedPeersJson => {
                let peers = self.wallet.connected_peers().await?;
                let peers_json = serde_json::to_string(&peers)?;
                Ok(ConsoleCommand::Print(peers_json))
            }
            WalletCommand::ReservedPeers => {
                let peers = self.wallet.reserved_peers().await?;
                Ok(ConsoleCommand::Print(format!("{peers:#?}")))
            }
            WalletCommand::AddReservedPeer { address } => {
                self.wallet.add_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::RemoveReservedPeer { address } => {
                self.wallet.remove_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
        }
    }
}

fn format_fees(output: &mut String, fees: Balances, chain_config: &ChainConfig) {
    let (coins, tokens) = fees.into_coins_and_tokens();
    writeln!(
        output,
        "Fees that will be paid by the transaction:\nCoins amount: {coins}\n"
    )
    .expect("Writing to a memory buffer should not fail");

    for (token_id, amount) in tokens {
        let token_id =
            Address::new(chain_config, &token_id).expect("Encoding token id should never fail");
        writeln!(output, "Token: {token_id} amount: {amount}")
            .expect("Writing to a memory buffer should not fail");
    }
    output.pop();
}

fn id_to_hex_string(id: H256) -> String {
    let hex_string = format!("{:?}", id);
    hex_string.strip_prefix("0x").unwrap_or(&hex_string).to_string()
}

/// This is a helper function used to ensure that failing to output a QR code will only display an error message instead of completely failing the command
fn qrcode_or_error_string(str_data: &str) -> String {
    let make_error_str = |e: QrCodeError| format!("<<Failed to generate QR Code: {e}>>");
    let qr_code_result = utils::qrcode::qrcode_from_str(str_data);
    qr_code_result.map_or_else(make_error_str, |qr| {
        qr.encode_to_console_string_with_defaults(1)
    })
}
