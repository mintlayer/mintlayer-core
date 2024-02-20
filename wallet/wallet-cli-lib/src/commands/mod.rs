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

        /// Passphrase along the mnemonic
        #[arg(long = "passphrase")]
        passphrase: Option<String>,
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

    /// Check the current wallet's number of accounts and their names
    #[clap(name = "wallet-info")]
    WalletInfo,

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

    /// Renames the selected account with an optional name.
    /// If the name is not specified, it will remove any existing name for the account.
    #[clap(name = "account-rename")]
    RenameAccount { name: Option<String> },

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

    /// Print the summary of the transaction
    #[clap(name = "transaction-inspect")]
    InspectTransaction {
        /// Hex encoded transaction or PartiallySignedTransaction.
        transaction: String,
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
        #[arg(value_parser(humantime::parse_duration))]
        duration: Duration,
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
