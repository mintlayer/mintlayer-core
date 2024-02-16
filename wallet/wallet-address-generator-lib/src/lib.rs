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

use clap::{Parser, ValueEnum};

use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::config::{Builder, ChainType};
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::u31::U31;
use crypto::key::hdkd::{child_number::ChildNumber, derivable::Derivable};
use utils::{clap_utils, ensure};
use wallet::key_chain::LOOKAHEAD_SIZE;
use wallet::WalletError;
use wallet::{
    key_chain::{make_account_path, KeyChainError, MasterKeyChain},
    WalletResult,
};
use wallet_types::KeyPurpose;

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
            Network::Regtest => write!(f, "Regtest"),
            Network::Signet => write!(f, "Signet"),
        }
    }
}

#[derive(Parser, Debug)]
#[clap(mut_args(clap_utils::env_adder("WALLET_ADDR_GEN")))]
#[clap(version)]
pub struct CliArgs {
    /// The network, for which addresses will be generated
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// Number of addresses to generate and display
    #[clap(long, short = 'n', default_value_t = 1)]
    pub address_count: u8,

    /// Mnemonic phrase (12, 15, or 24 words as a single quoted argument). If not specified, a new mnemonic phrase is generated and printed.
    #[clap(long)]
    #[arg(hide = true)]
    pub mnemonic: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CliError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(wallet_controller::mnemonic::Error),
    #[error("WalletError error: {0}")]
    WalletError(#[from] WalletError),
}

pub fn run(args: CliArgs) -> Result<(), CliError> {
    ensure!(
        args.address_count as u32 <= LOOKAHEAD_SIZE,
        CliError::InvalidInput(format!(
            "Cannot generate more than {} addresses",
            LOOKAHEAD_SIZE
        ))
    );

    let (root_key, seed_phrase) = root_key_and_mnemonic(&args.mnemonic)?;

    let chain_config = Builder::new(args.network.into()).build();

    let receive_funds_pkey = to_receiving_pub_key(&chain_config, root_key)?;

    let addresses = generate_addresses(args.address_count, receive_funds_pkey, chain_config)?;

    println!("\n");
    println!(
        "Generating addresses for network: {}",
        args.network.to_string().to_uppercase()
    );

    if let Some(mnemonic) = args.mnemonic {
        println!("Using the seed phrase you provided to generate address(es): {mnemonic}");
    } else {
        println!("No seed phrase provided. Generating a new one.");
        println!("WARNING: MAKE SURE TO WRITE DOWN YOUR SEED PHRASE AND KEEP IT SAFE!");
        println!("============================Seed phrase=============================");
        println!("{seed_phrase}");
        println!("====================================================================")
    }

    println!("\n");
    println!("Your address(es) are:");
    for addr in addresses {
        println!("- {}", addr)
    }
    println!("\n");

    Ok(())
}

fn generate_addresses(
    number_addresses: u8,
    receive_funds_pkey: ExtendedPublicKey,
    chain_config: ChainConfig,
) -> Result<Vec<Address<Destination>>, wallet::WalletError> {
    (0..number_addresses)
        .map(|key_index| -> WalletResult<Address<Destination>> {
            let public_key = receive_funds_pkey
                .clone()
                .derive_child(ChildNumber::from_normal(
                    U31::from_u32(key_index as u32).expect("MSB bit not set"),
                ))
                .map_err(KeyChainError::from)?
                .into_public_key();

            let public_key_hash = PublicKeyHash::from(&public_key);

            Ok(Address::new(
                &chain_config,
                &Destination::PublicKeyHash(public_key_hash),
            )?)
        })
        .collect::<WalletResult<Vec<_>>>()
}

fn to_receiving_pub_key(
    chain_config: &ChainConfig,
    root_key: ExtendedPrivateKey,
) -> Result<ExtendedPublicKey, wallet::WalletError> {
    let account_index = U31::ZERO;
    let account_path = make_account_path(chain_config, account_index);
    let account_privkey =
        root_key.derive_absolute_path(&account_path).map_err(KeyChainError::from)?;
    let receive_funds_pkey = account_privkey
        .to_public_key()
        .derive_child(KeyPurpose::ReceiveFunds.get_deterministic_index())
        .map_err(KeyChainError::from)?;
    Ok(receive_funds_pkey)
}

/// Generate a new mnemonic and a root private key
fn root_key_and_mnemonic(
    mnemonic: &Option<String>,
) -> Result<(ExtendedPrivateKey, String), CliError> {
    let language = wallet::wallet::Language::English;
    let mnemonic = match mnemonic {
        Some(mnemonic) => wallet_controller::mnemonic::parse_mnemonic(language, mnemonic)
            .map_err(CliError::InvalidMnemonic)?,
        None => wallet_controller::mnemonic::generate_new_mnemonic(language),
    };
    let (root_key, _root_vrf_key, _mnemonic) =
        MasterKeyChain::mnemonic_to_root_key(&mnemonic.to_string(), None)
            .map_err(WalletError::from)?;

    Ok((root_key, mnemonic.to_string()))
}
