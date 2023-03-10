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

//! # BIP39 key chain
//! The KeyChain struct holds and constantly derives keys for the wallet addresses
//! It uses the following derivation scheme:
//!
//! m/0'/<account_number>'/<key_purpose>'/<key_index>'
//!
//! Where `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

use common::address::{Address, AddressError};
use common::chain::config::create_regtest;
use common::chain::ChainConfig;
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::derivation_path::DerivationPath;
use std::str::FromStr;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{Store, WalletStorageRead};
use zeroize::Zeroize;

const KEY_KIND: ExtendedKeyKind = ExtendedKeyKind::Secp256k1Schnorr;
const LOOKAHEAD_SIZE: u16 = 100;

/// KeyChain errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum KeyChainError {
    #[error("Bip39 error: {0}")]
    Bip39(bip39::Error),
    #[error("Key derivation error: {0}")]
    Derivation(#[from] DerivationError),
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

/// The usage purpose of a key i.e. if it is for receiving funds or for change
pub enum KeyPurpose {
    /// This is for addresses created for receiving funds that are given to the user
    ReceiveFunds = 0,
    /// This is for the internal usage of the wallet when creating change output for a transaction
    Change = 1,
}

#[allow(dead_code)] // TODO remove
/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct KeyChain<B: Backend> {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The master key of this key chain from where all the keys are derived from
    // TODO implement encryption
    master_key: ExtendedPrivateKey,

    /// The database connection
    // TODO Consider if this should be an Option
    db: Arc<Store<B>>,

    /// The number of addresses to pre-generate from the master key
    lookahead_size: u16,
}
#[allow(dead_code)] // TODO remove
impl<B: Backend> KeyChain<B> {
    pub fn new_from_mnemonic(
        chain_config: Arc<ChainConfig>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
        db: Arc<Store<B>>,
    ) -> KeyChainResult<Self> {
        // TODO use Mnemonic::parse when bip39 is configured with "std"
        let mnemonic =
            bip39::Mnemonic::parse_normalized(mnemonic_str).map_err(KeyChainError::Bip39)?;
        // TODO use Mnemonic::to_seed when bip39 is configured with "std"
        let mut seed = mnemonic.to_seed_normalized(passphrase.unwrap_or(""));
        let master_key = ExtendedPrivateKey::new_master(&seed, KEY_KIND)?;
        // TODO(SECURITY) erase mnemonic
        seed.zeroize();

        Ok(KeyChain {
            chain_config,
            master_key,
            db,
            lookahead_size: LOOKAHEAD_SIZE,
        })
    }

    pub fn load_key_chain(db: Arc<Store<B>>) -> KeyChainResult<Self> {
        // TODO remove this
        let _ = db.get_storage_version().expect("This should work?");
        // TODO implement loading from database
        Ok(KeyChain {
            chain_config: Arc::new(create_regtest()),
            master_key: ExtendedPrivateKey::new_from_entropy(KEY_KIND).0,
            db,
            lookahead_size: LOOKAHEAD_SIZE,
        })
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address(&self, purpose: KeyPurpose) -> KeyChainResult<Address> {
        let key = self.get_new_key(purpose)?;

        let address = Address::from_public_key(
            &self.chain_config,
            &ExtendedPublicKey::from_private_key(&key).into_public_key(),
        )?;

        // TODO save address

        Ok(address)
    }

    /// Get a new derived key that hasn't been used before
    pub fn get_new_key(&self, purpose: KeyPurpose) -> KeyChainResult<ExtendedPrivateKey> {
        // TODO implement with correct paths
        let hd_path = match purpose {
            KeyPurpose::ReceiveFunds => DerivationPath::from_str("m/0'/0'/0'/0'")?,
            KeyPurpose::Change => DerivationPath::from_str("m/0'/0'/1'/0'")?,
        };
        // TODO get key from a precalculated pool
        let new_key = self.master_key.clone().derive_path(&hd_path)?;
        Ok(new_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::create_unit_test_config;
    use test_utils::assert_encoded_eq;
    use wallet_storage::{DefaultBackend, Store};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn key_chain_creation() {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let key_chain = KeyChain::new_from_mnemonic(chain_config, MNEMONIC, None, db).unwrap();

        // Sort test vectors by key_index i.e. the key with index 0 should be first
        let test_vec = vec![
            (
                KeyPurpose::ReceiveFunds,
                "m/0'/0'/0'/0'",
                "80000000800000008000000080000000",
                "04feff4263658459430aea33cb851b830a0235db1611d3279624f40c7c2c0135",
                "031ac0ee91fe1ff500f4b21579cda6ded3b10a2f9162d571b4c8873454f3593326",
                "4fddb29b630431422b3a534e0028e053eb212ab10a5f1db3ba5cbc4e81ff3294",
            ),
            (
                KeyPurpose::Change,
                "m/0'/0'/1'/0'",
                "80000000800000008000000180000000",
                "404dafb8e79d3110e816be00e020a91ef1754ab6b2ada14ec87a26f87e86e19e",
                "03305f803928705f620e6a05dce2e4a6f8c03d1dc0757008096bf689160f394641",
                "04e13b373ed3d5753657d375feec032187cdada01e5df83cc8fddd29c1f15755",
            ),
        ];

        for (purpose, path_str, path_encoded_str, secret, public, chaincode) in test_vec {
            let sk = key_chain.get_new_key(purpose).unwrap();
            let pk = ExtendedPublicKey::from_private_key(&sk);
            let pk2 = ExtendedPublicKey::from_private_key(&sk);
            assert_eq!(pk2.get_derivation_path().to_string(), path_str.to_string());
            assert_eq!(pk, pk2);
            let path = DerivationPath::from_str(path_str).unwrap();
            assert_eq!(sk.get_derivation_path(), path);
            assert_eq!(pk.get_derivation_path(), path);
            let path_len = path.len();
            assert_encoded_eq(
                &sk,
                format!("00{path_len:02x}{path_encoded_str}{chaincode}{secret}").as_str(),
            );
            assert_encoded_eq(
                &pk,
                format!("00{path_len:02x}{path_encoded_str}{chaincode}{public}").as_str(),
            );
        }
    }
}
