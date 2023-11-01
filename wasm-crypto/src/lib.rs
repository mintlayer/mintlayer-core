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

pub use bip39::{Language, Mnemonic};
use common::{
    address::{pubkeyhash::PublicKeyHash, Address},
    chain::{
        config::{Builder, ChainType, BIP44_PATH},
        Destination,
    },
};
use crypto::key::{
    extended::{ExtendedKeyKind, ExtendedPrivateKey},
    hdkd::{child_number::ChildNumber, derivable::Derivable, u31::U31},
    KeyKind, PrivateKey, PublicKey, Signature,
};
use error::Error;
use serialization::{DecodeAll, Encode};
use wasm_bindgen::prelude::*;

pub mod error;

#[wasm_bindgen]
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

#[wasm_bindgen]
pub fn make_private_key() -> Vec<u8> {
    let key = PrivateKey::new_from_entropy(KeyKind::Secp256k1Schnorr);
    key.0.encode()
}

/// Create the default account's extended private key for a given mnemonic
/// derivation path: 44'/mintlayer_coin_type'/0'
#[wasm_bindgen]
pub fn make_default_account_privkey(mnemonic: &str, network: Network) -> Result<Vec<u8>, Error> {
    let mnemonic = bip39::Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| Error::InvalidMnemonic)?;
    let seed = mnemonic.to_seed("");

    let root_key = ExtendedPrivateKey::new_master(&seed, ExtendedKeyKind::Secp256k1Schnorr)
        .expect("Should not fail to create a master key");

    let chain_config = Builder::new(network.into()).build();

    let account_index = U31::ZERO;
    let path = vec![
        BIP44_PATH,
        chain_config.bip44_coin_type(),
        ChildNumber::from_hardened(account_index),
    ];
    let account_path = path.try_into().expect("Path creation should not fail");
    let account_privkey = root_key
        .derive_absolute_path(&account_path)
        .expect("Should not fail to derive path");

    Ok(account_privkey.encode())
}

/// From an extended private key create a receiving private key for a given key index
/// derivation path: 44'/mintlayer_coin_type'/0'/0/key_index
#[wasm_bindgen]
pub fn make_receiving_address(private_key_bytes: &[u8], key_index: u32) -> Result<Vec<u8>, Error> {
    const RECEIVE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(0).0);

    let account_privkey = ExtendedPrivateKey::decode_all(&mut &private_key_bytes[..])
        .map_err(|_| Error::InvalidPublicKeyEncoding)?;

    let receive_funds_pkey = account_privkey
        .derive_child(RECEIVE_FUNDS_INDEX)
        .expect("Should not fail to derive key");

    let private_key: PrivateKey = receive_funds_pkey
        .derive_child(ChildNumber::from_normal(
            U31::from_u32(key_index).ok_or(Error::InvalidKeyIndex)?,
        ))
        .expect("Should not fail to derive key")
        .private_key();

    Ok(private_key.encode())
}

#[wasm_bindgen]
pub fn pubkey_to_string(public_key_bytes: &[u8], network: Network) -> Result<String, Error> {
    let public_key = PublicKey::decode_all(&mut &public_key_bytes[..])
        .map_err(|_| Error::InvalidPublicKeyEncoding)?;
    let chain_config = Builder::new(network.into()).build();

    let public_key_hash = PublicKeyHash::from(&public_key);

    Ok(
        Address::new(&chain_config, &Destination::Address(public_key_hash))
            .expect("Should not fail to create address")
            .get()
            .to_owned(),
    )
}

#[wasm_bindgen]
pub fn public_key_from_private_key(private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key = PrivateKey::decode_all(&mut &private_key[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;
    let public_key = PublicKey::from_private_key(&private_key);
    Ok(public_key.encode())
}

#[wasm_bindgen]
pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key = PrivateKey::decode_all(&mut &private_key[..])
        .map_err(|_| Error::InvalidPrivateKeyEncoding)?;
    let signature = private_key.sign_message(message)?;
    Ok(signature.encode())
}

#[wasm_bindgen]
pub fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, Error> {
    let public_key =
        PublicKey::decode_all(&mut &public_key[..]).map_err(|_| Error::InvalidPublicKeyEncoding)?;
    let signature =
        Signature::decode_all(&mut &signature[..]).map_err(|_| Error::InvalidSignatureEncoding)?;
    let verifcation_result = public_key.verify_message(&signature, message);
    Ok(verifcation_result)
}

#[cfg(test)]
mod tests {
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_and_verify(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let key = make_private_key();
        assert_eq!(key.len(), 33);

        let public_key = public_key_from_private_key(&key).unwrap();

        let message_size = 1 + rng.gen::<usize>() % 10000;
        let message: Vec<u8> = (0..message_size).map(|_| rng.gen::<u8>()).collect();

        let signature = sign_message(&key, &message).unwrap();

        {
            // Valid reference signature
            let verification_result = verify_signature(&public_key, &signature, &message).unwrap();
            assert!(verification_result);
        }
        {
            // Tamper with the message
            let mut tampered_message = message.clone();
            let tamper_bit_index = rng.gen::<usize>() % message_size;
            tampered_message[tamper_bit_index] = tampered_message[tamper_bit_index].wrapping_add(1);
            let verification_result =
                verify_signature(&public_key, &signature, &tampered_message).unwrap();
            assert!(!verification_result);
        }
        {
            // Tamper with the signature
            let mut tampered_signature = signature.clone();
            // Ignore the first byte because the it is the key kind
            let tamper_bit_index = 1 + rng.gen::<usize>() % (signature.len() - 1);
            tampered_signature[tamper_bit_index] =
                tampered_signature[tamper_bit_index].wrapping_add(1);
            let verification_result =
                verify_signature(&public_key, &tampered_signature, &message).unwrap();
            assert!(!verification_result);
        }
        {
            // Wrong keys
            let private_key = make_private_key();
            let public_key = public_key_from_private_key(&private_key).unwrap();
            let verification_result = verify_signature(&public_key, &signature, &message).unwrap();
            assert!(!verification_result);
        }
    }
}
