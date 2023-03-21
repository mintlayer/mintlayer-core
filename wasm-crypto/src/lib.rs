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

use crypto::key::{KeyKind, PrivateKey, PublicKey, Signature};
use error::Error;
use serialization::{DecodeAll, Encode};
use wasm_bindgen::prelude::*;

pub mod error;

#[wasm_bindgen]
pub fn make_private_key() -> Vec<u8> {
    let key = PrivateKey::new_from_entropy(KeyKind::Secp256k1Schnorr);
    key.0.encode()
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
