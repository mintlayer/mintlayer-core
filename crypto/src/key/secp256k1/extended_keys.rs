// Copyright (c) 2022 RBB S.r.l
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

use crate::key::hdkd::chain_code::CHAINCODE_LENGTH;
use crate::key::hdkd::derivation_path::DerivationPath;
use crate::key::hdkd::{
    chain_code::ChainCode,
    child_number::ChildNumber,
    derivable::{Derivable, DerivationError},
};
use crate::key::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::random::{CryptoRng, Rng};
use generic_array::{sequence::Split, typenum::U32, GenericArray};
use hmac::{Hmac, Mac};
use secp256k1;
use secp256k1::SECP256K1;
use serialization::{Decode, Encode};
use sha2::Sha512;
use zeroize::Zeroize;

// Create alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct Secp256k1ExtendedPrivateKey {
    /// The derivation path that was used to derive this key
    pub derivation_path: DerivationPath,
    /// Chain code
    pub chain_code: ChainCode,
    /// Private key
    pub private_key: Secp256k1PrivateKey,
}

fn new_hmac_sha_512(key: &[u8]) -> HmacSha512 {
    HmacSha512::new_from_slice(key).expect("HMAC can take key of any size")
}

fn to_key_and_chain_code(
    mac: HmacSha512,
) -> Result<(secp256k1::SecretKey, ChainCode), DerivationError> {
    // Finalize the hmac
    let mut result = mac.finalize().into_bytes();

    // Split in to two 32 byte arrays
    let (mut secret_key_bytes, mut chain_code_bytes): (
        GenericArray<u8, U32>,
        GenericArray<u8, U32>,
    ) = result.split();
    result.zeroize();

    // Create the secret key key
    let secret_key = secp256k1::SecretKey::from_slice(&secret_key_bytes)
        .map_err(|_| DerivationError::KeyDerivationError)?;
    secret_key_bytes.zeroize();

    // Chain code
    let chain_code: [u8; CHAINCODE_LENGTH] = chain_code_bytes.into();
    let chain_code = ChainCode::from(chain_code);
    chain_code_bytes.zeroize();

    Ok((secret_key, chain_code))
}

impl Secp256k1ExtendedPrivateKey {
    pub fn new_master(seed: &[u8]) -> Result<Secp256k1ExtendedPrivateKey, DerivationError> {
        // Create a new mac with the appropriate BIP39 constant
        let mut mac = new_hmac_sha_512(b"Bitcoin seed");

        mac.update(seed);

        let (private_key, chain_code) = to_key_and_chain_code(mac)?;

        Ok(Secp256k1ExtendedPrivateKey {
            derivation_path: DerivationPath::empty(),
            private_key: private_key.into(),
            chain_code,
        })
    }

    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> (Secp256k1ExtendedPrivateKey, Secp256k1ExtendedPublicKey) {
        // Create a new chain code
        let mut chain_code = [0u8; 32];
        rng.fill_bytes(&mut chain_code);
        let chain_code = chain_code.into();
        let private_key = secp256k1::SecretKey::new(rng).into();
        // Generate a new private key
        let ext_priv = Secp256k1ExtendedPrivateKey {
            derivation_path: DerivationPath::empty(),
            private_key,
            chain_code,
        };
        // Generate the public key
        let ext_pub = Secp256k1ExtendedPublicKey::from_private_key(&ext_priv);
        // Return the pair
        (ext_priv, ext_pub)
    }

    pub fn private_key(&self) -> &Secp256k1PrivateKey {
        &self.private_key
    }
}

impl Derivable for Secp256k1ExtendedPrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        // Create a new hmac with the chain code as the key
        let mut mac = new_hmac_sha_512(&self.chain_code.into_array());

        let secp_key = self.private_key.data;

        if num.is_hardened() {
            // When the derivation is hardened add the private key with a 0x00 prefix
            mac.update(&[0u8]);
            mac.update(&secp_key[..]);
        } else {
            // For normal derivations add the serialized public key
            mac.update(&secp_key.public_key(SECP256K1).serialize());
        }

        // Add the child number
        mac.update(&num.into_encoded_be_bytes());

        // Finalize and get the new un-tweaked key and the new chain code
        let (key_part, chain_code) = to_key_and_chain_code(mac)?;

        // TODO(SECURITY) erase this scalar after use
        let tweak_scalar = secp_key.into();

        // Create the derived private key
        let private_key = key_part
            .add_tweak(&tweak_scalar)
            .map_err(|_| DerivationError::KeyDerivationError)?
            .into();

        let derivation_path = {
            let mut child_path = self.derivation_path.as_vec().clone();
            child_path.push(num);
            child_path.try_into()?
        };

        Ok(Secp256k1ExtendedPrivateKey {
            derivation_path,
            chain_code,
            private_key,
        })
    }

    fn get_derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode)]
pub struct Secp256k1ExtendedPublicKey {
    /// The derivation path that was used to derive this key
    pub derivation_path: DerivationPath,
    /// Chain code
    pub chain_code: ChainCode,
    /// Public key
    pub public_key: Secp256k1PublicKey,
}

impl Secp256k1ExtendedPublicKey {
    pub fn public_key(&self) -> &Secp256k1PublicKey {
        &self.public_key
    }

    pub fn from_private_key(private_key: &Secp256k1ExtendedPrivateKey) -> Self {
        Secp256k1ExtendedPublicKey {
            derivation_path: private_key.derivation_path.clone(),
            chain_code: private_key.chain_code,
            public_key: private_key.private_key.data.public_key(SECP256K1).into(),
        }
    }
}

impl Derivable for Secp256k1ExtendedPublicKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        // Create a new hmac with the chain code as the key
        let mut mac = new_hmac_sha_512(&self.chain_code.into_array());

        if num.is_normal() {
            mac.update(&self.public_key.pubkey_data.serialize());
        } else {
            return Err(DerivationError::CannotDeriveHardenedKeyFromPublicKey(num));
        }

        // Add the child number
        mac.update(&num.into_encoded_be_bytes());

        // Finalize and get the new un-tweaked key and the new chain code
        let (key_part, chain_code) = to_key_and_chain_code(mac)?;

        // Create the derived public key
        let public_key = self
            .public_key
            .pubkey_data
            .add_exp_tweak(SECP256K1, &key_part.into())
            .map_err(|_| DerivationError::KeyDerivationError)?
            .into();

        let derivation_path = {
            let mut child_path = self.derivation_path.as_vec().clone();
            child_path.push(num);
            child_path.try_into()?
        };

        Ok(Secp256k1ExtendedPublicKey {
            derivation_path,
            chain_code,
            public_key,
        })
    }

    fn get_derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::hdkd::derivation_path::DerivationPath;
    use bip39::Mnemonic;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::{assert_encoded_eq, decode_from_hex};

    #[test]
    fn serialization() {
        let sk_hex = "007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67";
        let sk = decode_from_hex::<Secp256k1ExtendedPrivateKey>(sk_hex);
        assert_encoded_eq(&sk, sk_hex);
        let pk_hex = "007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494";
        let pk = decode_from_hex::<Secp256k1ExtendedPublicKey>(pk_hex);
        assert_encoded_eq(&pk, pk_hex);
    }

    #[rustfmt::skip]
    #[rstest]
    #[trace]
    #[case("m/86'/0'/0'", "03800000568000000080000000", "9043214d33a3c162a9a825d26b2a1c381455a72306ed17857f55ea65b7dd20da", "03418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb", "c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa")]
    #[case("m/44'/0'/0'", "038000002c8000000080000000", "fe64af825b5b78554c33a28b23085fc082f691b3c712cc1d4e66e133297da87a", "03774c910fcf07fa96886ea794f0d5caed9afe30b44b83f7e213bb92930e7df4bd", "3da4bc190a2680111d31fadfdc905f2a7f6ce77c6f109919116f253d43445219")]
    #[case("m/44'/0'/1'", "038000002c8000000080000001", "8855dfda37fe663bffc0136618504e3cbd7d992134609cef6191c729339d5c65", "025d0261853d4c3a379160fb51d2f262ac64e65219139982c4e2180bcef1a233d9", "2971fa2db0ff5d69e166a406813aa3d9ed09c4adac2e0ce33523da8c5609f4f4")]
    #[case("m/44'/2'/0'", "038000002c8000000280000000", "983cd10d8d14160b10b9a4bb63207e9585054a3133619d57b78ea9d5aa3046d2", "0340fe3b8e89165258bac0cb711613c618d1af63dc321a90b751d0697301441bcc", "869c5045e5fc789646babcd1961b101bc31e75fe50df8a585c79b05dca0ac758")]
    #[case("m/49'/0'/0'", "03800000318000000080000000", "880d51752bda4190607e079588d3f644d96bfa03446bce93cddfda3c4a99c7e6", "02f1f347891b20f7568eae3ec9869fbfb67bcab6f358326f10ecc42356bd55939d", "6eaae365ae0e0a0aab84325cfe7cd76c3b909035f889e7d3f1b847a9a0797ecb")]
    #[case("m/49'/2'/0'", "03800000318000000280000000", "cf222cc2e097049fe2ca76626c19c7e7a3ef971b1f64195758ab3c832463fcf4", "02b07388bd2edaba3c0a2c0856716fd7c9965d212fb2736f7b925f57d922b10ace", "67b7e1dc5c70a93504218ccf40c47ad46d4a9c858196376ce0e853aca7be0498")]
    #[case("m/84'/0'/0'", "03800000548000000080000000", "e14f274d16ca0d91031b98b162618061d03930fa381af6d4caf44b01819ab6d4", "02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b", "4a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc")]
    #[case("m/0'/1'/2'/3'/4'/5'/6'/7'/8'/9'", "0a80000000800000018000000280000003800000048000000580000006800000078000000880000009", "1754f94b8f5bfbacfbbc6b71bc6b2a2aefa3bb31a5579b2da7a0543451041c6a", "03f030912b83528995b199908bf45caad86262ede2016aa748dcf0d556b1ec120b", "0c61a6e40d45b7b04ac86ed5a75ebd32fca2d06ff3c1eaaef43f985920ef873f")]
    fn derivation_private_key(
        #[case] path: &str,
        #[case] path_encoded: &str,
        #[case] secret: &str,
        #[case] public: &str,
        #[case] chaincode: &str,
    ) {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str).unwrap();
        let master_key =
            Secp256k1ExtendedPrivateKey::new_master(&mnemonic.to_seed_normalized("")).unwrap();
        let master_pub_key = Secp256k1ExtendedPublicKey::from_private_key(&master_key);
        assert_eq!(master_key.chain_code, master_pub_key.chain_code);
        assert_encoded_eq(&master_key, "007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67");
        assert_encoded_eq(&master_pub_key, "007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494");

        let path = DerivationPath::from_str(path).unwrap();
        assert_encoded_eq(&path, path_encoded);
        let sk = master_key.derive_path(&path).unwrap();
        let pk = Secp256k1ExtendedPublicKey::from_private_key(&sk);
        assert_eq!(sk.chain_code, pk.chain_code);
        assert_encoded_eq(&sk, format!("{path_encoded}{chaincode}{secret}").as_str());
        assert_encoded_eq(&pk, format!("{path_encoded}{chaincode}{public}").as_str());
    }

    #[rstest]
    #[rustfmt::skip]
    #[case("m/1", "0100000001", "02ea2649b3512b9a859ab658a85e2989a7ae39b2518877b2dc0f2b44b785d5788d", "5c48917d6838b666aeb11eac7c4f98f807779b57c7522e38509719eeb1e7a592", true)]
    #[case("m/1/2/3", "03000000010000000200000003", "02ae3bdc9a9d4e474be7879ea2c623c14f0a66a66ab8423e8fdfcd9368ab27e8ad", "b0da2b9ff9dcc6f5e34ec72f0165639db70acd24751e0616da39f933e14dacfa", true)]
    #[case("m/1/2h", "", "", "", false)]
    fn derivation_public_key(
        #[case] path: &str,
        #[case] path_encoded: &str,
        #[case] public: &str,
        #[case] chaincode: &str,
        #[case] is_success: bool,
    ) {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str).unwrap();
        let master_key =
            Secp256k1ExtendedPrivateKey::new_master(&mnemonic.to_seed_normalized("")).unwrap();
        let master_pub_key = Secp256k1ExtendedPublicKey::from_private_key(&master_key);

        let path = DerivationPath::from_str(path).unwrap();
        let pk = master_pub_key.derive_path(&path);
        if !is_success {
            let hard_num = *path.into_iter().find(|&n| n.is_hardened()).unwrap();
            assert_eq!(
                pk.unwrap_err(),
                DerivationError::CannotDeriveHardenedKeyFromPublicKey(hard_num)
            );
            return;
        }
        let pk = pk.unwrap();
        assert_encoded_eq(&path, path_encoded);
        assert_encoded_eq(&pk, format!("{path_encoded}{chaincode}{public}").as_str());
    }
}
