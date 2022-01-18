mod internal;

use internal::*;
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};
use rand::{CryptoRng, Rng};
use tari_crypto::keys::PublicKey;
use tari_crypto::tari_utilities::message_format::MessageFormat;

use crate::hash::{Blake2bStream32, StreamHasher};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum RistrettoKeyError {
    InvalidData,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum RistrittoSignatureError {
    ByteConversionError(String),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct MLRistrettoPrivateKey {
    key_data: [u8; 32],
}

impl MLRistrettoPrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (MLRistrettoPrivateKey, MLRistrettoPublicKey) {
        let pair = RistrettoPublicKey::random_keypair(rng);
        (
            Self::from_native(&pair.0),
            MLRistrettoPublicKey {
                pubkey_data: pair
                    .1
                    .as_bytes()
                    .try_into()
                    .expect("Ristretto Public Key size is expected to be 32-bytes (compressed)"),
            },
        )
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let sk =
            RistrettoSecretKey::from_bytes(bytes).map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(&sk);
        Ok(result)
    }

    pub fn as_native(&self) -> RistrettoSecretKey {
        RistrettoSecretKey::from_bytes(&self.key_data)
            .expect("The data is always expected to be valid")
    }

    pub fn from_native(native: &RistrettoSecretKey) -> Self {
        Self {
            key_data: native
                .as_bytes()
                .try_into()
                .expect("Ristretto Private Key size is expected to be 32-bytes"),
        }
    }

    pub(crate) fn sign_message<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>, RistrittoSignatureError> {
        let (r, r_pub) = RistrettoPublicKey::random_keypair(rng);
        let k = self.as_native();
        let e = Blake2bStream32::new().write(msg).finalize();
        let sig = RistrettoSchnorr::sign(k, r, &e).unwrap();
        debug_assert_eq!(*sig.get_public_nonce(), r_pub);
        sig.to_binary()
            .map_err(|e| RistrittoSignatureError::ByteConversionError(e.to_string()))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct MLRistrettoPublicKey {
    pubkey_data: [u8; 32],
}

impl MLRistrettoPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.pubkey_data.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let pk =
            RistrettoPublicKey::from_bytes(bytes).map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(&pk);
        Ok(result)
    }

    pub fn as_native(&self) -> RistrettoPublicKey {
        RistrettoPublicKey::from_bytes(&self.pubkey_data)
            .expect("The data is always expected to be valid")
    }

    pub fn from_native(native: &RistrettoPublicKey) -> Self {
        Self {
            pubkey_data: native
                .as_bytes()
                .try_into()
                .expect("Ristretto Public Key size is expected to be 32-bytes"),
        }
    }

    pub fn from_private_key(private_key: &MLRistrettoPrivateKey) -> Self {
        Self::from_native(&RistrettoPublicKey::from_secret_key(
            &private_key.as_native(),
        ))
    }

    pub(crate) fn verify_message(&self, signature: &[u8], msg: &[u8]) -> bool {
        let signature = if let Ok(s) = RistrettoSchnorr::from_binary(signature) {
            s
        } else {
            return false;
        };
        let e = Blake2bStream32::new().write(msg).finalize();
        signature.verify_challenge(&self.as_native(), &e)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn basic() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let pk2 = MLRistrettoPublicKey::from_private_key(&sk);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn import_from_short_key() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        {
            let sk_bytes = sk.as_bytes();
            let sk_short = &sk_bytes[..sk_bytes.len() - 1];
            assert_eq!(sk_short.len(), 31);
            let sk_again = MLRistrettoPrivateKey::from_bytes(sk_short);
            assert!(sk_again.is_err());
        }
        {
            let pk_bytes = pk.as_bytes();
            let pk_short = &pk_bytes[..pk_bytes.len() - 1];
            assert_eq!(pk_short.len(), 31);
            let pk_again = MLRistrettoPublicKey::from_bytes(pk_short);
            assert!(pk_again.is_err());
        }
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sig = sk.sign_message(&mut rng, &msg).unwrap();
        assert!(sig.len() > 0);
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sign_empty() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let msg: Vec<u8> = Vec::new();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sig = sk.sign_message(&mut rng, &msg).unwrap();
        assert!(sig.len() > 0);
        assert!(pk.verify_message(&sig, &msg));
    }
}
